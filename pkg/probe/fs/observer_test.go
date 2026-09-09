package fs

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"golang.org/x/sys/unix"
)

func skipUnprivileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root or CAP_SYS_ADMIN")
	}
}

// startObserver creates and starts an observer filtered to dir and our PID.
func startObserver(t *testing.T, dir string) *Observer {
	t.Helper()
	obs, err := New(Config{
		Path:         dir,
		PathFilter:   dir,
		PIDFilter:    int32(os.Getpid()),
		EventBufSize: 256,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	return obs
}

// collectEvents drains the observer's event channel for the given duration,
// returning all events whose target starts with the given prefix.
func collectEvents(obs *Observer, d time.Duration) []models.GroundTruthEvent {
	var events []models.GroundTruthEvent
	deadline := time.After(d)
	for {
		select {
		case e := <-obs.Events():
			events = append(events, e)
		case <-deadline:
			return events
		}
	}
}

// assertHasEvent checks that at least one event with the given action type
// and target path exists in the slice.
func assertHasEvent(t *testing.T, events []models.GroundTruthEvent, action models.ActionType, target string) {
	t.Helper()
	for _, e := range events {
		if e.ActionType == action && e.Target == target {
			return
		}
	}
	t.Errorf("expected event %s on %s, got %d events:", action, target, len(events))
	for _, e := range events {
		t.Logf("  %s %s", e.ActionType, e.Target)
	}
}

// assertHasEventInDir checks that at least one event with the given action
// type exists and its target is either the exact path or its parent directory.
// On some filesystems (tmpfs), directory events (DELETE, RENAME) resolve
// only to the parent directory because DFID_NAME info records lack the
// filename. On ext4/xfs this resolves to the full path.
func assertHasEventInDir(t *testing.T, events []models.GroundTruthEvent, action models.ActionType, target string) {
	t.Helper()
	dir := filepath.Dir(target)
	for _, e := range events {
		if e.ActionType == action && (e.Target == target || e.Target == dir) {
			return
		}
	}
	t.Errorf("expected event %s on %s (or dir %s), got %d events:", action, target, dir, len(events))
	for _, e := range events {
		t.Logf("  %s %s", e.ActionType, e.Target)
	}
}

func TestObserver_CreateFile(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs := startObserver(t, dir)

	target := filepath.Join(dir, "created.txt")
	if err := os.WriteFile(target, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	assertHasEvent(t, events, models.FileWrite, target)
}

func TestObserver_ModifyFile(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()

	// Pre-create the file before starting the observer so we only see the modify.
	target := filepath.Join(dir, "modify.txt")
	if err := os.WriteFile(target, []byte("initial"), 0644); err != nil {
		t.Fatal(err)
	}

	obs := startObserver(t, dir)

	if err := os.WriteFile(target, []byte("modified"), 0644); err != nil {
		t.Fatal(err)
	}

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	assertHasEvent(t, events, models.FileWrite, target)
}

func TestObserver_CloseWriteIncludesContentHash(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs := startObserver(t, dir)

	target := filepath.Join(dir, "hashed.txt")
	if err := os.WriteFile(target, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	const want = "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	for _, event := range events {
		if event.ActionType != models.FileClose || event.Target != target {
			continue
		}
		if event.OutputHash == nil {
			t.Fatal("FileClose event has no output hash")
		}
		if *event.OutputHash != want {
			t.Errorf("FileClose hash = %q, want %q", *event.OutputHash, want)
		}
		return
	}
	t.Fatalf("no FileClose event for %s", target)
}

func TestObserverIgnoresHashReadOpen(t *testing.T) {
	path := "/mock/dir/hashed.txt"
	observer := &Observer{
		events: make(chan models.GroundTruthEvent, 1),
		cfg: Config{
			PathFilter: "/mock",
		},
		pendingHashOpens: map[string]int{path: 1},
	}

	observer.processRawEvent(&rawEvent{
		Mask: unix.FAN_OPEN,
		PID:  int32(os.Getpid()),
		Path: path,
	}, time.Now())

	if len(observer.pendingHashOpens) != 0 {
		t.Errorf("pending hash opens = %v, want none", observer.pendingHashOpens)
	}
	select {
	case event := <-observer.events:
		t.Errorf("unexpected self-generated event: %#v", event)
	default:
	}
}

func TestObserver_DeleteFile(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()

	target := filepath.Join(dir, "delete-me.txt")
	if err := os.WriteFile(target, []byte("bye"), 0644); err != nil {
		t.Fatal(err)
	}

	obs := startObserver(t, dir)

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	// On tmpfs, DELETE resolves to the parent directory only (DFID without
	// filename). On ext4/xfs, DFID_NAME provides the full path.
	assertHasEventInDir(t, events, models.FileDelete, target)
}

func TestObserver_RenameFile(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()

	src := filepath.Join(dir, "old-name.txt")
	dst := filepath.Join(dir, "new-name.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	obs := startObserver(t, dir)

	if err := os.Rename(src, dst); err != nil {
		t.Fatal(err)
	}

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	// Rename produces MOVED_FROM (source) and MOVED_TO (destination),
	// both mapped to FileRename. On tmpfs, these resolve to the parent
	// directory only; on ext4/xfs, DFID_NAME gives the full path.
	assertHasEventInDir(t, events, models.FileRename, src)
	assertHasEventInDir(t, events, models.FileRename, dst)
}

func TestObserver_OpenFile(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()

	target := filepath.Join(dir, "read-me.txt")
	if err := os.WriteFile(target, []byte("contents"), 0644); err != nil {
		t.Fatal(err)
	}

	obs := startObserver(t, dir)

	// Open and read the file (no write).
	f, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, _ = f.Read(buf)
	_ = f.Close()

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	assertHasEvent(t, events, models.FileOpen, target)
}

func TestObserver_StopIsClean(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs := startObserver(t, dir)

	// Stop without any file operations.
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Channel should be closed.
	_, ok := <-obs.Events()
	if ok {
		t.Error("expected events channel to be closed")
	}
}

func TestObserver_NoOverflow(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs := startObserver(t, dir)

	// Small burst of operations.
	for i := 0; i < 10; i++ {
		_ = os.WriteFile(filepath.Join(dir, "burst.txt"), []byte("x"), 0644)
	}

	collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	if obs.Overflow() {
		t.Error("unexpected queue overflow on a small burst")
	}
}

// TestDiag_RawFanotify bypasses the Observer to check whether fanotify
// events arrive at all and what their raw contents look like.
func TestDiag_RawFanotify(t *testing.T) {
	skipUnprivileged(t)

	dir := t.TempDir()

	fd, err := initFanotify()
	if err != nil {
		t.Fatalf("initFanotify: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()

	t.Logf("fanotify fd=%d", fd)
	t.Logf("watchMask=0x%x", watchMask)

	if err := markFilesystem(fd, dir, watchMask); err != nil {
		t.Fatalf("markFilesystem: %v", err)
	}

	mountFD, err := openMountFD(dir)
	if err != nil {
		t.Fatalf("openMountFD: %v", err)
	}
	defer func() { _ = unix.Close(mountFD) }()
	t.Logf("mountFD=%d", mountFD)
	// Verify mountFD is valid.
	var st unix.Stat_t
	if err := unix.Fstat(mountFD, &st); err != nil {
		t.Fatalf("mountFD %d fstat failed: %v", mountFD, err)
	}

	// Perform a file operation.
	target := filepath.Join(dir, "diag.txt")
	if err := os.WriteFile(target, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s, our PID=%d", target, os.Getpid())

	// Give the kernel a moment to queue events.
	time.Sleep(100 * time.Millisecond)

	// Non-blocking read.
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatalf("SetNonblock: %v", err)
	}

	buf := make([]byte, 64*1024)
	n, err := unix.Read(fd, buf)
	if err != nil {
		t.Logf("Read error: %v (n=%d)", err, n)
		if n <= 0 {
			t.Fatal("no data from fanotify fd")
		}
	}
	t.Logf("Read %d bytes from fanotify fd", n)

	// Parse and dump raw events.
	offset := 0
	count := 0
	for offset+metadataSize <= n {
		meta := readMetadata(buf[offset:])
		if meta.EventLen < metadataSize || offset+int(meta.EventLen) > n {
			break
		}

		infoStart := offset + int(meta.MetadataLen)
		infoEnd := offset + int(meta.EventLen)
		infoData := buf[infoStart:infoEnd]

		t.Logf("event[%d]: event_len=%d mask=0x%x fd=%d pid=%d info_bytes=%d",
			count, meta.EventLen, meta.Mask, meta.FD, meta.PID, len(infoData))
		if len(infoData) > 0 {
			t.Logf("  info hex: %s", hex.EncodeToString(infoData))
		}

		// Try path resolution.
		path := resolveEventPath(infoData, newKernelResolver(mountFD))
		t.Logf("  resolved path: %q", path)

		// Detailed handle resolution debugging for each info record.
		ioff := 0
		for ioff+4 <= len(infoData) {
			iType := infoData[ioff]
			iLen := int(binary.LittleEndian.Uint16(infoData[ioff+2 : ioff+4]))
			if iLen < 4 || ioff+iLen > len(infoData) {
				break
			}
			rec := infoData[ioff : ioff+iLen]
			if len(rec) >= 20 {
				hBytes := int(binary.LittleEndian.Uint32(rec[12:16]))
				hType := int32(binary.LittleEndian.Uint32(rec[16:20]))
				hEnd := 20 + hBytes
				if hEnd <= len(rec) {
					hData := make([]byte, hBytes)
					copy(hData, rec[20:hEnd])
					fh := unix.NewFileHandle(hType, hData)
					rfd, rerr := unix.OpenByHandleAt(mountFD, fh, unix.O_RDONLY|unix.O_PATH)
					if rerr != nil {
						t.Logf("  info[type=%d]: OpenByHandleAt failed: %v", iType, rerr)
					} else {
						link, lerr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", rfd))
						t.Logf("  info[type=%d]: OpenByHandleAt fd=%d, readlink=%q err=%v", iType, rfd, link, lerr)
						_ = unix.Close(rfd)
					}
				}
			}
			ioff += iLen
		}

		offset += int(meta.EventLen)
		count++
	}
	t.Logf("total events parsed: %d", count)
}

func TestMaskToActionTypes(t *testing.T) {
	tests := []struct {
		name string
		mask uint64
		want []models.ActionType
	}{
		{"create", 0x100, []models.ActionType{models.FileWrite}},  // FAN_CREATE
		{"delete", 0x200, []models.ActionType{models.FileDelete}}, // FAN_DELETE
		{"modify+close_write merges FileWrite", 0x2 | 0x8, []models.ActionType{models.FileWrite, models.FileClose}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskToActionTypes(tt.mask)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %s, want %s", i, got[i], tt.want[i])
				}
			}
		})
	}
}
