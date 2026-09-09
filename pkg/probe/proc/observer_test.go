package proc

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func skipUnprivileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root or CAP_BPF+CAP_PERFMON")
	}
}

// collect drains the observer's event channel until it is closed.
func collect(obs *Observer) []models.GroundTruthEvent {
	var got []models.GroundTruthEvent
	for e := range obs.Events() {
		got = append(got, e)
	}
	return got
}

func TestObserver_CapturesExecAndExit(t *testing.T) {
	skipUnprivileged(t)

	nonce := fmt.Sprintf("agenttrace-%d", time.Now().UnixNano())

	obs, err := New(Config{
		CommandFilter: "/bin/echo",
		EventBufSize:  256,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()

	// Give the tracepoints a moment to attach before generating events.
	time.Sleep(150 * time.Millisecond)

	if err := exec.Command("/bin/echo", nonce).Run(); err != nil {
		t.Fatalf("spawn echo: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := collect(obs)

	var sawExec, sawExit bool
	for _, e := range got {
		if !strings.Contains(e.Target, nonce) {
			continue
		}
		if e.Target != "/bin/echo "+nonce {
			t.Errorf("unexpected target %q, want %q", e.Target, "/bin/echo "+nonce)
		}
		switch e.ActionType {
		case models.ProcessExec:
			sawExec = true
		case models.ProcessExit:
			sawExit = true
		default:
			t.Errorf("unexpected action type %q", e.ActionType)
		}
		if e.Timestamp.IsZero() {
			t.Error("event has zero timestamp")
		}
	}

	if !sawExec {
		t.Errorf("no process_exec event for %q; got %d events: %v", nonce, len(got), got)
	}
	if !sawExit {
		t.Errorf("no process_exit event for %q; got %d events: %v", nonce, len(got), got)
	}
}

func TestObserver_ExitCodeAndTimestamps(t *testing.T) {
	skipUnprivileged(t)

	nonce := fmt.Sprintf("agenttrace-exit-%d", time.Now().UnixNano())

	obs, err := New(Config{
		CommandFilter: "/bin/sh",
		EventBufSize:  256,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	before := time.Now()
	// Deliberately nonzero, to confirm the probe reports the code the
	// process actually returned rather than defaulting to 0.
	_ = exec.Command("/bin/sh", "-c", fmt.Sprintf("echo %s; exit 7", nonce)).Run()
	after := time.Now()

	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := collect(obs)

	var execEvent, exitEvent *models.GroundTruthEvent
	for i := range got {
		if !strings.Contains(got[i].Target, nonce) {
			continue
		}
		switch got[i].ActionType {
		case models.ProcessExec:
			execEvent = &got[i]
		case models.ProcessExit:
			exitEvent = &got[i]
		}
	}
	if execEvent == nil || exitEvent == nil {
		t.Fatalf("missing exec (%v) or exit (%v) event for %q; got %d events: %v",
			execEvent != nil, exitEvent != nil, nonce, len(got), got)
	}

	if exitEvent.ExitCode == nil {
		t.Fatal("exit event has nil ExitCode")
	}
	if *exitEvent.ExitCode != 7 {
		t.Errorf("ExitCode = %d, want 7", *exitEvent.ExitCode)
	}
	if execEvent.ExitCode != nil {
		t.Errorf("exec event has non-nil ExitCode %d, want nil", *execEvent.ExitCode)
	}

	// The kernel timestamps (bpf_ktime_get_ns + userspace boot offset)
	// should land inside a generous window around the actual wall-clock
	// window in which the command ran, and exec must not be reported after
	// exit.
	window := 2 * time.Second
	lo, hi := before.Add(-window), after.Add(window)
	if execEvent.Timestamp.Before(lo) || execEvent.Timestamp.After(hi) {
		t.Errorf("exec timestamp %v outside expected window [%v, %v]", execEvent.Timestamp, lo, hi)
	}
	if exitEvent.Timestamp.Before(lo) || exitEvent.Timestamp.After(hi) {
		t.Errorf("exit timestamp %v outside expected window [%v, %v]", exitEvent.Timestamp, lo, hi)
	}
	if exitEvent.Timestamp.Before(execEvent.Timestamp) {
		t.Errorf("exit timestamp %v before exec timestamp %v", exitEvent.Timestamp, execEvent.Timestamp)
	}
}

// TestObserver_ResistsArgv0Spoofing is the live-kernel counterpart to
// TestCommandLine_UsesResolvedFilenameNotArgv0: it doesn't just check the
// parsing helper in isolation, it spawns a real process that performs the
// actual masquerading primitive (execve() with an argv[0] unrelated to the
// binary being loaded) and confirms the probe's reported ground truth is
// built from the kernel-resolved path, not the caller-supplied argv[0]. This
// also confirms CommandFilter itself can't be evaded by argv[0] spoofing,
// since it prefix-matches the same target string.
func TestObserver_ResistsArgv0Spoofing(t *testing.T) {
	skipUnprivileged(t)

	nonce := fmt.Sprintf("agenttrace-spoof-%d", time.Now().UnixNano())

	obs, err := New(Config{
		CommandFilter: "/bin/true",
		EventBufSize:  256,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	// Bypass exec.Command's LookPath convenience: set Path to the real
	// binary directly but Args[0] to an unrelated, misleading name. This is
	// exactly execve(real_path, {"fake_name", ...}, envp), the process
	// masquerading primitive malware uses to disguise itself in ps/argv-based
	// tooling.
	//
	// Deliberately /bin/true, not /bin/echo: on distros shipping uutils'
	// Rust coreutils (this dev environment included), the coreutils
	// binaries are a multicall dispatcher that itself checks argv[0]
	// against the executable name and refuses to run on a mismatch
	// ("Security violation: Requested utility ... does not match executable
	// name"), which would make this test fail before the kernel probe is
	// even exercised, for a reason unrelated to what's being tested. /bin/true
	// here resolves to GNU coreutils' standalone `gnutrue` binary, which,
	// like a typical statically-single-purpose binary, does not interpret
	// argv[0] at all. Picking a test binary that itself dispatches on
	// argv[0] would silently defeat the point of this test on such systems.
	cmd := &exec.Cmd{
		Path: "/bin/true",
		Args: []string{"totally-not-true", nonce},
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("spawn spoofed-argv0 true: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := collect(obs)

	var found bool
	for _, e := range got {
		if !strings.Contains(e.Target, nonce) {
			continue
		}
		found = true
		if strings.HasPrefix(e.Target, "totally-not-true") {
			t.Errorf("ground truth trusted the spoofed argv[0]: target=%q", e.Target)
		}
		if !strings.HasPrefix(e.Target, "/bin/true") {
			t.Errorf("expected target built from the resolved execve path /bin/true, got %q", e.Target)
		}
	}
	if !found {
		t.Fatalf("no event observed for the spoofed-argv0 process; got %d events: %v", len(got), got)
	}
}

func TestObserver_CommandFilterExcludesOthers(t *testing.T) {
	skipUnprivileged(t)

	obs, err := New(Config{
		CommandFilter: "/nonexistent/path/prefix",
		EventBufSize:  256,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	_ = exec.Command("/bin/true").Run()
	_ = exec.Command("/bin/ls", "/").Run()

	time.Sleep(300 * time.Millisecond)
	_ = obs.Stop()

	if got := collect(obs); len(got) != 0 {
		t.Errorf("expected no events past the filter, got %d: %v", len(got), got)
	}
}

func TestObserver_StopIsIdempotent(t *testing.T) {
	skipUnprivileged(t)

	obs, err := New(Config{EventBufSize: 16})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()

	if err := obs.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := obs.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}
