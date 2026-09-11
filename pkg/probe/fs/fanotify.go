// Package fs provides a filesystem observer using Linux fanotify.
//
// The observer watches all file operations on the filesystem containing
// a given path, using FAN_MARK_FILESYSTEM to capture events across bind
// mounts. It emits models.GroundTruthEvent values on a channel.
//
// Requires CAP_SYS_ADMIN in the initial user namespace.
package fs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// fanotify constants. Defined locally to avoid depending on a specific
// x/sys/unix version for newer kernel flags.
const (
	// FAN_REPORT_FID requests a file-handle info record (type 1) for the
	// object itself in every event.
	fanReportFid = 0x00000200

	// FAN_REPORT_DFID_NAME = FAN_REPORT_DIR_FID | FAN_REPORT_NAME.
	// Requests directory file-handle + entry name in event info records.
	fanReportDfidName = 0x00002400

	// Info record types.
	fanEventInfoTypeFid      = 1 // file handle for the object itself
	fanEventInfoTypeDfidName = 2 // parent dir handle + null-terminated name
	fanEventInfoTypeDfid     = 3 // parent dir handle, no name (merged events)

	// Size of struct fanotify_event_metadata (24 bytes on all architectures).
	metadataSize = 24
)

// handleResolver maps a kernel file handle (type + raw bytes) to a
// filesystem path. In production this calls open_by_handle_at + readlink;
// in tests it returns a predetermined path from a lookup table.
type handleResolver func(handleType int32, handleData []byte) string

// eventMetadata mirrors struct fanotify_event_metadata.
type eventMetadata struct {
	EventLen    uint32
	Vers        uint8
	Reserved    uint8
	MetadataLen uint16
	Mask        uint64
	FD          int32
	PID         int32
}

// rawEvent is a parsed fanotify event with a resolved filesystem path.
type rawEvent struct {
	Mask uint64
	PID  int32
	Path string
	// Ambiguous is true when Path could only be resolved to its containing
	// directory, not the specific file within it (see resolveEventPath).
	Ambiguous bool
}

// --- Kernel interaction (requires CAP_SYS_ADMIN) --------------------------

// initFanotify creates a fanotify file descriptor configured for
// notification-only FID-mode events (no permission decisions).
//
// FAN_REPORT_FID provides a file-handle record for the object itself,
// which remains resolvable even when the kernel merges events and drops
// the filename from the DFID_NAME record.
func initFanotify() (int, error) {
	flags := uint(unix.FAN_CLASS_NOTIF | fanReportFid | fanReportDfidName | unix.FAN_CLOEXEC)
	fd, err := unix.FanotifyInit(flags, 0)
	if err != nil {
		return -1, fmt.Errorf("fanotify_init: %w", err)
	}
	return fd, nil
}

// markFilesystem adds a filesystem-wide mark for the given event mask.
// All mount points of the filesystem containing path are watched.
func markFilesystem(fanotifyFD int, path string, mask uint64) error {
	flags := uint(unix.FAN_MARK_ADD | unix.FAN_MARK_FILESYSTEM)
	if err := unix.FanotifyMark(fanotifyFD, flags, mask, unix.AT_FDCWD, path); err != nil {
		return fmt.Errorf("fanotify_mark on %s: %w", path, err)
	}
	return nil
}

// openMountFD opens a read-only directory fd for path resolution via
// open_by_handle_at. The returned fd identifies the filesystem for handle
// lookups. We avoid O_PATH because some kernels/filesystems reject it
// as the mount_fd argument to open_by_handle_at.
func openMountFD(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, fmt.Errorf("open mount fd for %s: %w", path, err)
	}
	return fd, nil
}

// newKernelResolver returns a handleResolver that resolves file handles
// via open_by_handle_at on the given mount fd.
func newKernelResolver(mountFD int) handleResolver {
	return func(handleType int32, handleData []byte) string {
		fh := unix.NewFileHandle(handleType, handleData)
		fd, err := unix.OpenByHandleAt(mountFD, fh, unix.O_RDONLY|unix.O_PATH)
		if err != nil {
			return ""
		}
		defer func() { _ = unix.Close(fd) }()

		path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil {
			return ""
		}
		return path
	}
}

// --- Pure parsing (no kernel interaction) ----------------------------------

// parseEvents extracts rawEvents from a buffer read from the fanotify fd.
func parseEvents(buf []byte, n int, resolve handleResolver) []rawEvent {
	var events []rawEvent
	offset := 0
	for offset+metadataSize <= n {
		meta := readMetadata(buf[offset:])
		if meta.EventLen < metadataSize || offset+int(meta.EventLen) > n {
			break
		}

		if meta.Mask&unix.FAN_Q_OVERFLOW != 0 {
			events = append(events, rawEvent{Mask: unix.FAN_Q_OVERFLOW})
			offset += int(meta.EventLen)
			continue
		}

		// Ensure fd is closed to avoid leak
		if meta.FD >= 0 {
			_ = unix.Close(int(meta.FD))
		}

		// Info records follow the metadata header.
		infoStart := offset + int(meta.MetadataLen)
		infoEnd := offset + int(meta.EventLen)
		path, ambiguous := resolveEventPath(buf[infoStart:infoEnd], resolve)

		events = append(events, rawEvent{
			Mask:      meta.Mask,
			PID:       meta.PID,
			Path:      path,
			Ambiguous: ambiguous,
		})

		offset += int(meta.EventLen)
	}
	return events
}

func readMetadata(buf []byte) eventMetadata {
	return eventMetadata{
		EventLen:    binary.LittleEndian.Uint32(buf[0:4]),
		Vers:        buf[4],
		Reserved:    buf[5],
		MetadataLen: binary.LittleEndian.Uint16(buf[6:8]),
		Mask:        binary.LittleEndian.Uint64(buf[8:16]),
		FD:          int32(binary.LittleEndian.Uint32(buf[16:20])),
		PID:         int32(binary.LittleEndian.Uint32(buf[20:24])),
	}
}

// resolveEventPath iterates all info records and resolves the best available
// filesystem path. Preference order:
//  1. DFID_NAME (type 2): parent directory handle + entry name (full path)
//  2. FID (type 1): file handle resolved directly via open_by_handle_at
//  3. DFID (type 3): parent directory handle only (no filename; merged events)
//
// The second return value, ambiguous, is true only when the DFID-only
// fallback (case 3) is what actually produced the returned path -- i.e. the
// kernel merged events and dropped the filename, leaving only a directory
// handle. It is false whenever DFID_NAME or FID resolved a specific,
// non-degraded path. Callers use this to restrict the "directory covers any
// file inside it" matching leniency to genuinely coarse-resolution events,
// not to every ground-truth event whose target happens to be a directory.
func resolveEventPath(infoData []byte, resolve handleResolver) (path string, ambiguous bool) {
	var fidPath, dfidNamePath, dfidPath string

	offset := 0
	for offset+4 <= len(infoData) {
		infoType := infoData[offset]
		infoLen := int(binary.LittleEndian.Uint16(infoData[offset+2 : offset+4]))
		if infoLen < 4 || offset+infoLen > len(infoData) {
			break
		}

		record := infoData[offset : offset+infoLen]
		switch infoType {
		case fanEventInfoTypeDfidName:
			dfidNamePath = parseDfidName(record, resolve)
		case fanEventInfoTypeFid:
			fidPath = parseHandleToPath(record, resolve)
		case fanEventInfoTypeDfid:
			dfidPath = parseHandleToPath(record, resolve)
		}

		offset += infoLen
	}

	if dfidNamePath != "" {
		return dfidNamePath, false
	}
	if fidPath != "" {
		return fidPath, false
	}
	return dfidPath, true
}

// parseDfidName extracts a directory file handle and entry name from a
// FAN_EVENT_INFO_TYPE_DFID_NAME record and resolves them to a full path.
//
// Record layout:
//
//	header   (4 bytes): info_type, pad, len
//	fsid     (8 bytes): filesystem ID
//	file_handle:
//	  handle_bytes (4 bytes)
//	  handle_type  (4 bytes)
//	  f_handle     (handle_bytes bytes)
//	name     (remaining): null-terminated entry name
func parseDfidName(record []byte, resolve handleResolver) string {
	// Minimum: header(4) + fsid(8) + handle_bytes(4) + handle_type(4) = 20
	if len(record) < 20 {
		return ""
	}

	handleBytes := int(binary.LittleEndian.Uint32(record[12:16]))
	handleType := int32(binary.LittleEndian.Uint32(record[16:20]))

	handleDataEnd := 20 + handleBytes
	if handleDataEnd > len(record) {
		return ""
	}

	handleData := make([]byte, handleBytes)
	copy(handleData, record[20:handleDataEnd])

	// Entry name follows the handle data, null-terminated with possible padding.
	var name string
	if handleDataEnd < len(record) {
		nameBytes := record[handleDataEnd:]
		if idx := bytes.IndexByte(nameBytes, 0); idx > 0 {
			name = string(nameBytes[:idx])
		} else if len(nameBytes) > 0 && nameBytes[0] != 0 {
			name = string(nameBytes)
		}
	}

	dirPath := resolve(handleType, handleData)

	if dirPath == "" {
		return name
	}
	if name == "" {
		return dirPath
	}
	return filepath.Join(dirPath, name)
}

// parseHandleToPath extracts a file handle from an info record (FID or DFID)
// and resolves it to a path via the provided resolver.
//
// Record layout (same for type 1 and type 3):
//
//	header   (4 bytes): info_type, pad, len
//	fsid     (8 bytes): filesystem ID
//	file_handle:
//	  handle_bytes (4 bytes)
//	  handle_type  (4 bytes)
//	  f_handle     (handle_bytes bytes)
func parseHandleToPath(record []byte, resolve handleResolver) string {
	if len(record) < 20 {
		return ""
	}

	handleBytes := int(binary.LittleEndian.Uint32(record[12:16]))
	handleType := int32(binary.LittleEndian.Uint32(record[16:20]))

	handleDataEnd := 20 + handleBytes
	if handleDataEnd > len(record) {
		return ""
	}

	handleData := make([]byte, handleBytes)
	copy(handleData, record[20:handleDataEnd])

	return resolve(handleType, handleData)
}
