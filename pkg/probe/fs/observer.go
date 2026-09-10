package fs

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// watchMask is the set of fanotify events the observer monitors.
var watchMask = uint64(
	unix.FAN_OPEN |
		unix.FAN_MODIFY |
		unix.FAN_CLOSE_WRITE |
		unix.FAN_CREATE |
		unix.FAN_DELETE |
		unix.FAN_MOVED_FROM |
		unix.FAN_MOVED_TO)

// Config controls the observer's behavior.
type Config struct {
	// Path identifies the filesystem to watch. Every file operation on the
	// filesystem containing this path is monitored (across all mount points).
	Path string

	// PathFilter, if non-empty, restricts emitted events to paths with this
	// prefix. Useful on shared hosts to scope observation to the agent's
	// working directory. Leave empty to capture all events on the filesystem.
	PathFilter string

	// PIDFilter, if > 0, restricts emitted events to this process ID.
	// Useful in tests and when the agent's PID is known.
	PIDFilter int32

	// EventBufSize is the channel buffer size for emitted events.
	// Defaults to 4096 if zero.
	EventBufSize int
}

// Observer watches filesystem events via fanotify and emits GroundTruthEvents.
type Observer struct {
	fanotifyFD       int
	mountFD          int
	stopR            int // read end of stop-signal pipe
	stopW            int // write end of stop-signal pipe
	events           chan models.GroundTruthEvent
	stopped          chan struct{}
	cfg              Config
	overflow         bool // true if FAN_Q_OVERFLOW was seen
	pendingHashOpens map[string]int

	// pathGeneration counts write-class events (FAN_CREATE / FAN_MODIFY /
	// FAN_CLOSE_WRITE) seen per path. hashSettled snapshots the generation
	// before reading a closed file's content and re-checks it after: if the
	// file was written again in that window, the digest can no longer be
	// trusted to reflect the observed close, so no OutputHash is attached
	// (see the TOCTOU note on hashSettled). Grows unboundedly for the
	// observer's lifetime -- entries are never garbage collected, matching
	// pendingHashOpens' existing shape; revisit if a long-lived observer
	// over many distinct paths becomes a memory concern.
	pathGeneration map[string]uint64

	// hashFile computes the content hash for a closed file. Defaults to
	// content.SHA256File; overridable in tests to control the read's outcome.
	hashFile func(string) (string, error)

	mu sync.Mutex
}

// New creates an Observer. The caller must call Start to begin receiving
// events, and Stop to release resources.
func New(cfg Config) (*Observer, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("Config.Path is required")
	}
	if cfg.EventBufSize <= 0 {
		cfg.EventBufSize = 4096
	}

	fd, err := initFanotify()
	if err != nil {
		return nil, err
	}

	if err := markFilesystem(fd, cfg.Path, watchMask); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	mountFD, err := openMountFD(cfg.Path)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	// Pipe for signaling the read loop to stop.
	pipeFDs := [2]int{}
	if err := unix.Pipe2(pipeFDs[:], unix.O_CLOEXEC); err != nil {
		_ = unix.Close(fd)
		_ = unix.Close(mountFD)
		return nil, fmt.Errorf("pipe2: %w", err)
	}

	return &Observer{
		fanotifyFD:       fd,
		mountFD:          mountFD,
		stopR:            pipeFDs[0],
		stopW:            pipeFDs[1],
		events:           make(chan models.GroundTruthEvent, cfg.EventBufSize),
		stopped:          make(chan struct{}),
		cfg:              cfg,
		pendingHashOpens: make(map[string]int),
		pathGeneration:   make(map[string]uint64),
		hashFile:         content.SHA256File,
	}, nil
}

// Events returns the channel on which GroundTruthEvents are delivered.
// The channel is closed when Stop returns.
func (o *Observer) Events() <-chan models.GroundTruthEvent {
	return o.events
}

// Overflow reports whether the kernel's fanotify queue overflowed,
// meaning some events were lost. Check after Stop returns.
func (o *Observer) Overflow() bool {
	return o.overflow
}

// Start begins reading fanotify events in a background goroutine.
func (o *Observer) Start() {
	go o.readLoop()
}

// Stop signals the read loop to exit, waits for it, and releases all
// file descriptors. The events channel is closed after Stop returns.
func (o *Observer) Stop() error {
	// Signal the poll loop.
	_, _ = unix.Write(o.stopW, []byte{0})
	// Wait for readLoop to finish. Hashing is synchronous within readLoop
	// now (see hashSettled), so there are no outstanding goroutines to wait
	// on beyond readLoop itself.
	<-o.stopped

	_ = unix.Close(o.fanotifyFD)
	_ = unix.Close(o.mountFD)
	_ = unix.Close(o.stopR)
	_ = unix.Close(o.stopW)
	close(o.events)
	return nil
}

func (o *Observer) readLoop() {
	defer close(o.stopped)

	buf := make([]byte, 4096*metadataSize)
	pollFDs := []unix.PollFd{
		{Fd: int32(o.fanotifyFD), Events: unix.POLLIN},
		{Fd: int32(o.stopR), Events: unix.POLLIN},
	}

	for {
		_, err := unix.Poll(pollFDs, -1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}

		// Stop signal received.
		if pollFDs[1].Revents&unix.POLLIN != 0 {
			return
		}

		if pollFDs[0].Revents&unix.POLLIN == 0 {
			continue
		}

		// Drain everything already available rather than a single read: a
		// burst of writes can queue up several records before this loop
		// gets scheduled, and processing them all before hashing anything
		// means a close's generation snapshot reflects every write already
		// known about, not just whichever ones happened to fit in one read.
		o.hashAndEmit(o.drainNonBlocking(buf), buf)
	}
}

// drainNonBlocking reads and processes every fanotify record currently
// available without blocking, returning once none remain (or the stop pipe
// becomes readable -- readLoop's own blocking poll notices that on its next
// iteration, so this just needs to not spin past it). Used both for
// readLoop's normal batch pickup and, from hashSettled, as the synchronous
// catch-up that makes a close's generation check authoritative: any write
// whose syscall has already returned has its notification already enqueued
// here, whether or not this observer has gotten to it yet, so a
// non-blocking drain right before trusting a hash is not a best-effort
// peek, it is a real answer to "has anything else happened yet".
func (o *Observer) drainNonBlocking(buf []byte) []pendingHash {
	pollFDs := []unix.PollFd{
		{Fd: int32(o.fanotifyFD), Events: unix.POLLIN},
		{Fd: int32(o.stopR), Events: unix.POLLIN},
	}

	var pending []pendingHash
	for {
		_, err := unix.Poll(pollFDs, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return pending
		}
		if pollFDs[1].Revents&unix.POLLIN != 0 || pollFDs[0].Revents&unix.POLLIN == 0 {
			return pending
		}

		n, err := unix.Read(o.fanotifyFD, buf)
		if err != nil || n == 0 {
			return pending
		}

		now := time.Now()
		raw := parseEvents(buf, n, newKernelResolver(o.mountFD))
		for i := range raw {
			pending = append(pending, o.processRawEvent(&raw[i], now)...)
		}
	}
}

// pendingHash is a FileClose whose content hash still needs computing.
// processRawEvent collects these instead of hashing them itself; see
// hashAndEmit and hashSettled.
type pendingHash struct {
	target string
	ts     time.Time
}

func (o *Observer) processRawEvent(e *rawEvent, ts time.Time) []pendingHash {
	if e.Mask&unix.FAN_Q_OVERFLOW != 0 {
		o.overflow = true
		return nil
	}

	// PID filter.
	if o.cfg.PIDFilter > 0 && e.PID != o.cfg.PIDFilter {
		return nil
	}

	// Path filter.
	if o.cfg.PathFilter != "" && !strings.HasPrefix(e.Path, o.cfg.PathFilter) {
		return nil
	}

	o.mu.Lock()
	if e.PID == int32(os.Getpid()) && e.Mask&unix.FAN_OPEN != 0 && o.pendingHashOpens[e.Path] > 0 {
		o.pendingHashOpens[e.Path]--
		if o.pendingHashOpens[e.Path] == 0 {
			delete(o.pendingHashOpens, e.Path)
		}
		o.mu.Unlock()
		e.Mask &^= unix.FAN_OPEN
		if e.Mask == 0 {
			return nil
		}
	} else {
		o.mu.Unlock()
	}

	// Bump the per-path write generation before dispatching anything. A
	// write-class event means the file's content just changed; hashSettled
	// snapshots this value before reading a close's content and compares it
	// again afterward (via a synchronous catch-up drain, not just whatever
	// this call happened to see), to detect a write landing in the TOCTOU
	// window either before the read started or during it. The observer's
	// own hash-read is a FAN_OPEN only (already stripped above) and never
	// write-class, so it does not bump the generation.
	if e.Mask&(unix.FAN_CREATE|unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE) != 0 {
		o.mu.Lock()
		if o.pathGeneration == nil {
			o.pathGeneration = make(map[string]uint64)
		}
		o.pathGeneration[e.Path]++
		o.mu.Unlock()
	}

	var pending []pendingHash
	for _, actionType := range maskToActionTypes(e.Mask) {
		if actionType == models.FileClose {
			pending = append(pending, pendingHash{target: e.Path, ts: ts})
		} else {
			o.events <- models.GroundTruthEvent{
				Timestamp:  ts,
				ActionType: actionType,
				Target:     e.Path,
			}
		}
	}
	return pending
}

// hashAndEmit resolves every pending FileClose to a GroundTruthEvent and
// emits it. It is a worklist rather than a single pass over pending because
// hashSettled's own catch-up drain (see below) can discover further closes
// -- for this path or another -- that arrived while a hash was being read;
// those need the same treatment, with their own fresh generation snapshot,
// not to be silently dropped.
func (o *Observer) hashAndEmit(pending []pendingHash, buf []byte) {
	for len(pending) > 0 {
		p := pending[0]
		pending = pending[1:]

		digest, ok, more := o.hashSettled(p.target, buf)
		pending = append(pending, more...)

		event := models.GroundTruthEvent{
			Timestamp:  p.ts,
			ActionType: models.FileClose,
			Target:     p.target,
			// OutputHash left nil below when hashing failed, or the file
			// changed again before the read could be trusted to reflect
			// this specific close.
		}
		if ok {
			event.OutputHash = &digest
		}
		o.events <- event
	}
}

// hashSettled reads target's content and decides whether that read can be
// trusted to represent the close it's being attached to. Hashing happens
// synchronously here, in the single reader goroutine, specifically so the
// generation check below is authoritative rather than racing an
// independently-scheduled goroutine: after hashFile returns, it drains
// (non-blocking) anything already sitting in the fanotify queue -- which,
// by fanotify's own ordering guarantee, already includes the notification
// for any write whose syscall has already completed, whether or not this
// observer has processed it yet -- before comparing the path's generation
// against the snapshot taken before the read. If they differ, the file was
// touched again in that window and the read cannot be trusted.
//
// The returned pendingHash slice is whatever the catch-up drain discovered;
// the caller (hashAndEmit) is responsible for resolving those too.
func (o *Observer) hashSettled(target string, buf []byte) (digest string, ok bool, more []pendingHash) {
	o.mu.Lock()
	gen := o.pathGeneration[target]
	if o.pendingHashOpens == nil {
		o.pendingHashOpens = make(map[string]int)
	}
	o.pendingHashOpens[target]++
	o.mu.Unlock()

	d, err := o.hashFile(target)

	more = o.drainNonBlocking(buf)

	o.mu.Lock()
	raced := o.pathGeneration[target] != gen
	if err != nil {
		// Hashing failed early enough that no FAN_OPEN was generated, so
		// the pendingHashOpens bump won't be balanced by the self-open
		// path; undo it here. On the success path (including a raced
		// success) the read did open the file, so that decrement happens
		// when the self-FAN_OPEN is processed -- very likely already, by
		// the drain just above.
		o.pendingHashOpens[target]--
		if o.pendingHashOpens[target] == 0 {
			delete(o.pendingHashOpens, target)
		}
	}
	o.mu.Unlock()

	if err != nil || raced {
		return "", false, more
	}
	return d, true, more
}

// maskToActionTypes maps fanotify event mask bits to models.ActionType values.
// If multiple bits map to the same ActionType, only one is emitted.
func maskToActionTypes(mask uint64) []models.ActionType {
	seen := make(map[models.ActionType]bool, 4)
	var types []models.ActionType

	add := func(at models.ActionType) {
		if !seen[at] {
			seen[at] = true
			types = append(types, at)
		}
	}

	if mask&unix.FAN_CREATE != 0 {
		add(models.FileWrite)
	}
	if mask&unix.FAN_MODIFY != 0 {
		add(models.FileWrite)
	}
	if mask&unix.FAN_CLOSE_WRITE != 0 {
		add(models.FileClose)
	}
	if mask&unix.FAN_DELETE != 0 {
		add(models.FileDelete)
	}
	if mask&unix.FAN_MOVED_FROM != 0 {
		add(models.FileRename)
	}
	if mask&unix.FAN_MOVED_TO != 0 {
		add(models.FileRename)
	}
	if mask&unix.FAN_OPEN != 0 {
		add(models.FileOpen)
	}

	return types
}
