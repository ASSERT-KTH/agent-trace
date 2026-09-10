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
	// FAN_CLOSE_WRITE) seen per path. The async post-close hash goroutine
	// captures the generation at dispatch and re-checks it after the hash
	// read completes: if the file was written again in that window, the
	// digest can no longer be trusted to reflect the observed close, so no
	// OutputHash is attached (see the TOCTOU note in processRawEvent). Grows
	// unboundedly for the observer's lifetime -- entries are never garbage
	// collected, matching pendingHashOpens' existing shape; revisit if a
	// long-lived observer over many distinct paths becomes a memory concern.
	pathGeneration map[string]uint64

	// hashFile computes the content hash for a closed file. Defaults to
	// content.SHA256File; overridable in tests to control goroutine timing.
	hashFile func(string) (string, error)

	mu sync.Mutex
	wg sync.WaitGroup
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
	// Wait for readLoop to finish.
	<-o.stopped
	o.wg.Wait()

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

		n, err := unix.Read(o.fanotifyFD, buf)
		if err != nil || n == 0 {
			return
		}

		now := time.Now()
		raw := parseEvents(buf, n, newKernelResolver(o.mountFD))
		for i := range raw {
			o.processRawEvent(&raw[i], now)
		}
	}
}

func (o *Observer) processRawEvent(e *rawEvent, ts time.Time) {
	if e.Mask&unix.FAN_Q_OVERFLOW != 0 {
		o.overflow = true
		return
	}

	// PID filter.
	if o.cfg.PIDFilter > 0 && e.PID != o.cfg.PIDFilter {
		return
	}

	// Path filter.
	if o.cfg.PathFilter != "" && !strings.HasPrefix(e.Path, o.cfg.PathFilter) {
		return
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
			return
		}
	} else {
		o.mu.Unlock()
	}

	// Bump the per-path write generation before dispatching anything. A
	// write-class event means the file's content just changed; the async
	// hash goroutine below compares this value after its read to detect a
	// second write landing in the TOCTOU window between the observed close
	// and the goroutine actually reading the file. The observer's own
	// hash-read is a FAN_OPEN only (already stripped above) and never
	// write-class, so it does not bump the generation.
	var gen uint64
	if e.Mask&(unix.FAN_CREATE|unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE) != 0 {
		o.mu.Lock()
		if o.pathGeneration == nil {
			o.pathGeneration = make(map[string]uint64)
		}
		o.pathGeneration[e.Path]++
		gen = o.pathGeneration[e.Path]
		o.mu.Unlock()
	}

	for _, actionType := range maskToActionTypes(e.Mask) {
		if actionType == models.FileClose {
			o.wg.Add(1)
			go func(action models.ActionType, target string, timestamp time.Time, gen uint64) {
				defer o.wg.Done()

				o.mu.Lock()
				if o.pendingHashOpens == nil {
					o.pendingHashOpens = make(map[string]int)
				}
				o.pendingHashOpens[target]++
				o.mu.Unlock()

				digest, err := o.hashFile(target)

				o.mu.Lock()
				raced := o.pathGeneration[target] != gen
				if err != nil {
					// Hashing failed early enough that no FAN_OPEN was
					// generated, so the pendingHashOpens bump won't be
					// balanced by the self-open path; undo it here. On the
					// success path (including a raced success) the read did
					// open the file, so that decrement happens when the
					// self-FAN_OPEN is processed.
					o.pendingHashOpens[target]--
					if o.pendingHashOpens[target] == 0 {
						delete(o.pendingHashOpens, target)
					}
				}
				o.mu.Unlock()

				if err != nil || raced {
					o.events <- models.GroundTruthEvent{
						Timestamp:  timestamp,
						ActionType: action,
						Target:     target,
						// No OutputHash: either hashing failed, or the file
						// changed again before the hash could be trusted to
						// reflect this specific close.
					}
					return
				}

				o.events <- models.GroundTruthEvent{
					Timestamp:  timestamp,
					ActionType: action,
					Target:     target,
					OutputHash: &digest,
				}
			}(actionType, e.Path, ts, gen)
		} else {
			o.events <- models.GroundTruthEvent{
				Timestamp:  ts,
				ActionType: actionType,
				Target:     e.Path,
			}
		}
	}
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
