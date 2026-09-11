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
	// (see the TOCTOU note on hashSettled). This catches a write racing
	// during one specific hash read; it is not sufficient on its own to
	// guarantee a hash reflects the file's eventual final content -- see
	// pendingCloses. Grows unboundedly for the observer's lifetime --
	// entries are never garbage collected, matching pendingHashOpens'
	// existing shape; revisit if a long-lived observer over many distinct
	// paths becomes a memory concern.
	pathGeneration map[string]uint64

	// pendingCloses holds, per path, the most recent FileClose still
	// waiting to prove it won't be superseded before it is trusted enough
	// to hash. See registerClose and resolveSettled for the full mechanism
	// and why "nothing changed while I was reading" (pathGeneration) isn't
	// by itself enough to guarantee a hash reflects the final content.
	pendingCloses map[string]*pendingClose

	// lastWriteAt records, per path, the observer's local time when it last
	// processed a write-class event (FAN_CREATE / FAN_MODIFY /
	// FAN_CLOSE_WRITE) for that path. resolveSettled will not hash a pending
	// close until this path has been quiet for settleDelay. "Survived one
	// readLoop iteration untouched" is not sufficient on a loaded host,
	// where an unrelated fanotify wakeup -- including the observer's own
	// hash-read FAN_OPEN -- can end an iteration microseconds after it
	// began, so an intermediate close in a write burst could otherwise be
	// hashed against content the very next write truncates. Grows
	// unboundedly for the observer's lifetime, like pathGeneration and
	// pendingHashOpens.
	lastWriteAt map[string]time.Time

	// settleDelay is how long a path must be quiet (no write-class event,
	// see lastWriteAt) before a pending close for it is hashed. Defaults to
	// settleQuietWindow; left zero by tests that drive
	// settleSnapshot/resolveSettled directly and want an immediate resolve.
	settleDelay time.Duration

	// hashFile computes the content hash for a closed file. Defaults to
	// content.SHA256File; overridable in tests to control the read's outcome.
	hashFile func(string) (string, error)

	mu sync.Mutex
}

// pendingClose is a FileClose observed for a path but not yet resolved to a
// GroundTruthEvent. Its identity (the pointer itself) is what registerClose
// and resolveSettled use to detect whether a given close survived a settle
// cycle untouched, so a new pendingClose value is always allocated rather
// than mutating one in place.
type pendingClose struct {
	ts time.Time // this close's own observed timestamp
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
		pendingCloses:    make(map[string]*pendingClose),
		lastWriteAt:      make(map[string]time.Time),
		settleDelay:      settleQuietWindow,
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

// settlePollMs bounds how long readLoop's poll ever blocks between settle
// checks. readLoop must wake periodically to re-judge pending closes (see
// resolveSettled) even when nothing new arrives on the fanotify fd, since a
// close becomes eligible to hash purely by the passage of quiet time
// (settleQuietWindow). Correctness does not depend on this value, but it
// caps how much latency polling itself adds on top of settleQuietWindow
// before a settled close's hash is actually published -- kept small so that
// total latency (window + at most one poll period) stays comfortably under
// the gap between an agent's distinct operations on a path (see
// settleQuietWindow).
const settlePollMs = 5

// settleQuietWindow is the default settleDelay: a path must go this long
// with no observed write-class event before a pending FileClose for it is
// hashed. "Survived one readLoop iteration untouched" is not enough -- on a
// loaded host an unrelated fanotify wakeup (including the observer's own
// hash-read FAN_OPEN) can end an iteration microseconds after it began, so
// an intermediate close in a write burst could otherwise be hashed against
// content the next write immediately truncates (round 3's CI failure).
//
// The value is bounded on both sides: it must exceed the sub-millisecond
// gaps within a single logical rewrite (so a burst never has a quiet gap
// this long, and a hash is only ever published once the writer has actually
// been starved for this whole window -- unlikely on any real scheduler, but
// the failure mode to keep in mind when considering raising this further),
// yet stay well below the gap between an agent's distinct operations on a
// path -- once a file is written, closed, then (say) renamed or deleted a
// short time later, its content is only hashable in the interval between.
// Together with settlePollMs, total publish latency is window + at most one
// poll period (~25ms), clearing the sub-millisecond burst-gap bound by
// ~1000x while leaving ample room under cmd/simagent's 50ms fixture gap (see
// TestObserver_CloseHashSurvivesQuickRename, the regression guard for this).
const settleQuietWindow = 20 * time.Millisecond

func (o *Observer) readLoop() {
	defer close(o.stopped)

	buf := make([]byte, 4096*metadataSize)
	pollFDs := []unix.PollFd{
		{Fd: int32(o.fanotifyFD), Events: unix.POLLIN},
		{Fd: int32(o.stopR), Events: unix.POLLIN},
	}

	for {
		_, err := unix.Poll(pollFDs, settlePollMs)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			o.flushPendingCloses(buf)
			return
		}

		// Stop signal received. Once stopping, no more writes will ever be
		// observed, so it is always safe to resolve whatever is still
		// pending rather than silently dropping it.
		if pollFDs[1].Revents&unix.POLLIN != 0 {
			o.flushPendingCloses(buf)
			return
		}

		// Snapshot before draining: resolveSettled uses this to tell which
		// pending closes survive this iteration untouched (identity-compared
		// against pendingCloses afterward), versus ones this same iteration
		// just registered or superseded. Surviving is necessary but not
		// sufficient -- resolveSettled additionally requires the path to
		// have been quiet for settleDelay before it hashes, since an
		// iteration can end almost immediately and a survivor can still be
		// superseded moments later by a write that hasn't happened yet. See
		// resolveSettled and registerClose for why this -- not pathGeneration
		// alone -- guarantees a published hash reflects the file's eventual
		// final content.
		before := o.settleSnapshot()
		if pollFDs[0].Revents&unix.POLLIN != 0 {
			o.drainNonBlocking(buf)
		}
		o.resolveSettled(before, buf, false)
	}
}

// drainNonBlocking processes every fanotify record currently available
// without blocking, returning once none remain (or the stop pipe becomes
// readable -- the caller's own next check notices that, so this just needs
// to not spin past it). Used both for readLoop's normal per-iteration
// pickup and, from hashSettled, as the synchronous catch-up that makes its
// generation check authoritative: any write whose syscall has already
// returned has its notification already enqueued here, whether or not this
// observer has gotten to it yet, so a non-blocking drain right before
// trusting a hash is not a best-effort peek, it is a real answer to "has
// anything else happened yet".
func (o *Observer) drainNonBlocking(buf []byte) {
	pollFDs := []unix.PollFd{
		{Fd: int32(o.fanotifyFD), Events: unix.POLLIN},
		{Fd: int32(o.stopR), Events: unix.POLLIN},
	}

	for {
		_, err := unix.Poll(pollFDs, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		if pollFDs[1].Revents&unix.POLLIN != 0 || pollFDs[0].Revents&unix.POLLIN == 0 {
			return
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
	// write-class event means the file's content just changed; hashSettled
	// snapshots this value before reading a close's content and compares it
	// again afterward (via a synchronous catch-up drain, not just whatever
	// this call happened to see), to detect a write landing in the TOCTOU
	// window either before the read started or during it. This alone only
	// proves nothing changed during one specific read -- it says nothing
	// about writes that haven't happened yet -- which is why registerClose
	// below carries the real guarantee for closes. The observer's own
	// hash-read is a FAN_OPEN only (already stripped above) and never
	// write-class, so it does not bump the generation.
	if e.Mask&(unix.FAN_CREATE|unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE) != 0 {
		o.mu.Lock()
		if o.pathGeneration == nil {
			o.pathGeneration = make(map[string]uint64)
		}
		if o.lastWriteAt == nil {
			o.lastWriteAt = make(map[string]time.Time)
		}
		o.pathGeneration[e.Path]++
		o.lastWriteAt[e.Path] = ts
		o.mu.Unlock()
	}

	for _, actionType := range maskToActionTypes(e.Mask) {
		if actionType == models.FileClose {
			o.registerClose(e.Path, ts)
		} else {
			o.events <- models.GroundTruthEvent{
				Timestamp:  ts,
				ActionType: actionType,
				Target:     e.Path,
			}
		}
	}
}

// registerClose records a newly observed FileClose for path as the pending
// one to judge on some future settle check (see resolveSettled). If a close
// was already pending for this same path, that older one is immediately
// superseded: a second close arriving proves the first's content is not the
// file's final content, so there's no point even reading it -- it is
// emitted right here with no OutputHash.
//
// This, not pathGeneration, is what actually guarantees a hash the observer
// does attach reflects the eventual final content: a close is never hashed
// until it has survived a full settle cycle with nothing superseding it.
func (o *Observer) registerClose(path string, ts time.Time) {
	o.mu.Lock()
	if o.pendingCloses == nil {
		o.pendingCloses = make(map[string]*pendingClose)
	}
	superseded, existed := o.pendingCloses[path]
	o.pendingCloses[path] = &pendingClose{ts: ts}
	o.mu.Unlock()

	if existed {
		o.events <- models.GroundTruthEvent{
			Timestamp:  superseded.ts,
			ActionType: models.FileClose,
			Target:     path,
			// No OutputHash: a newer close for this path arrived before
			// this one was ever judged settled.
		}
	}
}

// settleSnapshot copies the current pendingCloses so resolveSettled can
// later tell, by pointer identity, which entries survived a settle cycle
// unchanged.
func (o *Observer) settleSnapshot() map[string]*pendingClose {
	o.mu.Lock()
	defer o.mu.Unlock()
	snap := make(map[string]*pendingClose, len(o.pendingCloses))
	for path, entry := range o.pendingCloses {
		snap[path] = entry
	}
	return snap
}

// resolveSettled hashes and emits every entry in before that is both still
// the current pendingCloses entry for its path (survived this settle cycle
// without a newer close superseding it, see registerClose) and whose path
// has been quiet -- no write-class event -- for at least settleDelay. Such
// an entry is removed from pendingCloses and emitted, with an OutputHash
// unless hashing failed or hashSettled's own check caught a write during
// the read. An entry that was superseded, or already resolved by a
// concurrent call, is left alone (registerClose emitted it). An entry that
// is still current but not yet quiet is left in pendingCloses for a later
// cycle to judge. force skips the quiet check: at shutdown no further write
// can ever be observed, so every survivor is by definition settled.
func (o *Observer) resolveSettled(before map[string]*pendingClose, buf []byte, force bool) {
	for path, entry := range before {
		o.mu.Lock()
		current, ok := o.pendingCloses[path]
		settled := ok && current == entry
		quiet := force || time.Since(o.lastWriteAt[path]) >= o.settleDelay
		if settled && quiet {
			delete(o.pendingCloses, path)
		}
		o.mu.Unlock()

		if !settled || !quiet {
			continue
		}

		digest, ok := o.hashSettled(path, buf)
		event := models.GroundTruthEvent{
			Timestamp:  entry.ts,
			ActionType: models.FileClose,
			Target:     path,
			// OutputHash left nil below when hashing failed, or a write
			// raced in during the read itself (hashSettled's own check);
			// a write landing before this point would instead have gone
			// through registerClose's supersession above, or held this
			// close back via the quiet check.
		}
		if ok {
			event.OutputHash = &digest
		}
		o.events <- event
	}
}

// flushPendingCloses resolves everything still pending at shutdown. Once
// the observer is stopping, no more writes will ever be observed, so every
// remaining entry is by definition settled.
func (o *Observer) flushPendingCloses(buf []byte) {
	o.resolveSettled(o.settleSnapshot(), buf, true)
}

// hashSettled reads target's content and decides whether that specific read
// can be trusted, i.e. nothing changed while it was in progress. It is the
// second, narrower line of defense after registerClose/resolveSettled
// (which guarantee the close wasn't already superseded before this call):
// after hashFile returns, it drains (non-blocking) anything already sitting
// in the fanotify queue -- which, by fanotify's own ordering guarantee,
// already includes the notification for any write whose syscall has
// already completed, whether or not this observer has processed it yet --
// before comparing the path's generation against the snapshot taken before
// the read. If they differ, the file was touched again during the read and
// it cannot be trusted.
func (o *Observer) hashSettled(target string, buf []byte) (digest string, ok bool) {
	o.mu.Lock()
	gen := o.pathGeneration[target]
	if o.pendingHashOpens == nil {
		o.pendingHashOpens = make(map[string]int)
	}
	o.pendingHashOpens[target]++
	o.mu.Unlock()

	d, err := o.hashFile(target)

	o.drainNonBlocking(buf)

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
		return "", false
	}
	return d, true
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
