// Package proc is the Tier 2 process probe. It attaches eBPF tracepoints to
// execve and process exit and emits models.GroundTruthEvent values that an
// independent verifier can compare against an agent's self-reported trajectory.
package proc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// The -I flag points clang at the multiarch UAPI headers (<asm/types.h>);
// x86_64-linux-gnu matches both local dev and the x86_64 CI runner. Add other
// triplets here if the build ever moves to a different architecture.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type event bpf proc.bpf.c -- -I/usr/include/x86_64-linux-gnu

// Kind values mirror the KIND_* constants in proc.bpf.c.
const (
	kindExec uint32 = 0
	kindExit uint32 = 1
)

// argSlot mirrors ARG_SLOT in proc.bpf.c: the BPF program writes each argv
// entry into its own fixed-width slot, and this side rejoins them.
const argSlot = 128

// Config controls the observer's behavior.
type Config struct {
	// PIDFilter, if > 0, restricts emitted events to this process tree. The
	// configured PID is the ancestry root; its direct children are top-level
	// events and deeper descendants are forensic-only events.
	PIDFilter int32

	// CommandFilter, if non-empty, restricts emitted events to commands whose
	// reconstructed command line has this prefix (e.g. "/usr/bin/git"). Useful
	// in tests and on shared hosts.
	CommandFilter string

	// EventBufSize is the channel buffer size for emitted events.
	// Defaults to 4096 if zero.
	EventBufSize int
}

// Observer watches process spawns via eBPF and emits GroundTruthEvents.
type Observer struct {
	objs          bpfObjects
	execLink      link.Link
	forkLink      link.Link
	exitLink      link.Link
	exitGroupLink link.Link
	reader        *ringbuf.Reader
	events        chan models.GroundTruthEvent
	stopped       chan struct{}
	cfg           Config
	dropped       atomic.Uint64
	stopOnce      sync.Once

	// bootOffsetNs converts a bpf_ktime_get_ns() reading (ns since boot) to a
	// wall-clock UnixNano. Computed once at New() from a matched pair of
	// CLOCK_MONOTONIC and wall-clock reads, so it drifts slowly with NTP
	// adjustments over long uptimes -- acceptable for a probe whose consumer
	// compares timestamps within a configurable delta, not exactly.
	bootOffsetNs int64
}

// New loads the eBPF programs, attaches the tracepoints, and opens the ring
// buffer. The caller must call Start to begin receiving events and Stop to
// release resources. Requires CAP_BPF + CAP_PERFMON (or root).
func New(cfg Config) (*Observer, error) {
	if cfg.EventBufSize <= 0 {
		cfg.EventBufSize = 4096
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	bootOffsetNs, err := computeBootOffsetNs()
	if err != nil {
		return nil, fmt.Errorf("compute boot offset: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	if cfg.PIDFilter > 0 {
		zero := uint32(0)
		one := uint8(1)
		if err := objs.ConfigMap.Update(&zero, &one, ebpf.UpdateAny); err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("update config_map: %w", err)
		}
		pid := uint32(cfg.PIDFilter)
		info := bpfProcInfo{IsShell: 1}
		if err := objs.TrackedPids.Update(&pid, &info, ebpf.UpdateAny); err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("update tracked_pids: %w", err)
		}
	}

	forkLink, err := link.Tracepoint("task", "task_newtask", objs.HandleFork, nil)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach task_newtask: %w", err)
	}

	execLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_execve: %w", err)
	}

	exitGroupLink, err := link.Tracepoint("syscalls", "sys_enter_exit_group", objs.HandleExitGroup, nil)
	if err != nil {
		_ = execLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_exit_group: %w", err)
	}

	exitLink, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		_ = exitGroupLink.Close()
		_ = execLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sched_process_exit: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = exitLink.Close()
		_ = exitGroupLink.Close()
		_ = execLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	return &Observer{
		objs:          objs,
		execLink:      execLink,
		forkLink:      forkLink,
		exitLink:      exitLink,
		exitGroupLink: exitGroupLink,
		reader:        reader,
		events:        make(chan models.GroundTruthEvent, cfg.EventBufSize),
		stopped:       make(chan struct{}),
		cfg:           cfg,
		bootOffsetNs:  bootOffsetNs,
	}, nil
}

// computeBootOffsetNs pairs a CLOCK_MONOTONIC read with a wall-clock read
// taken immediately after, and returns the constant such that
// wallNs = monotonicNs + bootOffsetNs for any later bpf_ktime_get_ns()
// reading (which is also CLOCK_MONOTONIC-based).
func computeBootOffsetNs() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("clock_gettime CLOCK_MONOTONIC: %w", err)
	}
	monoNs := ts.Nano()
	wallNs := time.Now().UnixNano()
	return wallNs - monoNs, nil
}

// Events returns the channel on which GroundTruthEvents are delivered.
// The channel is closed when Stop returns.
func (o *Observer) Events() <-chan models.GroundTruthEvent {
	return o.events
}

// Dropped reports how many events were discarded because the events channel was
// full. Check after Stop returns.
func (o *Observer) Dropped() uint64 {
	return o.dropped.Load()
}

// Start begins reading ring-buffer records in a background goroutine.
func (o *Observer) Start() {
	go o.readLoop()
}

// Stop unblocks the read loop, waits for it, and releases all resources.
// The events channel is closed after Stop returns. Safe to call once.
func (o *Observer) Stop() error {
	o.stopOnce.Do(func() {
		_ = o.reader.Close() // unblocks readLoop's Read with ErrClosed
		<-o.stopped
		_ = o.exitLink.Close()
		_ = o.exitGroupLink.Close()
		_ = o.forkLink.Close()
		_ = o.execLink.Close()
		_ = o.objs.Close()
		close(o.events)
	})
	return nil
}

func (o *Observer) readLoop() {
	defer close(o.stopped)

	var raw bpfEvent
	eventSize := binary.Size(raw)

	for {
		record, err := o.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if len(record.RawSample) < eventSize {
			continue
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &raw); err != nil {
			continue
		}
		// The root process's initial exec can happen before SetRootPID installs
		// the ancestry filter. The root itself is the controller, not an agent
		// action, so never expose its events as verification-grade events.
		if o.cfg.PIDFilter > 0 && int32(raw.Pid) == o.cfg.PIDFilter {
			continue
		}

		var actionType models.ActionType
		switch raw.Kind {
		case kindExec:
			actionType = models.ProcessExec
		case kindExit:
			actionType = models.ProcessExit
		default:
			continue
		}
		target := commandLine(raw.Args[:], raw.Nargs)
		if target == "" {
			continue
		}
		if o.cfg.CommandFilter != "" && !strings.HasPrefix(target, o.cfg.CommandFilter) {
			continue
		}

		isTopLevel := raw.IsToplevel == 1
		event := models.GroundTruthEvent{
			Timestamp:  time.Unix(0, raw.TsNs+o.bootOffsetNs),
			ActionType: actionType,
			Target:     target,
			IsTopLevel: &isTopLevel,
		}
		if raw.HasExitCode != 0 {
			code := raw.ExitCode
			event.ExitCode = &code
		}

		select {
		case o.events <- event:
		default:
			o.dropped.Add(1)
		}
	}
}

// commandLine rejoins the fixed-width argv slots written by the BPF program
// into a single space-separated command line. nargs bounds how many slots the
// probe populated; anything beyond it, or any empty slot, is skipped.
func commandLine(args []int8, nargs uint32) string {
	slots := len(args) / argSlot
	if n := int(nargs); n < slots {
		slots = n
	}

	parts := make([]string, 0, slots)
	for i := 0; i < slots; i++ {
		if s := cString(args[i*argSlot : (i+1)*argSlot]); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// cString converts a NUL-terminated C char array (int8 on this platform) into a
// Go string.
func cString(b []int8) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

// SetRootPID configures the probe to only track this process and its descendants.
// It also clears the CommandFilter if any, since ancestry tracking replaces it.
func (o *Observer) SetRootPID(pid int32) error {
	zero := uint32(0)
	one := uint8(1)
	if err := o.objs.ConfigMap.Update(&zero, &one, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update config_map: %w", err)
	}
	p := uint32(pid)
	info := bpfProcInfo{IsShell: 1}
	if err := o.objs.TrackedPids.Update(&p, &info, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update tracked_pids: %w", err)
	}
	o.cfg.PIDFilter = pid
	o.cfg.CommandFilter = ""
	return nil
}
