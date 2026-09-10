// Command watch is the ground-truth recorder half of the live verification
// harness (see the three-component architecture in
// docs/plan/01_protocol_architecture.md): it runs whichever probes are
// requested against a workspace, prints each ground-truth event as it is
// captured, and writes the accumulated ground truth to a JSON file that
// `verify` can compare against a trajectory.
//
// Invocation modes:
//
//   - watch --workspace PATH -- <agent command> [args...]
//     watch launches the agent itself, records its PID as the proc probe's
//     ancestry root (so the agent's own exec is suppressed and only its
//     descendants count as agent actions), runs it to completion, then
//     writes the ground truth. This is the mode that makes ancestry
//     tracking actually work.
//
//   - watch --workspace PATH --root-pid N
//     Attach the ancestry root to an already-running PID (e.g. a container
//     entrypoint watch cannot be the parent of). Anything that PID did
//     before this call is invisible to the proc probe; the fs probe is
//     unaffected. Records until Ctrl+C.
//
//   - watch --workspace PATH
//     No ancestry scoping. The proc probe reports every process on the host
//     unless --proc-filter narrows it. Records until Ctrl+C.
//
// Extending this for a new tier's probe is one addition to probeBuilders
// below; nothing else in this file needs to change.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	"github.com/agent-trace/agent-trace/pkg/probe/proc"
)

// watchConfig holds the flags a probe builder may need. Add fields here as
// new probes need new configuration (e.g. a listen address for a Tier 3
// network proxy).
type watchConfig struct {
	Workspace    string
	ProcFilter   string
	EventBufSize int

	// AncestryPending is true whenever runWatch will call the proc probe's
	// SetRootPID once the root PID becomes known (exec-wrap or --root-pid).
	// It tells the proc builder to start in ancestry-filtered mode from the
	// moment its tracepoints attach, instead of the zero-value global mode --
	// otherwise every process on the host would be recorded as top-level
	// ground truth during the window before SetRootPID runs.
	AncestryPending bool
}

type builderFunc func(watchConfig) (probe.Observer, error)

// probeBuilders is the extension point: one entry per probe this harness
// knows how to run. Add a case here when a new tier's probe lands, e.g.:
//
//	"net": func(cfg watchConfig) (probe.Observer, error) {
//		return net.New(net.Config{...})
//	},
var probeBuilders = map[string]builderFunc{
	"fs": func(cfg watchConfig) (probe.Observer, error) {
		return fs.New(fs.Config{
			Path:         cfg.Workspace,
			PathFilter:   cfg.Workspace,
			EventBufSize: cfg.EventBufSize,
		})
	},
	"proc": func(cfg watchConfig) (probe.Observer, error) {
		return proc.New(proc.Config{
			CommandFilter: cfg.ProcFilter,
			EventBufSize:  cfg.EventBufSize,
			DeferRootPID:  cfg.AncestryPending,
		})
	},
}

func availableProbes() string {
	names := make([]string, 0, len(probeBuilders))
	for name := range probeBuilders {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// watchOptions is the fully parsed configuration for one runWatch call.
// main() fills it from flags; tests construct it directly.
type watchOptions struct {
	cfg       watchConfig
	probes    string
	out       string
	rootPID   int
	agentArgs []string // command (and args) after "--"; empty means no exec-wrap
}

func main() {
	var workspace, probesFlag, procFilter, out string
	var bufSize, rootPID int

	flag.StringVar(&workspace, "workspace", "", "Path to the workspace to watch (fs probe)")
	flag.StringVar(&probesFlag, "probes", "fs,proc", "Comma-separated probes to run (available: "+availableProbes()+")")
	flag.StringVar(&procFilter, "proc-filter", "", "Only report processes whose command line has this prefix (proc probe); ignored when an agent command or --root-pid is given, since ancestry scoping replaces it")
	flag.StringVar(&out, "out", "ground_truth.json", "Path to write the captured ground truth JSON on exit")
	flag.IntVar(&bufSize, "buf", 4096, "Per-probe event channel buffer size")
	flag.IntVar(&rootPID, "root-pid", 0, "Attach the proc probe's ancestry root to this already-running PID instead of launching the agent. RACE: anything that PID did before this call is invisible to the proc probe (the fs probe is unaffected). Mutually exclusive with a trailing -- <command>.")
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		_, _ = fmt.Fprintln(out, "Usage: watch --workspace PATH [flags] [-- <agent command> [args...]]")
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "With a trailing `-- <command>`, watch launches the command, records its PID as")
		_, _ = fmt.Fprintln(out, "the proc probe's ancestry root, runs it to completion, then writes the ground")
		_, _ = fmt.Fprintln(out, "truth. Without one, watch records until Ctrl+C.")
		_, _ = fmt.Fprintln(out)
		flag.PrintDefaults()
	}
	flag.Parse()

	opts := watchOptions{
		cfg:       watchConfig{Workspace: workspace, ProcFilter: procFilter, EventBufSize: bufSize},
		probes:    probesFlag,
		out:       out,
		rootPID:   rootPID,
		agentArgs: flag.Args(),
	}
	if err := runWatch(opts); err != nil {
		log.Fatal(err)
	}
}

// runWatch builds the requested probes, records ground truth according to the
// invocation mode implied by opts, and writes the result to opts.out. It is
// the whole of watch's behavior, split out from main so it can be tested.
func runWatch(opts watchOptions) error {
	if opts.cfg.Workspace == "" {
		return errors.New("--workspace is required")
	}
	if opts.rootPID != 0 && len(opts.agentArgs) > 0 {
		return errors.New("--root-pid and a trailing `-- <command>` are mutually exclusive")
	}
	if os.Getuid() != 0 {
		return errors.New("watch requires root (fanotify + eBPF); rerun with sudo")
	}

	// Ancestry scoping (exec-wrap or --root-pid) calls SetRootPID once the
	// root PID is known, some time after the proc probe is built. Flag that
	// now so the proc builder starts filtered from the outset instead of in
	// global mode for that window -- see watchConfig.AncestryPending.
	opts.cfg.AncestryPending = len(opts.agentArgs) > 0 || opts.rootPID != 0

	// Build probes. The proc observer is held separately from the rest: its
	// SetRootPID isn't part of the probe.Observer interface, and its Start
	// must be sequenced after the ancestry root PID is known.
	var others []probe.Observer
	var procObs *proc.Observer
	for _, name := range strings.Split(opts.probes, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		build, ok := probeBuilders[name]
		if !ok {
			return fmt.Errorf("unknown probe %q (available: %s)", name, availableProbes())
		}
		obs, err := build(opts.cfg)
		if err != nil {
			return fmt.Errorf("start %s probe: %w", name, err)
		}
		if name == "proc" {
			p, ok := obs.(*proc.Observer)
			if !ok {
				return fmt.Errorf("proc builder returned %T, want *proc.Observer", obs)
			}
			procObs = p
			continue
		}
		others = append(others, obs)
	}
	if len(others) == 0 && procObs == nil {
		return errors.New("no probes selected")
	}
	if opts.rootPID != 0 && procObs == nil {
		return errors.New("--root-pid requires the proc probe")
	}

	var (
		mu     sync.Mutex
		ground models.GroundTruth
		wg     sync.WaitGroup
	)
	collect := func(o probe.Observer) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range o.Events() {
				fmt.Printf("%s  %-14s %s", e.Timestamp.Format("15:04:05.000"), e.ActionType, e.Target)
				if e.ExitCode != nil {
					fmt.Printf("  (exit %d)", *e.ExitCode)
				}
				fmt.Println()
				mu.Lock()
				ground = append(ground, e)
				mu.Unlock()
			}
		}()
	}

	// Every non-proc observer starts now. The proc observer's readLoop starts
	// only once its ancestry root PID is known, so the root's own (already
	// buffered) execve is reliably suppressed by PID -- matching the ordering
	// in tests/e2e/tier2_test.go's runTier2Agent.
	for _, o := range others {
		collect(o)
		o.Start()
	}
	if procObs != nil {
		collect(procObs)
	}

	procStarted := false
	startProc := func() {
		if procObs != nil && !procStarted {
			procObs.Start()
			procStarted = true
		}
	}
	stopEverything := func() {
		// Ensure the proc readLoop exists before Stop, or Stop blocks
		// forever waiting on a goroutine that was never launched.
		startProc()
		for _, o := range others {
			if err := o.Stop(); err != nil {
				log.Printf("stop probe: %v", err)
			}
		}
		if procObs != nil {
			if err := procObs.Stop(); err != nil {
				log.Printf("stop proc probe: %v", err)
			}
		}
		wg.Wait()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	var agentErr error
	switch {
	case len(opts.agentArgs) > 0:
		// Give the fs probe a moment to be fully reading before the agent runs.
		time.Sleep(200 * time.Millisecond)

		cmd := exec.Command(opts.agentArgs[0], opts.agentArgs[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Start(); err != nil {
			stopEverything()
			return fmt.Errorf("start agent %q: %w", opts.agentArgs[0], err)
		}
		// SetRootPID after Start (PID must exist) but before the proc readLoop
		// starts, so the root's buffered execve is dropped by PID match.
		if procObs != nil {
			if err := procObs.SetRootPID(int32(cmd.Process.Pid)); err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				stopEverything()
				return fmt.Errorf("set proc probe root pid: %w", err)
			}
			startProc()
		}
		fmt.Printf("watching %s (probes: %s) -- running %s\n",
			opts.cfg.Workspace, opts.probes, strings.Join(opts.agentArgs, " "))

		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case agentErr = <-done:
		case <-sigCh:
			fmt.Println("\ninterrupted -- stopping the agent early")
			_ = cmd.Process.Kill()
			<-done
		}
		// Let the kernel deliver, and the probes drain, the trailing events.
		time.Sleep(300 * time.Millisecond)

	case opts.rootPID > 0:
		if err := procObs.SetRootPID(int32(opts.rootPID)); err != nil {
			stopEverything()
			return fmt.Errorf("set proc probe root pid: %w", err)
		}
		startProc()
		fmt.Printf("watching %s (probes: %s), proc ancestry root pid %d -- press Ctrl+C to stop and write %s\n",
			opts.cfg.Workspace, opts.probes, opts.rootPID, opts.out)
		<-sigCh

	default:
		startProc()
		fmt.Printf("watching %s (probes: %s) -- press Ctrl+C to stop and write %s\n",
			opts.cfg.Workspace, opts.probes, opts.out)
		<-sigCh
	}

	fmt.Println("\nstopping probes...")
	stopEverything()

	sort.Slice(ground, func(i, j int) bool { return ground[i].Timestamp.Before(ground[j].Timestamp) })

	b, err := json.MarshalIndent(ground, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal ground truth: %w", err)
	}
	if err := os.WriteFile(opts.out, b, 0644); err != nil {
		return fmt.Errorf("write %s: %w", opts.out, err)
	}
	fmt.Printf("wrote %d events to %s\n", len(ground), opts.out)

	if agentErr != nil {
		return fmt.Errorf("agent exited with error: %w", agentErr)
	}
	return nil
}
