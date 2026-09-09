// Command watch is the ground-truth recorder half of the live verification
// harness (see the three-component architecture in
// docs/plan/01_protocol_architecture.md): it runs whichever probes are
// requested against a workspace, prints each ground-truth event as it is
// captured, and on interrupt writes the accumulated ground truth to a JSON
// file that `verify` can compare against a trajectory.
//
// Extending this for a new tier's probe is one addition to probeBuilders
// below; nothing else in this file needs to change.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"

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

func main() {
	var workspace, probesFlag, procFilter, out string
	var bufSize int

	flag.StringVar(&workspace, "workspace", "", "Path to the workspace to watch (fs probe)")
	flag.StringVar(&probesFlag, "probes", "fs,proc", "Comma-separated probes to run (available: "+availableProbes()+")")
	flag.StringVar(&procFilter, "proc-filter", "", "Only report processes whose command line has this prefix (proc probe); empty means no filter")
	flag.StringVar(&out, "out", "ground_truth.json", "Path to write the captured ground truth JSON on exit")
	flag.IntVar(&bufSize, "buf", 4096, "Per-probe event channel buffer size")
	flag.Parse()

	if workspace == "" {
		log.Fatal("--workspace is required")
	}
	if os.Getuid() != 0 {
		log.Fatal("watch requires root (fanotify + eBPF); rerun with sudo")
	}

	cfg := watchConfig{Workspace: workspace, ProcFilter: procFilter, EventBufSize: bufSize}

	var observers []probe.Observer
	for _, name := range strings.Split(probesFlag, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		build, ok := probeBuilders[name]
		if !ok {
			log.Fatalf("unknown probe %q (available: %s)", name, availableProbes())
		}
		obs, err := build(cfg)
		if err != nil {
			log.Fatalf("start %s probe: %v", name, err)
		}
		observers = append(observers, obs)
	}
	if len(observers) == 0 {
		log.Fatal("no probes selected")
	}

	var (
		mu     sync.Mutex
		ground models.GroundTruth
		wg     sync.WaitGroup
	)

	for _, obs := range observers {
		obs.Start()
		wg.Add(1)
		go func(o probe.Observer) {
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
		}(obs)
	}

	fmt.Printf("watching %s (probes: %s) -- press Ctrl+C to stop and write %s\n", workspace, probesFlag, out)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nstopping probes...")
	for _, obs := range observers {
		if err := obs.Stop(); err != nil {
			log.Printf("stop probe: %v", err)
		}
	}
	wg.Wait()

	sort.Slice(ground, func(i, j int) bool { return ground[i].Timestamp.Before(ground[j].Timestamp) })

	b, err := json.MarshalIndent(ground, "", "  ")
	if err != nil {
		log.Fatalf("marshal ground truth: %v", err)
	}
	if err := os.WriteFile(out, b, 0644); err != nil {
		log.Fatalf("write %s: %v", out, err)
	}
	fmt.Printf("wrote %d events to %s\n", len(ground), out)
}
