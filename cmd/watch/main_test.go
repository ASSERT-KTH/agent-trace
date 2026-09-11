package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func skipUnprivileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root (fanotify + eBPF)")
	}
}

// TestRunWatch_ExecWrapSuppressesRootSeesChild exercises the Fix 3a wiring:
// runWatch launches the "agent" itself and records its PID as the proc
// probe's ancestry root. Two properties must hold:
//
//   - the agent process's own exec must NOT appear as a ground-truth event
//     (it is the controller, not an agent action), matching the suppression
//     tests/e2e/tier2_test.go's runTier2Agent already relies on;
//   - a child the agent spawns MUST appear, tagged top-level.
//
// The fake agent is a shell (the ancestry root) that forks one child,
// `/bin/echo <nonce>`, via `&` so the shell genuinely forks rather than
// exec-ing echo in place.
func TestRunWatch_ExecWrapSuppressesRootSeesChild(t *testing.T) {
	skipUnprivileged(t)

	ws := t.TempDir()
	out := filepath.Join(t.TempDir(), "ground_truth.json")
	nonce := fmt.Sprintf("watch-3a-%d", time.Now().UnixNano())
	// sleep 0.1 prevents a scheduler race where the child shell runs and forks
	// before the parent watch process has a chance to call SetRootPID.
	script := "sleep 0.1 && /bin/echo " + nonce + " & wait"

	opts := watchOptions{
		cfg:       watchConfig{Workspace: ws, EventBufSize: 256},
		probes:    "proc",
		out:       out,
		agentArgs: []string{"/bin/sh", "-c", script},
	}

	if err := runWatch(opts); err != nil {
		t.Fatalf("runWatch: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	var ground models.GroundTruth
	if err := json.Unmarshal(data, &ground); err != nil {
		t.Fatalf("unmarshal ground truth: %v", err)
	}

	var sawRoot, sawChild bool
	for _, e := range ground {
		if e.ActionType != models.ProcessExec {
			continue
		}
		if strings.HasPrefix(e.Target, "/bin/sh") && strings.Contains(e.Target, nonce) {
			// The root shell's own exec line (its argv carries the -c script).
			sawRoot = true
		}
		if strings.HasPrefix(e.Target, "/bin/echo") && strings.Contains(e.Target, nonce) {
			sawChild = true
			if e.IsTopLevel != nil && !*e.IsTopLevel {
				t.Errorf("child exec %q tagged forensic-only, want top-level", e.Target)
			}
		}
	}
	if sawRoot {
		t.Errorf("root agent exec leaked into ground truth; events: %+v", ground)
	}
	if !sawChild {
		t.Errorf("child exec (echo %s) missing from ground truth; events: %+v", nonce, ground)
	}
}

// TestRunWatch_RejectsRootPIDWithCommand is a pure-logic guard that needs no
// privileges: the two ancestry-root mechanisms are mutually exclusive.
func TestRunWatch_RejectsRootPIDWithCommand(t *testing.T) {
	err := runWatch(watchOptions{
		cfg:       watchConfig{Workspace: t.TempDir()},
		probes:    "proc",
		rootPID:   1234,
		agentArgs: []string{"/bin/true"},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}
