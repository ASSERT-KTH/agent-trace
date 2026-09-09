package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

func skipUnprivileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root or CAP_SYS_ADMIN")
	}
}

// buildSimAgent compiles the cmd/simagent binary and returns the path to it.
func buildSimAgent(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "simagent")

	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/simagent")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build simagent: %v\n%s", err, string(out))
	}
	return binPath
}

func TestTier1_E2E_Faithful(t *testing.T) {
	skipUnprivileged(t)

	binPath := buildSimAgent(t)
	workspace := t.TempDir()
	trajectoryPath := filepath.Join(t.TempDir(), "trajectory.json")

	// 1. Start the FS probe (Observer) on the workspace.
	obs, err := fs.New(fs.Config{
		Path:         workspace,
		PathFilter:   workspace,
		EventBufSize: 4096,
		// We could set PIDFilter, but the subprocess hasn't started yet.
		// Since workspace is a new TempDir, there's no interference.
	})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	obs.Start()

	// 2. Run the simagent.
	cmd := exec.Command(binPath, "--workspace", workspace, "--trajectory-out", trajectoryPath, "--file-only")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("simagent failed: %v\n%s", err, string(out))
	}

	// Give the kernel and probe a moment to queue and process events.
	time.Sleep(500 * time.Millisecond)

	// 3. Stop the observer and collect ground truth.
	if err := obs.Stop(); err != nil {
		t.Fatalf("obs.Stop: %v", err)
	}

	var g models.GroundTruth
	for e := range obs.Events() {
		// On some filesystems (tmpfs), directory events like DELETE resolve to
		// the parent directory rather than the target file. We normalize here
		// for the 1-to-1 matching if needed, though simagent also works in TempDir.
		// For simplicity, we just take the events as is.
		g = append(g, e)
	}

	// 4. Ingest the trajectory (F1.3).
	data, err := os.ReadFile(trajectoryPath)
	if err != nil {
		t.Fatalf("failed to read trajectory: %v", err)
	}
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatalf("models.ParseTrajectory: %v", err)
	}

	// 5. Verify
	cfg := matching.Config{
		Delta: 2 * time.Second, // Generous delta for e2e
	}
	verdict := verification.Verify(tr, g, cfg)

	if !verdict.Faithful {
		t.Errorf("expected FAITHFUL verdict, got NOT FAITHFUL")
		t.Logf("Unwitnessed: %d", len(verdict.Unwitnessed))
		for _, e := range verdict.Unwitnessed {
			t.Logf("  %s %s", e.ActionType, e.Target)
		}
		t.Logf("Unrecorded: %d", len(verdict.Unrecorded))
		for _, e := range verdict.Unrecorded {
			t.Logf("  %s %s", e.ActionType, e.Target)
		}
		t.Logf("Mismatched: %d", len(verdict.Mismatched))
	}
}

func TestTier1_E2E_NotFaithful_Omission(t *testing.T) {
	skipUnprivileged(t)

	binPath := buildSimAgent(t)
	workspace := t.TempDir()
	trajectoryPath := filepath.Join(t.TempDir(), "trajectory.json")

	// 1. Start probe
	obs, err := fs.New(fs.Config{
		Path:       workspace,
		PathFilter: workspace,
	})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	obs.Start()

	// 2. Run agent
	cmd := exec.Command(binPath, "--workspace", workspace, "--trajectory-out", trajectoryPath, "--file-only")
	if err := cmd.Run(); err != nil {
		t.Fatalf("simagent failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	_ = obs.Stop()

	var g models.GroundTruth
	for e := range obs.Events() {
		g = append(g, e)
	}

	// 4. Ingest and mutate (Omission Attack)
	data, _ := os.ReadFile(trajectoryPath)
	tr, _ := models.ParseTrajectory(data)

	// Drop the first entry to simulate omission
	if len(tr) > 0 {
		tr = tr[1:]
	}

	// 5. Verify
	cfg := matching.Config{Delta: 2 * time.Second}
	verdict := verification.Verify(tr, g, cfg)

	if verdict.Faithful {
		t.Errorf("expected NOT FAITHFUL verdict due to omission")
	}
	if len(verdict.Unrecorded) == 0 {
		t.Errorf("expected at least one Unrecorded event")
	}
}

func TestTier1_E2E_NotFaithful_Fabrication(t *testing.T) {
	skipUnprivileged(t)

	binPath := buildSimAgent(t)
	workspace := t.TempDir()
	trajectoryPath := filepath.Join(t.TempDir(), "trajectory.json")

	// 1. Start probe
	obs, err := fs.New(fs.Config{
		Path:       workspace,
		PathFilter: workspace,
	})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	obs.Start()

	// 2. Run agent
	cmd := exec.Command(binPath, "--workspace", workspace, "--trajectory-out", trajectoryPath, "--file-only")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("simagent failed: %v\n%s", err, string(out))
	}

	time.Sleep(200 * time.Millisecond)
	_ = obs.Stop()

	var g models.GroundTruth
	for e := range obs.Events() {
		g = append(g, e)
	}

	// 4. Ingest and mutate (Fabrication Attack): insert an entry for a file
	// open that never happened. The path is inside the tracked workspace, so a
	// real open would have been observed; since it wasn't, the entry has no
	// ground-truth counterpart and lands in Unwitnessed.
	data, _ := os.ReadFile(trajectoryPath)
	tr, _ := models.ParseTrajectory(data)
	if len(tr) == 0 {
		t.Fatal("simagent produced an empty trajectory")
	}

	ghost := models.TrajectoryEntry{
		Timestamp:  tr[0].Timestamp.Add(time.Millisecond),
		ActionType: models.FileOpen,
		Target:     filepath.Join(workspace, "ghost.txt"),
	}
	tr = append(tr, ghost)

	// 5. Verify
	cfg := matching.Config{Delta: 2 * time.Second}
	verdict := verification.Verify(tr, g, cfg)

	if verdict.Faithful {
		t.Fatal("expected NOT FAITHFUL verdict due to fabricated entry")
	}
	found := false
	for _, e := range verdict.Unwitnessed {
		if e.Target == ghost.Target && e.ActionType == ghost.ActionType {
			found = true
		}
	}
	if !found {
		t.Errorf("fabricated entry %s %s not in Unwitnessed set", ghost.ActionType, ghost.Target)
	}
}

func TestTier1_E2E_NotFaithful_FilenameSwap(t *testing.T) {
	skipUnprivileged(t)

	binPath := buildSimAgent(t)
	workspace := t.TempDir()
	trajectoryPath := filepath.Join(t.TempDir(), "trajectory.json")

	// 1. Start probe
	obs, err := fs.New(fs.Config{
		Path:       workspace,
		PathFilter: workspace,
	})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	obs.Start()

	// 2. Run agent
	cmd := exec.Command(binPath, "--workspace", workspace, "--trajectory-out", trajectoryPath, "--file-only")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("simagent failed: %v\n%s", err, string(out))
	}

	time.Sleep(200 * time.Millisecond)
	_ = obs.Stop()

	var g models.GroundTruth
	for e := range obs.Events() {
		g = append(g, e)
	}

	// 4. Ingest and mutate (Substitution Attack at occurrence level): repoint
	// one honest entry at a file the agent never touched, keeping its action
	// type and timestamp. The Tier 1 filesystem probe records no content
	// hashes, so this does not surface as Mismatched -- that needs Tier 4
	// content verification. At occurrence level the swapped entry loses its
	// ground-truth match (Unwitnessed) and the real event loses its entry
	// (Unrecorded); that pair is the occurrence-level signature of T3.
	data, _ := os.ReadFile(trajectoryPath)
	tr, _ := models.ParseTrajectory(data)

	realTarget := filepath.Join(workspace, "file1.txt")
	swapTarget := filepath.Join(workspace, "decoy.txt")
	swapped := false
	for i := range tr {
		if tr[i].Target == realTarget {
			tr[i].Target = swapTarget
			swapped = true
			break
		}
	}
	if !swapped {
		t.Fatalf("no entry referencing %s to swap", realTarget)
	}

	// 5. Verify
	cfg := matching.Config{Delta: 2 * time.Second}
	verdict := verification.Verify(tr, g, cfg)

	if verdict.Faithful {
		t.Fatal("expected NOT FAITHFUL verdict due to filename swap")
	}

	foundUnwitnessed := false
	for _, e := range verdict.Unwitnessed {
		if e.Target == swapTarget {
			foundUnwitnessed = true
		}
	}
	if !foundUnwitnessed {
		t.Errorf("swapped entry %s not in Unwitnessed set", swapTarget)
	}

	foundUnrecorded := false
	for _, e := range verdict.Unrecorded {
		if e.Target == realTarget {
			foundUnrecorded = true
		}
	}
	if !foundUnrecorded {
		t.Errorf("real event %s not in Unrecorded set", realTarget)
	}
}
