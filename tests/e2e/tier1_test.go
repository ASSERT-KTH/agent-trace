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
	cmd := exec.Command(binPath, "--workspace", workspace, "--trajectory-out", trajectoryPath)
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
	cmd := exec.Command(binPath, "--workspace", workspace, "--trajectory-out", trajectoryPath)
	if err := cmd.Run(); err != nil {
		t.Fatalf("simagent failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	obs.Stop()

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
