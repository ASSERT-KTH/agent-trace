package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

func TestTier4_E2E_NotFaithful_ContentSubstitution(t *testing.T) {
	skipUnprivileged(t)

	binPath := buildSimAgent(t)
	workspace := t.TempDir()
	trajectoryPath := filepath.Join(t.TempDir(), "trajectory.json")

	observer, err := fs.New(fs.Config{
		Path:         workspace,
		PathFilter:   workspace,
		EventBufSize: 4096,
	})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	observer.Start()

	command := exec.Command(binPath, "--workspace", workspace, "--trajectory-out", trajectoryPath, "--file-only")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("simagent failed: %v\n%s", err, output)
	}

	time.Sleep(500 * time.Millisecond)
	if err := observer.Stop(); err != nil {
		t.Fatalf("observer.Stop: %v", err)
	}

	var groundTruth models.GroundTruth
	for event := range observer.Events() {
		groundTruth = append(groundTruth, event)
	}

	data, err := os.ReadFile(trajectoryPath)
	if err != nil {
		t.Fatalf("read trajectory: %v", err)
	}
	trajectory, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatalf("ParseTrajectory: %v", err)
	}

	config := matching.Config{Delta: 2 * time.Second}
	if verdict := verification.Verify(trajectory, groundTruth, config); !verdict.Faithful {
		t.Fatalf("honest content-hashed trajectory was not faithful: %#v", verdict)
	}

	target := filepath.Join(workspace, "file1.txt")
	mutated := false
	for index := range trajectory {
		entry := &trajectory[index]
		if entry.ActionType != models.FileClose || entry.Target != target || entry.OutputHash == nil {
			continue
		}
		bogusHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		entry.OutputHash = &bogusHash
		mutated = true
		break
	}
	if !mutated {
		t.Fatalf("no content-hashed FileClose entry for %s", target)
	}

	verdict := verification.Verify(trajectory, groundTruth, config)
	if verdict.Faithful {
		t.Fatal("expected NOT FAITHFUL verdict after substituting the content hash")
	}
	for _, pair := range verdict.Mismatched {
		if pair.Entry.ActionType == models.FileClose && pair.Entry.Target == target {
			return
		}
	}
	t.Fatalf("content substitution for %s was not classified as Mismatched: %#v", target, verdict)
}

// TestTier4_E2E_RacedRewriteDropsStaleHash is the supplementary, timing-driven
// check for Fix 5 (the deterministic proof is TestObserver_RacedCloseDropsHash
// in pkg/probe/fs). A tight write/close/rewrite loop keeps overwriting the file
// while post-close hash goroutines are still in flight. The assertion is safe
// regardless of scheduling: any OutputHash the observer does attach to a
// FileClose for this path must be the hash of the file's final content -- never
// a stale intermediate. Post-fix, a close whose file was written again reports
// no hash instead.
func TestTier4_E2E_RacedRewriteDropsStaleHash(t *testing.T) {
	skipUnprivileged(t)

	workspace := t.TempDir()
	observer, err := fs.New(fs.Config{
		Path:         workspace,
		PathFilter:   workspace,
		PIDFilter:    int32(os.Getpid()),
		EventBufSize: 4096,
	})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	observer.Start()
	time.Sleep(200 * time.Millisecond)

	target := filepath.Join(workspace, "raced.txt")
	const iterations = 40
	var finalContent []byte
	for i := 0; i < iterations; i++ {
		finalContent = []byte(fmt.Sprintf("content-revision-%03d\n", i))
		if err := os.WriteFile(target, finalContent, 0o644); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	time.Sleep(700 * time.Millisecond)
	if err := observer.Stop(); err != nil {
		t.Fatalf("observer.Stop: %v", err)
	}

	finalHash := content.SHA256Bytes(finalContent)

	var withHash, withoutHash int
	for e := range observer.Events() {
		if e.ActionType != models.FileClose || e.Target != target {
			continue
		}
		if e.OutputHash == nil {
			withoutHash++
			continue
		}
		withHash++
		if *e.OutputHash != finalHash {
			t.Errorf("FileClose carried a stale OutputHash %q; only the final-content hash %q may be attached",
				*e.OutputHash, finalHash)
		}
	}

	t.Logf("raced-rewrite: %d FileClose with the final-content hash, %d conservatively without",
		withHash, withoutHash)
	if withHash+withoutHash == 0 {
		t.Skip("no FileClose events observed for the target (kernel merged them); nothing to assert")
	}
}
