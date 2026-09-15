package e2e

import (
	"encoding/hex"
	"crypto/sha256"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
	probenet "github.com/agent-trace/agent-trace/pkg/probe/net"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const tier5FetchURL = "https://example.com/api"
const tier5FetchBody = "content-body"

func findLibSSL(t *testing.T) string {
	t.Helper()
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl not available")
	}
	out, err := exec.Command("ldd", curlPath).CombinedOutput()
	if err != nil {
		t.Skipf("ldd %s: %v", curlPath, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "libssl.so") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "=>" && i+1 < len(fields) {
				if _, err := os.Stat(fields[i+1]); err == nil {
					return fields[i+1]
				}
			}
		}
	}
	t.Skip("could not resolve libssl.so path from ldd output")
	return ""
}

func runTier5MockAgent(t *testing.T, attack string) (models.Trajectory, models.GroundTruth) {
	t.Helper()

	libssl := findLibSSL(t)

	netObs, err := probenet.New(probenet.Config{
		EventBufSize: 256,
		ExePath:      libssl,
	})
	if err != nil {
		t.Fatalf("probenet.New: %v", err)
	}

	// We use 'exec curl' so that curl inherits the exact PID of this shell script.
	// The sleep ensures the net probe has time to attach its uprobe before curl starts.
	cmd := exec.Command("sh", "-c", "sleep 0.5 && exec curl -s -o /dev/null -X POST -d "+tier5FetchBody+" "+tier5FetchURL)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start shell: %v", err)
	}
	
	if err := netObs.TrackPID(int32(cmd.Process.Pid)); err != nil {
		t.Fatalf("netObs.TrackPID: %v", err)
	}
	go netObs.Start()

	if err := cmd.Wait(); err != nil {
		t.Fatalf("curl script failed: %v", err)
	}

	time.Sleep(3 * time.Second)

	if err := netObs.Stop(); err != nil {
		t.Fatalf("netObs.Stop: %v", err)
	}

	var g models.GroundTruth
	// We only care about Net events for Tier 5 assertions
	for e := range netObs.Events() {
		g = append(g, e)
	}

	// Build the trajectory manually
	var tr models.Trajectory
	target := models.CanonicalNetTarget("POST", "example.com", 443, "/api", "")
	h := sha256.Sum256([]byte(tier5FetchBody))
	hashStr := "sha256:" + hex.EncodeToString(h[:])

	if attack == "substitution" {
		hashStr = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}
	
	entry := models.TrajectoryEntry{
		Timestamp:   time.Now().Add(-1 * time.Second), // Fake timestamp close to reality
		ActionType:  models.NetRequest,
		Target:      target,
		RequestHash: &hashStr,
	}
	tr = append(tr, entry)

	tr = append(tr, models.TrajectoryEntry{
		Timestamp:  time.Now().Add(-2 * time.Second),
		ActionType: models.NetConnect,
		Target:     "example.com",
	})

	return tr, g
}

func TestTier5_E2E_NetRequest_Content_Faithful(t *testing.T) {
	skipUnprivileged(t)
	tr, g := runTier5MockAgent(t, "")
	
	config := matching.Config{Delta: 10 * time.Second}
	verdict := verification.Verify(tr, g, config)
	if !verdict.Faithful {
		t.Errorf("expected FAITHFUL verdict")
		t.Logf("Unwitnessed: %d", len(verdict.Unwitnessed))
		for _, e := range verdict.Unwitnessed {
			t.Logf("  unwitnessed: %s %s", e.ActionType, e.Target)
		}
		t.Logf("Unrecorded: %d", len(verdict.Unrecorded))
		for _, e := range verdict.Unrecorded {
			t.Logf("  unrecorded: %s %s", e.ActionType, e.Target)
		}
		t.Logf("Mismatched: %d", len(verdict.Mismatched))
		for _, m := range verdict.Mismatched {
			t.Logf("  mismatched: %s %s", m.Entry.ActionType, m.Entry.Target)
			t.Logf("    entry hash: %v", m.Entry.RequestHash)
			t.Logf("    event hash: %v", m.Event.RequestHash)
		}
		t.Fatalf("verdict was not faithful")
	}

	foundReq := false
	for _, pair := range verdict.Corroborated {
		if pair.Entry.ActionType == models.NetRequest {
			foundReq = true
			if pair.Entry.RequestHash == nil {
				t.Error("expected RequestHash in Corroborated NetRequest entry")
			}
			if pair.Event.RequestHash == nil {
				t.Error("expected RequestHash in Corroborated NetRequest event")
			}
		}
	}
	if !foundReq {
		t.Errorf("expected to corroborate a NetRequest action. Ground truth has %d events, Trajectory has %d entries.", len(g), len(tr))
		for _, e := range g {
			if e.ActionType == models.NetRequest {
				t.Logf("Found NetRequest in ground truth: %s (hash: %v)", e.Target, e.RequestHash)
			}
		}
		for _, e := range tr {
			if e.ActionType == models.NetRequest {
				t.Logf("Found NetRequest in trajectory: %s (hash: %v)", e.Target, e.RequestHash)
			}
		}
		t.FailNow()
	}
}

func TestTier5_E2E_NetRequest_Content_Substitution(t *testing.T) {
	skipUnprivileged(t)
	tr, g := runTier5MockAgent(t, "substitution")

	config := matching.Config{Delta: 10 * time.Second}
	verdict := verification.Verify(tr, g, config)
	if verdict.Faithful {
		t.Fatal("expected NOT FAITHFUL verdict after substituting the RequestHash")
	}

	foundMismatch := false
	for _, pair := range verdict.Mismatched {
		if pair.Entry.ActionType == models.NetRequest {
			foundMismatch = true
			t.Logf("Successfully caught Mismatched NetRequest for %s: entry hash %v, event hash %v", 
				pair.Entry.Target, pair.Entry.RequestHash, pair.Event.RequestHash)
		}
	}
	if !foundMismatch {
		t.Errorf("expected Mismatched NetRequest")
		for _, e := range verdict.Unwitnessed {
			t.Logf("  unwitnessed: %s %s", e.ActionType, e.Target)
		}
		for _, e := range verdict.Unrecorded {
			t.Logf("  unrecorded: %s %s", e.ActionType, e.Target)
		}
		t.FailNow()
	}
}
