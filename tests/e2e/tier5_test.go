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
	probenet "github.com/agent-trace/agent-trace/pkg/probe/net"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const tier5FetchURL = "https://example.com/api"
const tier5FetchBody = "content-body"

func runTier5Agent(t *testing.T, attack string) (models.Trajectory, models.GroundTruth) {
	t.Helper()

	binPath := buildSimAgent(t)
	workspace := t.TempDir()
	trajectoryPath := filepath.Join(t.TempDir(), "trajectory.json")

	netObs, err := probenet.New(probenet.Config{
		EventBufSize: 256,
		ExePath:      binPath,
	})
	if err != nil {
		t.Fatalf("probenet.New: %v", err)
	}

	args := []string{
		"--workspace", workspace,
		"--trajectory-out", trajectoryPath,
		"--fetch-url", tier5FetchURL,
		"--fetch-method", "POST",
		"--fetch-body", tier5FetchBody,
		"--emit-net-request",
		"--file-only", // skip proc probe overhead, we don't need it
	}
	if attack != "" {
		args = append(args, "--attack", attack)
	}

	cmd := exec.Command(binPath, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start simagent: %v", err)
	}

	if err := netObs.TrackPID(int32(cmd.Process.Pid)); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("netObs.TrackPID: %v", err)
	}
	go netObs.Start()

	if err := cmd.Wait(); err != nil {
		t.Fatalf("simagent failed: %v\n%s", err, output.String())
	}

	time.Sleep(3 * time.Second)

	if err := netObs.Stop(); err != nil {
		t.Fatalf("netObs.Stop: %v", err)
	}

	var g models.GroundTruth
	for e := range netObs.Events() {
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

func TestTier5_E2E_NetRequest_Content_Faithful(t *testing.T) {
	skipUnprivileged(t)
	tr, g := runTier5Agent(t, "")
	
	config := matching.Config{Delta: 10 * time.Second}
	verdict := verification.Verify(tr, g, config)
	if !verdict.Faithful {
		t.Fatalf("expected FAITHFUL verdict, got: %#v", verdict)
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
		t.Error("expected to corroborate a NetRequest action")
	}
}

func TestTier5_E2E_NetRequest_Content_Substitution(t *testing.T) {
	skipUnprivileged(t)
	// simagent doesn't have a "net-substitution" attack yet, we'll manually manipulate the trajectory.
	tr, g := runTier5Agent(t, "")
	
	for i := range tr {
		if tr[i].ActionType == models.NetRequest {
			bogus := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			tr[i].RequestHash = &bogus
		}
	}

	config := matching.Config{Delta: 10 * time.Second}
	verdict := verification.Verify(tr, g, config)
	if verdict.Faithful {
		t.Fatal("expected NOT FAITHFUL verdict after substituting the RequestHash")
	}

	foundMismatch := false
	for _, pair := range verdict.Mismatched {
		if pair.Entry.ActionType == models.NetRequest {
			foundMismatch = true
		}
	}
	if !foundMismatch {
		t.Errorf("expected Mismatched NetRequest, got %#v", verdict)
	}
}
