package verification

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
)

var (
	baseTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	cfg      = matching.DefaultConfig()
)

func te(offsetMs int, action models.ActionType, target string, in, out *string) models.TrajectoryEntry {
	return models.TrajectoryEntry{
		Timestamp:  baseTime.Add(time.Duration(offsetMs) * time.Millisecond),
		ActionType: action,
		Target:     target,
		InputHash:  in,
		OutputHash: out,
	}
}

func ge(offsetMs int, action models.ActionType, target string, in, out *string) models.GroundTruthEvent {
	return models.GroundTruthEvent{
		Timestamp:  baseTime.Add(time.Duration(offsetMs) * time.Millisecond),
		ActionType: action,
		Target:     target,
		InputHash:  in,
		OutputHash: out,
	}
}

func sp(s string) *string { return &s }

// --- Unit tests for individual sets ---

func TestAllCorroborated(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/etc/hostname", nil, sp("h1")),
		te(1000, models.FileWrite, "/tmp/out.txt", sp("h2"), sp("h3")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileRead, "/etc/hostname", nil, sp("h1")),
		ge(1002, models.FileWrite, "/tmp/out.txt", sp("h2"), sp("h3")),
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("expected FAITHFUL")
	}
	if len(v.Corroborated) != 2 {
		t.Errorf("expected 2 corroborated, got %d", len(v.Corroborated))
	}
	if len(v.Unwitnessed) != 0 {
		t.Errorf("expected 0 unwitnessed, got %d", len(v.Unwitnessed))
	}
	if len(v.Unrecorded) != 0 {
		t.Errorf("expected 0 unrecorded, got %d", len(v.Unrecorded))
	}
	if len(v.Mismatched) != 0 {
		t.Errorf("expected 0 mismatched, got %d", len(v.Mismatched))
	}
}

func TestUnwitnessed(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/etc/hostname", nil, sp("h1")),
		te(1000, models.FileRead, "/etc/shadow", nil, sp("h_secret")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileRead, "/etc/hostname", nil, sp("h1")),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("expected NOT FAITHFUL")
	}
	if len(v.Unwitnessed) != 1 {
		t.Fatalf("expected 1 unwitnessed, got %d", len(v.Unwitnessed))
	}
	if v.Unwitnessed[0].Target != "/etc/shadow" {
		t.Errorf("wrong unwitnessed target: %s", v.Unwitnessed[0].Target)
	}
}

func TestUnrecorded(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/etc/hostname", nil, sp("h1")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileRead, "/etc/hostname", nil, sp("h1")),
		ge(500, models.NetRequest, "https://evil.com/exfil", sp("stolen"), sp("ack")),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("expected NOT FAITHFUL")
	}
	if len(v.Unrecorded) != 1 {
		t.Fatalf("expected 1 unrecorded, got %d", len(v.Unrecorded))
	}
	if v.Unrecorded[0].Target != "https://evil.com/exfil" {
		t.Errorf("wrong unrecorded target: %s", v.Unrecorded[0].Target)
	}
}

func TestMismatched(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/etc/hostname", nil, sp("benign_hash")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileRead, "/etc/hostname", nil, sp("real_hash")),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("expected NOT FAITHFUL")
	}
	if len(v.Mismatched) != 1 {
		t.Fatalf("expected 1 mismatched, got %d", len(v.Mismatched))
	}
	if *v.Mismatched[0].Entry.OutputHash != "benign_hash" {
		t.Errorf("wrong entry hash: %s", *v.Mismatched[0].Entry.OutputHash)
	}
	if *v.Mismatched[0].Event.OutputHash != "real_hash" {
		t.Errorf("wrong event hash: %s", *v.Mismatched[0].Event.OutputHash)
	}
}

func TestHashNilTreatedAsAgreement(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/etc/hostname", nil, sp("h1")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileRead, "/etc/hostname", nil, nil),
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("nil ground-truth hash should not cause mismatch")
	}
	if len(v.Corroborated) != 1 {
		t.Errorf("expected 1 corroborated, got %d", len(v.Corroborated))
	}
}

func TestEmptyTrajectoryAndGroundTruth(t *testing.T) {
	v := Verify(nil, nil, cfg)

	if !v.Faithful {
		t.Error("empty T and G should be FAITHFUL")
	}
}

func TestEmptyTrajectoryWithGroundTruth(t *testing.T) {
	ground := models.GroundTruth{
		ge(0, models.FileRead, "/etc/hostname", nil, sp("h1")),
	}

	v := Verify(nil, ground, cfg)

	if v.Faithful {
		t.Error("empty T with non-empty G should be NOT FAITHFUL (omission)")
	}
	if len(v.Unrecorded) != 1 {
		t.Errorf("expected 1 unrecorded, got %d", len(v.Unrecorded))
	}
}

func TestGreedyClosestTimestamp(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileWrite, "/tmp/f.txt", nil, sp("h1")),
		te(100, models.FileWrite, "/tmp/f.txt", nil, sp("h2")),
	}
	ground := models.GroundTruth{
		ge(3, models.FileWrite, "/tmp/f.txt", nil, sp("h1")),
		ge(98, models.FileWrite, "/tmp/f.txt", nil, sp("h2")),
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("expected FAITHFUL with correct closest-timestamp pairing")
	}
	if len(v.Corroborated) != 2 {
		t.Errorf("expected 2 corroborated, got %d", len(v.Corroborated))
	}
}

// --- E2E attack scenarios (design properties P1, P2, P3, P5) ---

// Honest trajectory: 5 actions, all present and matching in ground truth.
func honestTrajectory() (models.Trajectory, models.GroundTruth) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/workspace/config.yaml", nil, sp("cfg_h")),
		te(1000, models.ProcessExec, "python main.py", sp("args_h"), nil),
		te(2000, models.NetRequest, "https://api.openai.com/v1/chat", sp("req_h"), sp("resp_h")),
		te(3000, models.FileWrite, "/workspace/output.txt", sp("before_h"), sp("after_h")),
		te(4000, models.ProcessExec, "git commit -m fix", sp("git_args"), nil),
	}
	ground := models.GroundTruth{
		ge(2, models.FileRead, "/workspace/config.yaml", nil, sp("cfg_h")),
		ge(1003, models.ProcessExec, "python main.py", sp("args_h"), nil),
		ge(2010, models.NetRequest, "https://api.openai.com/v1/chat", sp("req_h"), sp("resp_h")),
		ge(3001, models.FileWrite, "/workspace/output.txt", sp("before_h"), sp("after_h")),
		ge(4005, models.ProcessExec, "git commit -m fix", sp("git_args"), nil),
	}
	return traj, ground
}

func TestE2E_HonestTrajectory(t *testing.T) {
	traj, ground := honestTrajectory()
	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("honest trajectory should be FAITHFUL")
	}
	if len(v.Corroborated) != 5 {
		t.Errorf("expected 5 corroborated, got %d", len(v.Corroborated))
	}
}

// T1 attack: agent omits the API call from the trajectory (hides exfiltration).
func TestE2E_T1_Omission(t *testing.T) {
	traj, ground := honestTrajectory()

	// Drop the network request (index 2) from the trajectory.
	traj = append(traj[:2], traj[3:]...)

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("omission attack should be NOT FAITHFUL")
	}
	if len(v.Unrecorded) != 1 {
		t.Fatalf("expected 1 unrecorded, got %d", len(v.Unrecorded))
	}
	if v.Unrecorded[0].Target != "https://api.openai.com/v1/chat" {
		t.Errorf("wrong unrecorded target: %s", v.Unrecorded[0].Target)
	}
	if len(v.Corroborated) != 4 {
		t.Errorf("expected 4 corroborated, got %d", len(v.Corroborated))
	}
}

// T2 attack: agent fabricates a benign file read that never happened.
func TestE2E_T2_Fabrication(t *testing.T) {
	traj, ground := honestTrajectory()

	// Insert a fake entry: agent claims it read a harmless README.
	fake := te(2500, models.FileRead, "/workspace/README.md", nil, sp("readme_h"))
	traj = append(traj[:3], append(models.Trajectory{fake}, traj[3:]...)...)

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("fabrication attack should be NOT FAITHFUL")
	}
	if len(v.Unwitnessed) != 1 {
		t.Fatalf("expected 1 unwitnessed, got %d", len(v.Unwitnessed))
	}
	if v.Unwitnessed[0].Target != "/workspace/README.md" {
		t.Errorf("wrong unwitnessed target: %s", v.Unwitnessed[0].Target)
	}
	if len(v.Corroborated) != 5 {
		t.Errorf("expected 5 corroborated, got %d", len(v.Corroborated))
	}
}

// T3 attack: agent claims it read /etc/hostname but actually read /etc/shadow.
// The trajectory entry matches the ground-truth event on (type, target, time)
// but the output hash differs.
func TestE2E_T3_Substitution(t *testing.T) {
	traj, ground := honestTrajectory()

	// Replace the file read's output hash with a different value.
	// The agent claims it got "innocent_content" but the probe captured "cfg_h".
	traj[0].OutputHash = sp("innocent_content")

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("substitution attack should be NOT FAITHFUL")
	}
	if len(v.Mismatched) != 1 {
		t.Fatalf("expected 1 mismatched, got %d", len(v.Mismatched))
	}
	if v.Mismatched[0].Entry.Target != "/workspace/config.yaml" {
		t.Errorf("wrong mismatched target: %s", v.Mismatched[0].Entry.Target)
	}
	if len(v.Corroborated) != 4 {
		t.Errorf("expected 4 corroborated, got %d", len(v.Corroborated))
	}
}

// Combined attack: omission + fabrication + substitution in the same trajectory.
func TestE2E_CombinedAttack(t *testing.T) {
	traj, ground := honestTrajectory()

	// T1: drop the network request (index 2)
	traj = append(traj[:2], traj[3:]...)

	// T2: insert a fabricated entry
	fake := te(2500, models.FileRead, "/workspace/README.md", nil, sp("readme_h"))
	traj = append(traj[:2], append(models.Trajectory{fake}, traj[2:]...)...)

	// T3: substitute the file write hash (now at index 3 after mutations)
	traj[3].OutputHash = sp("tampered_hash")

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("combined attack should be NOT FAITHFUL")
	}
	if len(v.Unrecorded) != 1 {
		t.Errorf("expected 1 unrecorded (omitted net request), got %d", len(v.Unrecorded))
	}
	if len(v.Unwitnessed) != 1 {
		t.Errorf("expected 1 unwitnessed (fabricated README read), got %d", len(v.Unwitnessed))
	}
	if len(v.Mismatched) != 1 {
		t.Errorf("expected 1 mismatched (substituted file write), got %d", len(v.Mismatched))
	}
}
