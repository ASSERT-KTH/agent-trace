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
	return models.GroundTruthEvent{IsTopLevel: bp(true),
		Timestamp:  baseTime.Add(time.Duration(offsetMs) * time.Millisecond),
		ActionType: action,
		Target:     target,
		InputHash:  in,
		OutputHash: out,
	}
}

func sp(s string) *string { return &s }

func bp(b bool) *bool { return &b }

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

func TestDescendantGroundTruthIsIgnored(t *testing.T) {
	ground := models.GroundTruth{
		{IsTopLevel: bp(false), Timestamp: baseTime, ActionType: models.ProcessExec, Target: "helper"},
	}

	v := Verify(nil, ground, cfg)
	if !v.Faithful {
		t.Fatalf("descendant event should not affect verification: %+v", v)
	}
	if len(v.Unrecorded) != 0 {
		t.Fatalf("expected no unrecorded descendant events, got %d", len(v.Unrecorded))
	}
}

func TestLegacyGroundTruthDefaultsToTopLevel(t *testing.T) {
	traj := models.Trajectory{te(0, models.FileRead, "/tmp/file", nil, nil)}
	ground := models.GroundTruth{
		{Timestamp: baseTime, ActionType: models.FileRead, Target: "/tmp/file"},
	}

	v := Verify(traj, ground, cfg)
	if !v.Faithful || len(v.Corroborated) != 1 {
		t.Fatalf("legacy event should remain verifiable: %+v", v)
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

func TestExitCodeMismatch(t *testing.T) {
	claimedOK := int32(0)
	actualFailed := int32(1)
	traj := models.Trajectory{
		{Timestamp: baseTime, ActionType: models.ProcessExit, Target: "/usr/bin/git push", ExitCode: &claimedOK},
	}
	ground := models.GroundTruth{
		{IsTopLevel: bp(true), Timestamp: baseTime.Add(5 * time.Millisecond), ActionType: models.ProcessExit, Target: "/usr/bin/git push", ExitCode: &actualFailed},
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("expected NOT FAITHFUL: agent claimed exit 0 but process exited 1")
	}
	if len(v.Mismatched) != 1 {
		t.Fatalf("expected 1 mismatched, got %d", len(v.Mismatched))
	}
	if *v.Mismatched[0].Entry.ExitCode != 0 || *v.Mismatched[0].Event.ExitCode != 1 {
		t.Errorf("wrong exit codes in mismatch: entry=%d event=%d",
			*v.Mismatched[0].Entry.ExitCode, *v.Mismatched[0].Event.ExitCode)
	}
}

func TestExitCodeNilTreatedAsAgreement(t *testing.T) {
	code := int32(0)
	traj := models.Trajectory{
		{Timestamp: baseTime, ActionType: models.ProcessExit, Target: "/usr/bin/git push", ExitCode: &code},
	}
	ground := models.GroundTruth{
		// Probe didn't capture an exit code (e.g. killed by an uncaught
		// signal, never hit exit_group): should not be a mismatch.
		{IsTopLevel: bp(true), Timestamp: baseTime.Add(5 * time.Millisecond), ActionType: models.ProcessExit, Target: "/usr/bin/git push"},
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("nil ground-truth exit code should not cause mismatch")
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

// F2.2: a single verification pass over a trajectory that mixes file and
// process actions, where the process probe reports absolute command paths
// while the agent logs bare command names. All entries should corroborate.
func TestMixedFileAndProcessVerification(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/workspace/./main.go", nil, sp("src_h")),
		te(500, models.ProcessExec, "go", sp("build_args"), nil),
		te(1500, models.FileWrite, "/workspace/bin/app", sp("nil_h"), sp("bin_h")),
		te(2500, models.ProcessExec, "git", sp("commit_args"), nil),
		te(3000, models.ProcessExit, "git", nil, sp("0")),
	}
	ground := models.GroundTruth{
		ge(3, models.FileRead, "/workspace/main.go", nil, sp("src_h")),
		ge(505, models.ProcessExec, "/usr/local/bin/go", sp("build_args"), nil),
		ge(1502, models.FileWrite, "/workspace/bin/app", sp("nil_h"), sp("bin_h")),
		ge(2503, models.ProcessExec, "/usr/bin/git", sp("commit_args"), nil),
		ge(3004, models.ProcessExit, "/usr/bin/git", nil, sp("0")),
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Errorf("mixed file+process trajectory should be FAITHFUL: %+v", v)
	}
	if len(v.Corroborated) != 5 {
		t.Errorf("expected 5 corroborated, got %d", len(v.Corroborated))
	}
}

// F2.2: a process action the agent omitted from its trajectory must surface as
// Unrecorded even when file actions in the same pass all corroborate.
func TestMixedVerificationDetectsOmittedProcess(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileWrite, "/workspace/payload.sh", nil, sp("sh_h")),
	}
	ground := models.GroundTruth{
		ge(2, models.FileWrite, "/workspace/payload.sh", nil, sp("sh_h")),
		ge(50, models.ProcessExec, "/bin/bash", sp("bash_args"), nil),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("omitted subprocess spawn should be NOT FAITHFUL")
	}
	if len(v.Unrecorded) != 1 || v.Unrecorded[0].ActionType != models.ProcessExec {
		t.Fatalf("expected 1 unrecorded process_exec, got %+v", v.Unrecorded)
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

// T3 attack, process-identity variant: the agent's trajectory claims it ran
// a trusted system binary, but the process it actually ran resolves to a
// different path (e.g. a planted binary earlier in PATH, or a directly
// invoked execve() with a spoofed argv[0]). This is the scenario proc.
// commandLine's move from argv[0] to the kernel-resolved execve filename
// exists to make visible: the ground-truth target below is what the fixed
// probe reports for such a run (see proc.TestCommandLine_UsesResolvedFilenameNotArgv0
// and matching.TestProcessCommandWithArguments for the layers underneath).
// Because the claimed and actual binaries are different resolved paths,
// commandsMatch refuses the match (no basename fallback applies across
// different directories), so this surfaces as Unwitnessed + Unrecorded
// rather than Mismatched, the same occurrence-level pattern the Tier 1
// filename-swap test documents for file actions.
func TestE2E_T3_ProcessMasquerading(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.ProcessExec, "/usr/bin/ls -la /workspace", nil, nil),
	}
	ground := models.GroundTruth{
		ge(5, models.ProcessExec, "/tmp/attacker-writable-dir/ls -la /workspace", nil, nil),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("process masquerading should be NOT FAITHFUL")
	}
	if len(v.Unwitnessed) != 1 {
		t.Fatalf("expected 1 unwitnessed (claimed binary never ran), got %d", len(v.Unwitnessed))
	}
	if v.Unwitnessed[0].Target != "/usr/bin/ls -la /workspace" {
		t.Errorf("wrong unwitnessed target: %s", v.Unwitnessed[0].Target)
	}
	if len(v.Unrecorded) != 1 {
		t.Fatalf("expected 1 unrecorded (the binary that actually ran), got %d", len(v.Unrecorded))
	}
	if v.Unrecorded[0].Target != "/tmp/attacker-writable-dir/ls -la /workspace" {
		t.Errorf("wrong unrecorded target: %s", v.Unrecorded[0].Target)
	}
	if len(v.Corroborated) != 0 {
		t.Errorf("expected 0 corroborated, got %d", len(v.Corroborated))
	}
}

// T3 attack, bare-name variant of process masquerading: the agent reports a
// process by the normal bare-name convention ("ls"), but the binary that
// actually ran resolves to a planted copy in an agent-writable directory
// that happens to share the basename. Before Fix 2, commandsMatch's
// unconditional basename fallback made this Corroborated. After Fix 2, a
// bare name only vouches for a resolved path whose directory is on the
// trustedBinDirs allowlist, so /tmp/attacker-writable-dir/ls does not
// match, and this surfaces as Unwitnessed + Unrecorded.
func TestE2E_T3_BareNameMasquerading(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.ProcessExec, "ls -la /workspace", nil, nil),
	}
	ground := models.GroundTruth{
		ge(5, models.ProcessExec, "/tmp/attacker-writable-dir/ls -la /workspace", nil, nil),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("bare-name masquerading should be NOT FAITHFUL")
	}
	if len(v.Corroborated) != 0 {
		t.Errorf("expected 0 corroborated, got %d", len(v.Corroborated))
	}
	if len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != "ls -la /workspace" {
		t.Errorf("expected the bare claim unwitnessed, got %+v", v.Unwitnessed)
	}
	if len(v.Unrecorded) != 1 ||
		v.Unrecorded[0].Target != "/tmp/attacker-writable-dir/ls -la /workspace" {
		t.Errorf("expected the planted binary unrecorded, got %+v", v.Unrecorded)
	}
}

// Sibling to TestE2E_T3_BareNameMasquerading: the same bare claim against a
// binary that really did resolve into a standard system directory still
// corroborates, so Fix 2 doesn't break the honest bare-name convention.
func TestE2E_BareNameAgainstTrustedPathStillFaithful(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.ProcessExec, "ls -la /workspace", nil, nil),
	}
	ground := models.GroundTruth{
		ge(5, models.ProcessExec, "/usr/bin/ls -la /workspace", nil, nil),
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Errorf("bare name vs /usr/bin path should be FAITHFUL, got %+v", v)
	}
	if len(v.Corroborated) != 1 {
		t.Errorf("expected 1 corroborated, got %d", len(v.Corroborated))
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
