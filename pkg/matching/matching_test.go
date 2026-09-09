package matching

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

var baseTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func entry(offset time.Duration, action models.ActionType, target string) models.TrajectoryEntry {
	return models.TrajectoryEntry{
		Timestamp:  baseTime.Add(offset),
		ActionType: action,
		Target:     target,
	}
}

func event(offset time.Duration, action models.ActionType, target string) models.GroundTruthEvent {
	return models.GroundTruthEvent{
		Timestamp:  baseTime.Add(offset),
		ActionType: action,
		Target:     target,
	}
}

func TestMatchExact(t *testing.T) {
	cfg := DefaultConfig()
	te := entry(0, models.FileWrite, "/tmp/test.txt")
	ge := event(0, models.FileWrite, "/tmp/test.txt")

	if !Match(te, ge, cfg) {
		t.Error("identical entries should match")
	}
}

func TestMatchWithinDelta(t *testing.T) {
	cfg := DefaultConfig()
	te := entry(0, models.FileWrite, "/tmp/test.txt")
	ge := event(500*time.Millisecond, models.FileWrite, "/tmp/test.txt")

	if !Match(te, ge, cfg) {
		t.Error("entries within delta should match")
	}
}

func TestMatchAtDeltaBoundary(t *testing.T) {
	cfg := DefaultConfig()
	te := entry(0, models.FileWrite, "/tmp/test.txt")
	ge := event(DefaultDelta, models.FileWrite, "/tmp/test.txt")

	if !Match(te, ge, cfg) {
		t.Error("entries exactly at delta should match")
	}
}

func TestNoMatchOutsideDelta(t *testing.T) {
	cfg := DefaultConfig()
	te := entry(0, models.FileWrite, "/tmp/test.txt")
	ge := event(DefaultDelta+time.Millisecond, models.FileWrite, "/tmp/test.txt")

	if Match(te, ge, cfg) {
		t.Error("entries outside delta should not match")
	}
}

func TestNoMatchDifferentActionType(t *testing.T) {
	cfg := DefaultConfig()
	te := entry(0, models.FileWrite, "/tmp/test.txt")
	ge := event(0, models.FileRead, "/tmp/test.txt")

	if Match(te, ge, cfg) {
		t.Error("different action types should not match")
	}
}

func TestNoMatchDifferentTarget(t *testing.T) {
	cfg := DefaultConfig()
	te := entry(0, models.FileWrite, "/tmp/a.txt")
	ge := event(0, models.FileWrite, "/tmp/b.txt")

	if Match(te, ge, cfg) {
		t.Error("different targets should not match")
	}
}

func TestFilePathNormalization(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		name    string
		tTarget string
		gTarget string
		want    bool
	}{
		{
			name:    "dot segment removed",
			tTarget: "/workspace/./src/main.go",
			gTarget: "/workspace/src/main.go",
			want:    true,
		},
		{
			name:    "double dot resolved",
			tTarget: "/workspace/src/../src/main.go",
			gTarget: "/workspace/src/main.go",
			want:    true,
		},
		{
			name:    "trailing slash removed",
			tTarget: "/workspace/src/",
			gTarget: "/workspace/src",
			want:    true,
		},
		{
			name:    "genuinely different paths",
			tTarget: "/workspace/src/main.go",
			gTarget: "/workspace/src/lib.go",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			te := entry(0, models.FileWrite, tc.tTarget)
			ge := event(0, models.FileWrite, tc.gTarget)
			got := Match(te, ge, cfg)
			if got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.tTarget, tc.gTarget, got, tc.want)
			}
		})
	}
}

func TestProcessCommandNormalization(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		name    string
		tTarget string
		gTarget string
		want    bool
	}{
		{
			name:    "bare name vs absolute path",
			tTarget: "ls",
			gTarget: "/usr/bin/ls",
			want:    true,
		},
		{
			name:    "absolute path vs bare name",
			tTarget: "/bin/echo",
			gTarget: "echo",
			want:    true,
		},
		{
			name:    "identical bare names",
			tTarget: "git",
			gTarget: "git",
			want:    true,
		},
		{
			name:    "identical absolute paths",
			tTarget: "/usr/local/bin/python3",
			gTarget: "/usr/local/bin/python3",
			want:    true,
		},
		{
			name:    "path with dot segment vs bare name",
			tTarget: "/usr/bin/./ls",
			gTarget: "ls",
			want:    true,
		},
		{
			name:    "different bare names",
			tTarget: "ls",
			gTarget: "cat",
			want:    false,
		},
		{
			name:    "same basename different directory",
			tTarget: "/usr/bin/python",
			gTarget: "/opt/venv/bin/python",
			want:    false,
		},
		{
			name:    "bare name matches basename but not the other command",
			tTarget: "sh",
			gTarget: "/bin/bash",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			te := entry(0, models.ProcessExec, tc.tTarget)
			ge := event(0, models.ProcessExec, tc.gTarget)
			got := Match(te, ge, cfg)
			if got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.tTarget, tc.gTarget, got, tc.want)
			}
		})
	}
}

func TestProcessCommandWithArguments(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		name    string
		tTarget string
		gTarget string
		want    bool
	}{
		{
			// The common honest case post-fix: the agent reports the bare
			// command it invoked, the process probe reports the
			// kernel-resolved path, and both carry the same arguments
			// (which now contain a path themselves, the case the old
			// whole-string bare/path check got wrong).
			name:    "bare command with path argument vs resolved path",
			tTarget: "wc -l /tmp/workspace/file2.txt",
			gTarget: "/usr/bin/wc -l /tmp/workspace/file2.txt",
			want:    true,
		},
		{
			name:    "identical bare command and arguments",
			tTarget: "git commit -m fix",
			gTarget: "git commit -m fix",
			want:    true,
		},
		{
			name:    "same command, different arguments do not match",
			tTarget: "wc -l /tmp/workspace/file1.txt",
			gTarget: "/usr/bin/wc -l /tmp/workspace/file2.txt",
			want:    false,
		},
		{
			name:    "same arguments, different resolved command do not match",
			tTarget: "wc -l /tmp/workspace/file2.txt",
			gTarget: "/usr/bin/cat -l /tmp/workspace/file2.txt",
			want:    false,
		},
		{
			// The anti-spoofing case this change exists for: the agent
			// claims a fully-qualified, trusted binary, but the process
			// probe (once it reports the real execve path instead of
			// argv[0], see proc.commandLine) shows a different binary
			// actually ran. This must NOT be treated as a match just
			// because both sides share the same trailing arguments.
			name:    "claimed trusted path vs actually-resolved different path",
			tTarget: "/usr/bin/ls -la /tmp/workspace",
			gTarget: "/tmp/attacker-writable-dir/ls -la /tmp/workspace",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			te := entry(0, models.ProcessExec, tc.tTarget)
			ge := event(0, models.ProcessExec, tc.gTarget)
			got := Match(te, ge, cfg)
			if got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.tTarget, tc.gTarget, got, tc.want)
			}
		})
	}
}

func TestBareCommandRequiresTrustedDirectory(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		name    string
		tTarget string
		gTarget string
		want    bool
	}{
		{
			// The legitimate convenience case: bare claim, standard
			// system path. Still matches.
			name:    "bare name vs allowlisted /usr/bin path",
			tTarget: "ls",
			gTarget: "/usr/bin/ls",
			want:    true,
		},
		{
			// The actual fix. Pre-Fix-2 the basename match alone made this
			// true, letting a planted binary in an agent-writable directory
			// corroborate a bare-name claim for a common tool.
			name:    "bare name vs non-allowlisted, often-writable path",
			tTarget: "ls",
			gTarget: "/tmp/attacker-writable-dir/ls",
			want:    false,
		},
		{
			// Intentional stricter stance (spec Fix 2): a bare claim can no
			// longer vouch for a virtualenv/pyenv-style interpreter path,
			// only for system-standard locations. If this proves too strict
			// for real target agents, widen trustedBinDirs deliberately.
			name:    "bare name vs venv interpreter path",
			tTarget: "python",
			gTarget: "/opt/venv/bin/python",
			want:    false,
		},
		{
			name:    "bare name vs allowlisted /usr/local/bin path",
			tTarget: "node",
			gTarget: "/usr/local/bin/node",
			want:    true,
		},
		{
			// Direction is symmetric: the resolved path may be on either
			// side of the comparison.
			name:    "non-allowlisted path vs bare name (reversed order)",
			tTarget: "/home/agent/build/mytool",
			gTarget: "mytool",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			te := entry(0, models.ProcessExec, tc.tTarget)
			ge := event(0, models.ProcessExec, tc.gTarget)
			got := Match(te, ge, cfg)
			if got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.tTarget, tc.gTarget, got, tc.want)
			}
		})
	}
}

func TestProcessExitUsesCommandNormalization(t *testing.T) {
	cfg := DefaultConfig()
	te := entry(0, models.ProcessExit, "make")
	ge := event(0, models.ProcessExit, "/usr/bin/make")

	if !Match(te, ge, cfg) {
		t.Error("process_exit should normalize command paths like process_exec")
	}
}

func TestNoNormalizationForNonFileActions(t *testing.T) {
	cfg := DefaultConfig()
	te := entry(0, models.NetRequest, "https://api.example.com/v1/chat")
	ge := event(0, models.NetRequest, "https://api.example.com/v1/chat")

	if !Match(te, ge, cfg) {
		t.Error("identical net targets should match")
	}

	te2 := entry(0, models.NetRequest, "https://api.example.com/v1/chat")
	ge2 := event(0, models.NetRequest, "https://api.example.com/v1/Chat")

	if Match(te2, ge2, cfg) {
		t.Error("net targets are case-sensitive, should not match")
	}
}

func TestNegativeTimeDifference(t *testing.T) {
	cfg := DefaultConfig()
	te := entry(500*time.Millisecond, models.FileRead, "/tmp/test.txt")
	ge := event(0, models.FileRead, "/tmp/test.txt")

	if !Match(te, ge, cfg) {
		t.Error("probe before agent log should still match within delta")
	}
}

func TestCustomDelta(t *testing.T) {
	cfg := Config{Delta: 50 * time.Millisecond}
	te := entry(0, models.ProcessExec, "ls")
	ge := event(100*time.Millisecond, models.ProcessExec, "ls")

	if Match(te, ge, cfg) {
		t.Error("should not match with tight custom delta")
	}

	cfg2 := Config{Delta: 5 * time.Second}
	if !Match(te, ge, cfg2) {
		t.Error("should match with wide custom delta")
	}
}
