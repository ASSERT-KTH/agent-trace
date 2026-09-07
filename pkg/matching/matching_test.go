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
