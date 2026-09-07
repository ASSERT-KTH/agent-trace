package matching

import (
	"path/filepath"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

const DefaultDelta = 1 * time.Second

type Config struct {
	Delta time.Duration
}

func DefaultConfig() Config {
	return Config{Delta: DefaultDelta}
}

func normalizeTarget(actionType models.ActionType, target string) string {
	switch actionType {
	case models.FileOpen, models.FileRead, models.FileWrite,
		models.FileClose, models.FileRename, models.FileDelete:
		return filepath.Clean(target)
	default:
		return target
	}
}

// Match reports whether a trajectory entry and a ground-truth event refer to
// the same action: same action_type, same normalized target, and timestamps
// within delta of each other.
func Match(t models.TrajectoryEntry, g models.GroundTruthEvent, cfg Config) bool {
	if t.ActionType != g.ActionType {
		return false
	}

	normT := normalizeTarget(t.ActionType, t.Target)
	normG := normalizeTarget(g.ActionType, g.Target)
	if normT != normG && normG != filepath.Dir(normT) {
		return false
	}

	diff := t.Timestamp.Sub(g.Timestamp)
	if diff < 0 {
		diff = -diff
	}
	return diff <= cfg.Delta
}
