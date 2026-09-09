package matching

import (
	"path/filepath"
	"strings"
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

func isFileAction(actionType models.ActionType) bool {
	switch actionType {
	case models.FileOpen, models.FileRead, models.FileWrite,
		models.FileClose, models.FileRename, models.FileDelete:
		return true
	default:
		return false
	}
}

// targetsMatch reports whether a trajectory target and a ground-truth target
// refer to the same resource, applying per-action-type normalization.
func targetsMatch(actionType models.ActionType, tTarget, gTarget string) bool {
	switch {
	case isFileAction(actionType):
		normT := filepath.Clean(tTarget)
		normG := filepath.Clean(gTarget)
		// A directory-level ground-truth event (fanotify reports the parent
		// directory for some operations) corroborates a file operation that
		// happened inside it.
		return normT == normG || normG == filepath.Dir(normT)
	case actionType == models.ProcessExec || actionType == models.ProcessExit:
		return commandsMatch(tTarget, gTarget)
	default:
		return tTarget == gTarget
	}
}

// commandsMatch compares two "command arg1 arg2 ..." references for a process
// action. The command token (the part before the first space) is compared
// separately from the argument tokens that follow it, because the command
// token is the only part that gets bare-name/path normalization: when one
// side's command token is a bare name (no path separator) and the other's is
// a path, they match if the path's final element equals the bare name. This
// absorbs the common case where the agent logs "wc -l file.txt" while an
// execve probe reports "/usr/bin/wc -l file.txt" (see proc.commandLine,
// which builds the ground-truth command token from the kernel-resolved
// execve path rather than argv[0], precisely so this comparison is checking
// the real binary and not a caller-supplied label for it). Argument tokens
// always require an exact match; only the command token gets path leniency,
// otherwise a fabricated argument could hide behind normalization meant for
// binary names. The comparison is deterministic: it never consults the
// verifier host's PATH or the filesystem.
func commandsMatch(a, b string) bool {
	if a == b {
		return true
	}

	aCmd, aArgs := splitCommandLine(a)
	bCmd, bArgs := splitCommandLine(b)

	if aArgs != bArgs {
		return false
	}
	return commandTokensMatch(aCmd, bCmd)
}

// splitCommandLine separates the leading command token from the rest of the
// argument string.
func splitCommandLine(s string) (cmd, args string) {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// commandTokensMatch compares two single command tokens (no arguments),
// applying bare-name/path leniency as described in commandsMatch.
func commandTokensMatch(a, b string) bool {
	if a == b {
		return true
	}

	aBare := !strings.ContainsRune(a, filepath.Separator)
	bBare := !strings.ContainsRune(b, filepath.Separator)

	switch {
	case aBare == bBare:
		// Both bare names (and unequal, handled above) never match. Two
		// distinct paths match only if they clean to the same string; we do
		// not resolve symlinks, which would be non-deterministic.
		if aBare {
			return false
		}
		return filepath.Clean(a) == filepath.Clean(b)
	case aBare:
		return a == filepath.Base(filepath.Clean(b))
	default:
		return b == filepath.Base(filepath.Clean(a))
	}
}

// Match reports whether a trajectory entry and a ground-truth event refer to
// the same action: same action_type, same normalized target, and timestamps
// within delta of each other.
func Match(t models.TrajectoryEntry, g models.GroundTruthEvent, cfg Config) bool {
	if t.ActionType != g.ActionType {
		return false
	}

	if !targetsMatch(t.ActionType, t.Target, g.Target) {
		return false
	}

	diff := t.Timestamp.Sub(g.Timestamp)
	if diff < 0 {
		diff = -diff
	}
	return diff <= cfg.Delta
}
