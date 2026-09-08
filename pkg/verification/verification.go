package verification

import (
	"math"
	"time"

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
)

type MatchedPair struct {
	Entry models.TrajectoryEntry
	Event models.GroundTruthEvent
}

type Verdict struct {
	Faithful    bool
	Corroborated []MatchedPair
	Unwitnessed  []models.TrajectoryEntry
	Unrecorded   []models.GroundTruthEvent
	Mismatched   []MatchedPair
}

// hashesAgree compares two optional hashes. If either side is nil (content
// not captured), we cannot disprove the claim, so we treat it as agreement.
// A mismatch requires both sides to have a non-nil, different value.
func hashesAgree(a, b *string) bool {
	if a == nil || b == nil {
		return true
	}
	return *a == *b
}

// exitCodesAgree compares two optional process exit codes with the same
// nil-agreement rule as hashesAgree: if either side didn't report one, we
// cannot disprove the claim. A mismatch requires both sides to report a
// code and for those codes to differ -- e.g. the agent claims a command
// succeeded while the ground truth shows it exited nonzero.
func exitCodesAgree(a, b *int32) bool {
	if a == nil || b == nil {
		return true
	}
	return *a == *b
}

// Verify compares a self-reported trajectory T against an independently
// observed ground truth G and classifies every entry/event into one of
// four sets: Corroborated, Unwitnessed, Unrecorded, or Mismatched.
//
// Algorithm: for each trajectory entry, find the closest unmatched
// ground-truth event with matching (action_type, target) within delta.
// Greedy closest-timestamp, one-to-one.
func Verify(t models.Trajectory, g models.GroundTruth, cfg matching.Config) Verdict {
	matched := make([]bool, len(g))
	var v Verdict

	for _, entry := range t {
		bestIdx := -1
		bestDiff := time.Duration(math.MaxInt64)

		for j, event := range g {
			if matched[j] {
				continue
			}
			if !matching.Match(entry, event, cfg) {
				continue
			}
			diff := entry.Timestamp.Sub(event.Timestamp)
			if diff < 0 {
				diff = -diff
			}
			if diff < bestDiff {
				bestDiff = diff
				bestIdx = j
			}
		}

		if bestIdx == -1 {
			v.Unwitnessed = append(v.Unwitnessed, entry)
			continue
		}

		matched[bestIdx] = true
		pair := MatchedPair{Entry: entry, Event: g[bestIdx]}

		inputOK := hashesAgree(entry.InputHash, g[bestIdx].InputHash)
		outputOK := hashesAgree(entry.OutputHash, g[bestIdx].OutputHash)
		exitOK := exitCodesAgree(entry.ExitCode, g[bestIdx].ExitCode)

		if inputOK && outputOK && exitOK {
			v.Corroborated = append(v.Corroborated, pair)
		} else {
			v.Mismatched = append(v.Mismatched, pair)
		}
	}

	for j, event := range g {
		if !matched[j] {
			v.Unrecorded = append(v.Unrecorded, event)
		}
	}

	v.Faithful = len(v.Unwitnessed) == 0 &&
		len(v.Unrecorded) == 0 &&
		len(v.Mismatched) == 0

	return v
}
