package models

import (
	"encoding/json"
	"errors"
	"time"
)

// TrajectoryEntry is a self-reported action from the agent's trajectory log.
type TrajectoryEntry struct {
	Timestamp  time.Time   `json:"timestamp"`
	ActionType ActionType  `json:"action_type"`
	Target     string      `json:"target"`
	InputHash  *string     `json:"input_hash,omitempty"`
	OutputHash *string     `json:"output_hash,omitempty"`
}

// GroundTruthEvent is an independently observed action from the host-level probes.
type GroundTruthEvent struct {
	Timestamp  time.Time   `json:"timestamp"`
	ActionType ActionType  `json:"action_type"`
	Target     string      `json:"target"`
	InputHash  *string     `json:"input_hash,omitempty"`
	OutputHash *string     `json:"output_hash,omitempty"`
}

func (e *TrajectoryEntry) Validate() error {
	if e.Timestamp.IsZero() {
		return errors.New("timestamp is required")
	}
	if !e.ActionType.IsValid() {
		return errors.New("invalid action type: " + string(e.ActionType))
	}
	if e.Target == "" {
		return errors.New("target is required")
	}
	return nil
}

func (e *GroundTruthEvent) Validate() error {
	if e.Timestamp.IsZero() {
		return errors.New("timestamp is required")
	}
	if !e.ActionType.IsValid() {
		return errors.New("invalid action type: " + string(e.ActionType))
	}
	if e.Target == "" {
		return errors.New("target is required")
	}
	return nil
}

// Trajectory is an ordered sequence of self-reported entries.
type Trajectory []TrajectoryEntry

// GroundTruth is an ordered sequence of independently observed events.
type GroundTruth []GroundTruthEvent

func ParseTrajectory(data []byte) (Trajectory, error) {
	var t Trajectory
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	for i := range t {
		if err := t[i].Validate(); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func ParseGroundTruth(data []byte) (GroundTruth, error) {
	var g GroundTruth
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, err
	}
	for i := range g {
		if err := g[i].Validate(); err != nil {
			return nil, err
		}
	}
	return g, nil
}

func StringPtr(s string) *string {
	return &s
}
