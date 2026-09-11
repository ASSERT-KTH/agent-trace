package models

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestActionTypeIsValid(t *testing.T) {
	valid := []ActionType{
		FileOpen, FileRead, FileWrite, FileClose, FileRename, FileDelete,
		NetRequest, NetDNS, NetConnect,
		ProcessExec, ProcessExit,
		GitCommit,
	}
	for _, at := range valid {
		if !at.IsValid() {
			t.Errorf("expected %q to be valid", at)
		}
	}

	invalid := []ActionType{"", "unknown", "FILE_OPEN", "file-read"}
	for _, at := range invalid {
		if at.IsValid() {
			t.Errorf("expected %q to be invalid", at)
		}
	}
}

func TestTrajectoryEntryValidation(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		entry   TrajectoryEntry
		wantErr bool
	}{
		{
			name: "valid entry with both hashes",
			entry: TrajectoryEntry{
				Timestamp:  now,
				ActionType: FileWrite,
				Target:     "/tmp/test.txt",
				InputHash:  StringPtr("abc123"),
				OutputHash: StringPtr("def456"),
			},
		},
		{
			name: "valid entry with no hashes",
			entry: TrajectoryEntry{
				Timestamp:  now,
				ActionType: FileDelete,
				Target:     "/tmp/test.txt",
			},
		},
		{
			name: "missing timestamp",
			entry: TrajectoryEntry{
				ActionType: FileRead,
				Target:     "/tmp/test.txt",
			},
			wantErr: true,
		},
		{
			name: "invalid action type",
			entry: TrajectoryEntry{
				Timestamp:  now,
				ActionType: "bogus",
				Target:     "/tmp/test.txt",
			},
			wantErr: true,
		},
		{
			name: "empty target",
			entry: TrajectoryEntry{
				Timestamp:  now,
				ActionType: FileRead,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.entry.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestGroundTruthEventValidation(t *testing.T) {
	now := time.Now()

	valid := GroundTruthEvent{
		Timestamp:  now,
		ActionType: NetRequest,
		Target:     "https://api.example.com/v1/chat",
		OutputHash: StringPtr("resp_hash"),
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	invalid := GroundTruthEvent{
		ActionType: NetRequest,
		Target:     "https://api.example.com",
	}
	if err := invalid.Validate(); err == nil {
		t.Error("expected error for missing timestamp")
	}
}

func TestTrajectoryEntryRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)

	original := TrajectoryEntry{
		Timestamp:  now,
		ActionType: FileWrite,
		Target:     "/workspace/main.py",
		InputHash:  StringPtr("sha256:aaa"),
		OutputHash: StringPtr("sha256:bbb"),
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded TrajectoryEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !original.Timestamp.Equal(decoded.Timestamp) {
		t.Errorf("timestamp mismatch: %v != %v", original.Timestamp, decoded.Timestamp)
	}
	if original.ActionType != decoded.ActionType {
		t.Errorf("action_type mismatch: %v != %v", original.ActionType, decoded.ActionType)
	}
	if original.Target != decoded.Target {
		t.Errorf("target mismatch: %v != %v", original.Target, decoded.Target)
	}
	if *original.InputHash != *decoded.InputHash {
		t.Errorf("input_hash mismatch: %v != %v", *original.InputHash, *decoded.InputHash)
	}
	if *original.OutputHash != *decoded.OutputHash {
		t.Errorf("output_hash mismatch: %v != %v", *original.OutputHash, *decoded.OutputHash)
	}
}

func TestRoundTripNilHashes(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)

	original := TrajectoryEntry{
		Timestamp:  now,
		ActionType: FileDelete,
		Target:     "/workspace/tmp.log",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded TrajectoryEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.InputHash != nil {
		t.Errorf("expected nil input_hash, got %v", *decoded.InputHash)
	}
	if decoded.OutputHash != nil {
		t.Errorf("expected nil output_hash, got %v", *decoded.OutputHash)
	}
}

// TestGroundTruthEventRoundTripPathIsAmbiguous pins the wire behavior of
// PathIsAmbiguous (Fix 6): true must round-trip as true, and the omitempty
// default (false, or the field absent entirely, as legacy ground truth
// files predating Fix 6 will have) must decode as false, never as some
// zero-value ambiguity that could accidentally enable the directory-fallback
// leniency in matching.targetsMatch.
func TestGroundTruthEventRoundTripPathIsAmbiguous(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)

	t.Run("true survives the round trip", func(t *testing.T) {
		original := GroundTruthEvent{
			Timestamp:       now,
			ActionType:      FileWrite,
			Target:          "/workspace/src",
			PathIsAmbiguous: true,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		var decoded GroundTruthEvent
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !decoded.PathIsAmbiguous {
			t.Error("expected path_is_ambiguous to survive the round trip as true")
		}
	})

	t.Run("false is omitted and decodes back to false", func(t *testing.T) {
		original := GroundTruthEvent{
			Timestamp:  now,
			ActionType: FileWrite,
			Target:     "/workspace/src/main.go",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if bytes.Contains(data, []byte("path_is_ambiguous")) {
			t.Errorf("expected path_is_ambiguous to be omitted when false, got %s", data)
		}

		var decoded GroundTruthEvent
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.PathIsAmbiguous {
			t.Error("expected path_is_ambiguous to decode back to false")
		}
	})

	t.Run("legacy JSON without the field decodes to false", func(t *testing.T) {
		legacy := []byte(`{"timestamp":"2026-01-01T00:00:00Z","action_type":"file_write","target":"/workspace/src"}`)

		var decoded GroundTruthEvent
		if err := json.Unmarshal(legacy, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.PathIsAmbiguous {
			t.Error("legacy ground truth without path_is_ambiguous must decode to false, not true")
		}
	})
}

func TestParseTrajectory(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)

	entries := Trajectory{
		{Timestamp: now, ActionType: FileRead, Target: "/etc/hostname", OutputHash: StringPtr("h1")},
		{Timestamp: now.Add(time.Second), ActionType: FileWrite, Target: "/tmp/out.txt", InputHash: StringPtr("h2"), OutputHash: StringPtr("h3")},
	}

	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := ParseTrajectory(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(parsed))
	}
	if parsed[0].Target != "/etc/hostname" {
		t.Errorf("wrong target: %s", parsed[0].Target)
	}
	if parsed[1].ActionType != FileWrite {
		t.Errorf("wrong action type: %s", parsed[1].ActionType)
	}
}

func TestParseTrajectoryRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"bad json", `not json`},
		{"missing target", `[{"timestamp":"2026-09-01T00:00:00Z","action_type":"file_read"}]`},
		{"invalid action", `[{"timestamp":"2026-09-01T00:00:00Z","action_type":"bad","target":"/x"}]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTrajectory([]byte(tc.json))
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestParseGroundTruth(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)

	events := GroundTruth{
		{Timestamp: now, ActionType: ProcessExec, Target: "ls", OutputHash: StringPtr("out1")},
	}

	data, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := ParseGroundTruth(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 event, got %d", len(parsed))
	}
	if parsed[0].ActionType != ProcessExec {
		t.Errorf("wrong action type: %s", parsed[0].ActionType)
	}
}
