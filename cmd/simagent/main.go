package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func main() {
	var workspace string
	var trajectoryOut string

	flag.StringVar(&workspace, "workspace", "", "Path to the workspace directory")
	flag.StringVar(&trajectoryOut, "trajectory-out", "", "Path to write the trajectory JSON")
	flag.Parse()

	if workspace == "" || trajectoryOut == "" {
		log.Fatal("--workspace and --trajectory-out are required")
	}

	var trajectory models.Trajectory

	addEntry := func(action models.ActionType, target string) {
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: action,
			Target:     target,
		})
	}

	// Wait slightly between operations so timestamps are strictly ordered and matched properly
	delay := func() {
		time.Sleep(50 * time.Millisecond)
	}

	f1 := filepath.Join(workspace, "file1.txt")

	// 1. WriteFile
	// os.WriteFile triggers:
	// - FAN_OPEN (FileOpen)
	// - FAN_CREATE (FileWrite)
	// - FAN_MODIFY (FileWrite)
	// - FAN_CLOSE_WRITE (FileClose)
	// We report exactly what the kernel sees so the 1-to-1 verifier is happy.
	addEntry(models.FileOpen, f1)
	addEntry(models.FileWrite, f1) // create
	addEntry(models.FileWrite, f1) // modify
	addEntry(models.FileClose, f1)
	err := os.WriteFile(f1, []byte("hello"), 0644)
	if err != nil {
		log.Fatalf("failed to write file: %v", err)
	}

	delay()

	// 2. Rename
	// os.Rename triggers:
	// - FAN_MOVED_FROM (FileRename) on src
	// - FAN_MOVED_TO (FileRename) on dst
	f2 := filepath.Join(workspace, "file2.txt")
	addEntry(models.FileRename, f1)
	err = os.Rename(f1, f2)
	if err != nil {
		log.Fatalf("failed to rename file: %v", err)
	}

	delay()

	// 3. Delete
	// os.Remove triggers:
	// - FAN_DELETE (FileDelete)
	// Note: on tmpfs, this might report the parent dir in DFID, but we use TempDir
	// and if the kernel provides DFID_NAME, it gives the full path. We'll report the full path.
	addEntry(models.FileDelete, f2)
	err = os.Remove(f2)
	if err != nil {
		log.Fatalf("failed to remove file: %v", err)
	}

	b, err := json.MarshalIndent(trajectory, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal trajectory: %v", err)
	}
	if err := os.WriteFile(trajectoryOut, b, 0644); err != nil {
		log.Fatalf("failed to write trajectory: %v", err)
	}
}
