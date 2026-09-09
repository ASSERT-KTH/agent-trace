package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

func main() {
	var workspace string
	var trajectoryOut string
	var dropEntry int
	var fileOnly bool

	flag.StringVar(&workspace, "workspace", "", "Path to the workspace directory")
	flag.StringVar(&trajectoryOut, "trajectory-out", "", "Path to write the trajectory JSON")
	flag.IntVar(&dropEntry, "drop-entry", -1, "Zero-based index of a trajectory entry to omit before writing (simulates an omission attack for manual testing; -1 disables)")
	flag.BoolVar(&fileOnly, "file-only", false, "Skip the subprocess step, producing a trajectory with only filesystem actions (for Tier 1, where no process probe runs)")
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
	addEntryWithOutputHash := func(action models.ActionType, target, outputHash string) {
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: action,
			Target:     target,
			OutputHash: &outputHash,
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
	fileContents := []byte("hello")
	err := os.WriteFile(f1, fileContents, 0644)
	if err != nil {
		log.Fatalf("failed to write file: %v", err)
	}
	fileHash := content.SHA256Bytes(fileContents)
	addEntryWithOutputHash(models.FileClose, f1, fileHash)

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

	// 3. Exec (Tier 2): the agent double-checks its edit by running "wc -l"
	// against the renamed file, like a real coding agent verifying a change.
	// We report the exact argv the kernel will see: os/exec passes argv[0] as
	// given ("wc"), not the PATH-resolved absolute path, so the process
	// probe's reconstructed command line matches this string byte-for-byte.
	// Skipped under --file-only: Tier 1 runs no process probe, so these
	// entries would have no ground truth to corroborate them.
	if !fileOnly {
		wcArgs := []string{"wc", "-l", f2}
		wcCmdLine := strings.Join(wcArgs, " ")
		addEntry(models.ProcessExec, wcCmdLine)
		// wc opens f2 for reading. FAN_OPEN fires for any open regardless of
		// mode, so the fs probe observes this too -- report it or that event
		// goes Unrecorded even though the trajectory is otherwise honest.
		addEntry(models.FileOpen, f2)
		wcCmd := exec.Command(wcArgs[0], wcArgs[1:]...)
		runErr := wcCmd.Run()
		if _, ok := runErr.(*exec.ExitError); runErr != nil && !ok {
			log.Fatalf("failed to run wc: %v", runErr)
		}
		var wcExitCode int32
		if wcCmd.ProcessState != nil {
			wcExitCode = int32(wcCmd.ProcessState.ExitCode())
		}
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: models.ProcessExit,
			Target:     wcCmdLine,
			ExitCode:   &wcExitCode,
		})

		delay()
	}

	// 4. Delete
	// os.Remove triggers:
	// - FAN_DELETE (FileDelete)
	// Note: on tmpfs, this might report the parent dir in DFID, but we use TempDir
	// and if the kernel provides DFID_NAME, it gives the full path. We'll report the full path.
	addEntry(models.FileDelete, f2)
	err = os.Remove(f2)
	if err != nil {
		log.Fatalf("failed to remove file: %v", err)
	}

	if dropEntry >= 0 && dropEntry < len(trajectory) {
		trajectory = append(trajectory[:dropEntry], trajectory[dropEntry+1:]...)
	}

	b, err := json.MarshalIndent(trajectory, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal trajectory: %v", err)
	}
	if err := os.WriteFile(trajectoryOut, b, 0644); err != nil {
		log.Fatalf("failed to write trajectory: %v", err)
	}
}
