package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// httpClient is used for the optional --fetch-url HTTPS request. A 10-second
// timeout is generous enough for example.com but short enough to not stall
// tests indefinitely if the network is unavailable.
var httpClient = &http.Client{Timeout: 10 * time.Second}


func main() {
	var workspace string
	var trajectoryOut string
	var dropEntry int
	var fileOnly bool
	var attack string
	var fetchURL string

	flag.StringVar(&workspace, "workspace", "", "Path to the workspace directory")
	flag.StringVar(&trajectoryOut, "trajectory-out", "", "Path to write the trajectory JSON")
	flag.IntVar(&dropEntry, "drop-entry", -1, "Zero-based index of a trajectory entry to omit before writing (simulates an omission attack for manual testing; -1 disables)")
	flag.BoolVar(&fileOnly, "file-only", false, "Skip the subprocess step, producing a trajectory with only filesystem actions (for Tier 1, where no process probe runs)")
	flag.StringVar(&attack, "attack", "", "Simulate an attack scenario: 'omission', 'fabrication', 'substitution-exit', 'substitution-hash', 'substitution-cmd', 'net-omission', 'net-fabrication'")
	flag.StringVar(&fetchURL, "fetch-url", "", "If set, run `curl -s -o /dev/null -m 10 <url>` and record a NetConnect trajectory entry for the host")
	var fetchMethod, fetchBody string
	var emitNetRequest bool
	flag.StringVar(&fetchMethod, "fetch-method", "GET", "HTTP method to use for fetch (simulates net request)")
	flag.StringVar(&fetchBody, "fetch-body", "", "HTTP body to send (for POST/PUT)")
	flag.BoolVar(&emitNetRequest, "emit-net-request", false, "Emit a NetRequest entry with RequestHash instead of just NetConnect")

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
	addEntryWithInputHash := func(action models.ActionType, target, inputHash string) {
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: action,
			Target:     target,
			InputHash:  &inputHash,
		})
	}
	addEntryWithRequestHash := func(action models.ActionType, target, requestHash string) {
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: action,
			Target:     target,
			RequestHash: &requestHash,
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
	emptyHash := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	addEntryWithInputHash(models.FileOpen, f1, emptyHash)
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
		// Tier 2.5 Semantic Gap test: agent executes a shell command (top-level)
		// which spawns a subprocess (forensic).
		// We resolve the absolute path because the verifier now uses strict
		// absolute-path matching for process execution to prevent substitution attacks.
		wcPath, err := exec.LookPath("wc")
		if err != nil {
			log.Fatalf("failed to find wc in PATH: %v", err)
		}
		wcArgs := []string{wcPath, "-l", f2}
		wcCmdLine := strings.Join(wcArgs, " ")
		addEntry(models.ProcessExec, wcCmdLine)
		// wc opens f2 for reading. Since fanotify tracks all file events,
		// report it so it doesn't cause an omission mismatch.
		addEntryWithInputHash(models.FileOpen, f2, fileHash)
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

	// 5. Optional HTTPS fetch (Tier 3): make the request from within this
	// process using net/http so the TCP connection originates from simagent's
	// own PID. That PID is what the test wires into the net probe's
	// tracked_pids BPF map, so the tcp_connect tracepoint fires and the
	// netHello path captures the TLS ClientHello SNI.
	//
	// Using a subprocess (e.g. curl) would NOT work: the subprocess runs
	// under a different PID that is not in tracked_pids, making its
	// connections invisible to the BPF program. It would also pollute the
	// proc probe's ground truth with unexpected process_exec/exit events.
	var fetchHost string
	if fetchURL != "" {
		u, err := url.Parse(fetchURL)
		if err != nil {
			log.Fatalf("invalid --fetch-url %q: %v", fetchURL, err)
		}
		fetchHost = u.Hostname()

		// Go's crypto/tls sends a proper TLS ClientHello with an SNI
		// extension on the first write, so the BPF netHello path will
		// extract the hostname even though we are not using OpenSSL.
		var bodyReader io.Reader
		if fetchBody != "" {
			bodyReader = strings.NewReader(fetchBody)
		}
		req, err := http.NewRequest(fetchMethod, fetchURL, bodyReader)
		if err != nil {
			log.Fatalf("new request: %v", err)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			log.Printf("fetch %s: %v (ignoring for trajectory purposes)", fetchURL, err)
		} else {
			_ = resp.Body.Close()
		}

		// Record what we did: a network connection to the host.
		addEntry(models.NetConnect, fetchHost)

		if emitNetRequest {
			port := 0
			if u.Port() != "" {
				port, _ = strconv.Atoi(u.Port())
			} else if u.Scheme == "https" {
				port = 443
			}
			target := models.CanonicalNetTarget(fetchMethod, fetchHost, port, u.Path, u.RawQuery)
			if fetchBody != "" {
				h := sha256.Sum256([]byte(fetchBody))
				hashStr := "sha256:" + hex.EncodeToString(h[:])
				addEntryWithRequestHash(models.NetRequest, target, hashStr)
			} else {
				addEntry(models.NetRequest, target)
			}
		}

		delay()
	}

	if dropEntry >= 0 && dropEntry < len(trajectory) {
		trajectory = append(trajectory[:dropEntry], trajectory[dropEntry+1:]...)
	}

	switch attack {
	case "omission":
		// Drop the first entry if drop-entry wasn't already used
		if dropEntry == -1 && len(trajectory) > 0 {
			trajectory = trajectory[1:]
		}
	case "fabrication":
		// Claim to have run curl, but didn't
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: models.ProcessExec,
			Target:     "/usr/bin/curl https://example.com",
		})
	case "substitution-exit":
		// Find a process_exit and change its exit code
		for i := range trajectory {
			if trajectory[i].ActionType == models.ProcessExit && trajectory[i].ExitCode != nil {
				fakeExitCode := *trajectory[i].ExitCode + 1
				trajectory[i].ExitCode = &fakeExitCode
				break
			}
		}
	case "substitution-hash":
		// Find a file_close with an output hash and change it
		for i := range trajectory {
			if trajectory[i].ActionType == models.FileClose && trajectory[i].OutputHash != nil {
				fakeHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
				trajectory[i].OutputHash = &fakeHash
				break
			}
		}
	case "substitution-cmd":
		// Find a process_exec and change its arguments
		for i := range trajectory {
			if trajectory[i].ActionType == models.ProcessExec {
				trajectory[i].Target = trajectory[i].Target + " --fake-flag"
				break
			}
		}
	case "net-omission":
		// Drop the NetConnect entry — the net probe still saw it, so it
		// surfaces as Unrecorded in the verifier.
		filtered := trajectory[:0:0]
		for _, e := range trajectory {
			if e.ActionType != models.NetConnect {
				filtered = append(filtered, e)
			}
		}
		trajectory = filtered
	case "net-fabrication":
		// Claim to have connected to a host that was never contacted.
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: models.NetConnect,
			Target:     "ghost.example.invalid",
		})
	}

	b, err := json.MarshalIndent(trajectory, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal trajectory: %v", err)
	}
	if err := os.WriteFile(trajectoryOut, b, 0644); err != nil {
		log.Fatalf("failed to write trajectory: %v", err)
	}
}
