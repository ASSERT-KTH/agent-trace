package net

import (
	stdnet "net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// findLibSSL locates the shared library openssl(1) itself links against, so
// this test can attach the SSL_write uprobe to a real, dynamically linked
// BoringSSL/OpenSSL build without needing a Bun (or other statically linked)
// binary on the test host. Skips the test if either isn't available.
func findLibSSL(t *testing.T) string {
	t.Helper()
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}
	out, err := exec.Command("ldd", opensslPath).Output()
	if err != nil {
		t.Skipf("ldd %s: %v", opensslPath, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "libssl.so") {
			continue
		}
		fields := strings.Fields(line)
		// "libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x...)"
		for i, f := range fields {
			if f == "=>" && i+1 < len(fields) {
				if _, err := os.Stat(fields[i+1]); err == nil {
					return fields[i+1]
				}
			}
		}
	}
	t.Skip("could not resolve libssl.so path from ldd output")
	return ""
}

// TestObserver_ContentCaptureViaSSLWriteUprobe exercises the full S5 path:
// resolve SSL_write in a real shared library, attach and validate the
// uprobe, capture an HTTP/1.1 request written by openssl(1) s_client
// through it, and correlate it into a models.NetRequest GroundTruthEvent
// carrying the right target and RequestHash. This is deliberately run
// against libssl.so rather than the openssl binary itself: SSL_write lives
// in the shared library, not in openssl(1)'s own symbol table.
func TestObserver_ContentCaptureViaSSLWriteUprobe(t *testing.T) {
	skipUnprivileged(t)
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	libssl := findLibSSL(t)

	const host = "agenttrace-content-test.internal"
	addr := startTLSServer(t, host)
	serverHost, port, err := stdnet.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	obs, err := New(Config{
		ExePath:           libssl,
		EventBufSize:      256,
		ValidationTimeout: 8 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cmd := exec.Command("openssl", "s_client",
		"-connect", stdnet.JoinHostPort(serverHost, port),
		"-servername", host, "-quiet")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start openssl: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	if err := obs.TrackPID(int32(cmd.Process.Pid)); err != nil {
		t.Fatalf("TrackPID: %v", err)
	}

	startDone := make(chan struct{})
	go func() {
		obs.Start()
		close(startDone)
	}()

	// s_client forwards stdin to SSL_write once the handshake completes;
	// Start's validation blocks (with its own timeout) until that frame
	// arrives, so no extra synchronization is needed here beyond writing
	// promptly.
	start := time.Now()
	if _, err := stdin.Write([]byte("GET /v1/hello?x=1 HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write to openssl stdin: %v", err)
	}
	_ = stdin.Close()
	end := time.Now()

	select {
	case <-startDone:
	case <-time.After(15 * time.Second):
		t.Fatal("Observer.Start did not return (uprobe validation hung)")
	}
	t.Logf("TLSAttachError: %v", obs.TLSAttachError())
	if attachErr := obs.TLSAttachError(); attachErr != nil {
		t.Fatalf("TLSAttachError: %v", attachErr)
	}

	// Drain events with a bound: correlate() only advances the stream as
	// frames arrive, and the request may have been fully captured in one
	// SSL_write or split across a couple. Every event is logged, and every
	// one seen is kept, not just the first NetRequest, so a failure shows
	// what actually came out of the pipeline instead of just "found nothing".
	var got *models.GroundTruthEvent
	var all []models.GroundTruthEvent
	deadline := time.After(5 * time.Second)
drain:
	for {
		select {
		case ev := <-obs.Events():
			t.Logf("event: type=%s target=%q requestHash=%v ts=%v", ev.ActionType, ev.Target, ev.RequestHash, ev.Timestamp)
			all = append(all, ev)
			if ev.ActionType == models.NetRequest && got == nil {
				e := ev
				got = &e
			}
		case <-deadline:
			break drain
		}
	}

	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	cov := obs.Coverage() // Coverage is only meaningful after Stop returns
	t.Logf("coverage: %+v", cov)

	if got == nil {
		t.Fatalf("no NetRequest event observed (saw %d events total: %+v; coverage: %+v)", len(all), all, cov)
	}
	wantTarget := "GET https://" + host + "/v1/hello?x=1"
	if got.Target != wantTarget {
		t.Errorf("Target = %q, want %q", got.Target, wantTarget)
	}
	if got.Timestamp.Before(start.Add(-time.Second)) || got.Timestamp.After(end.Add(5*time.Second)) {
		t.Errorf("timestamp %v outside expected window [%v, %v]", got.Timestamp, start, end)
	}
	if got.RequestHash != nil {
		t.Errorf("RequestHash = %v, want nil for a bodyless GET", *got.RequestHash)
	}
}
