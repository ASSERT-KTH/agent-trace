package tlsoffset

import (
	"os/exec"
	"testing"
)

func TestScanELF_Self(t *testing.T) {
	// Let's find something we know has symbols. The go test binary itself won't have SSL_write,
	// but let's test that it doesn't panic.
	path, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go command not found")
	}

	cands, buildID, err := ScanELF(path)
	if err != nil {
		t.Logf("Scan error (expected if no rodata): %v", err)
	}
	t.Logf("Go binary build ID: %s, candidates: %d", buildID, len(cands))
}
