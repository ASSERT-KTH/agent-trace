package content

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSHA256File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "content.txt")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := SHA256File(path)
	if err != nil {
		t.Fatalf("SHA256File: %v", err)
	}
	const want = "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	if got != want {
		t.Errorf("SHA256File = %q, want %q", got, want)
	}
}

func TestSHA256Bytes(t *testing.T) {
	got := SHA256Bytes([]byte("hello\n"))
	const want = "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	if got != want {
		t.Errorf("SHA256Bytes = %q, want %q", got, want)
	}
}

func TestSHA256FileMissing(t *testing.T) {
	if _, err := SHA256File(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Error("SHA256File missing file returned nil error")
	}
}
