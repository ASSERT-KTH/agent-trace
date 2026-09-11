// Package content provides deterministic content digests shared by reporters
// and ground-truth probes.
package content

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// SHA256File returns a versioned SHA-256 digest of the file's complete
// contents. The sha256 prefix makes the stored representation unambiguous as
// additional digest algorithms are introduced.
func SHA256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}

	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// SHA256FD returns a versioned SHA-256 digest of the file's complete
// contents, read directly from an open file descriptor. It does not close the original fd.
func SHA256FD(fd int) (string, error) {
	newFd, err := unix.Dup(fd)
	if err != nil {
		return "", fmt.Errorf("dup fd: %w", err)
	}
	file := os.NewFile(uintptr(newFd), "fd")
	defer func() { _ = file.Close() }()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash fd %d: %w", fd, err)
	}

	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// SHA256Bytes returns a versioned SHA-256 digest of data.
func SHA256Bytes(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}
