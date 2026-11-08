package intelstore

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// Authored summaries follow the same real preparation/seal/export pipeline as
// existing fixtures, using only an in-memory transport and fixed test clock.
func TestReadableAdvisoryFixtureReproducible(t *testing.T) {
	data, id := matchingFixtureBundleFor(t, "matching-readable", 3)
	t.Logf("generation=%x bytes=%d sha256=%x", id, len(data), sha256.Sum256(data))
	if output := os.Getenv("PACKTRACE_READABLE_FIXTURE_NEW_OUTPUT"); output != "" {
		f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		n, writeErr := f.Write(data)
		closeErr := f.Close()
		if n != len(data) || writeErr != nil || closeErr != nil {
			t.Fatal(n, writeErr, closeErr)
		}
		return
	}
	existing, err := os.ReadFile(filepath.Join("..", "execution", "testdata", "intel", "readable.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, existing) {
		t.Fatal("readable fixture differs from real deterministic source path")
	}
}
