//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxReadTransitionUsesCapturedObjectNotReplacedName(t *testing.T) {
	r, d := fixture(t)
	selected, s, err := r.native.capture("dir/a", true)
	if err != nil {
		t.Fatal(err)
	}
	defer selected.Close()
	// This deterministic schedule replaces the actual name AFTER the non-I/O
	// capture and BEFORE the production read transition. No device experiments.
	if err = os.Rename(filepath.Join(d, "dir", "a"), filepath.Join(d, "dir", "old")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(d, "dir", "a"), []byte("xyz"), 0600); err != nil {
		t.Fatal(err)
	}
	read, err := r.native.readCaptured(selected, s)
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	b, err := io.ReadAll(read)
	if err != nil || string(b) != "abc" {
		t.Fatalf("transition rebound name: %q %v", b, err)
	}
	if r.check("dir/a", s) == nil {
		t.Fatal("replaced namespace certified")
	}
}
func TestLinuxAncestorMoveInvalidatesLease(t *testing.T) {
	r, d := fixture(t)
	f, err := r.OpenRegular(context.Background(), "dir/a", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	outside := t.TempDir()
	if err = os.Rename(filepath.Join(d, "dir"), filepath.Join(outside, "moved")); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "abc" {
		t.Fatalf("original capability lost: %q %v", b, err)
	}
	if f.Stable() == nil {
		t.Fatal("moved ancestor certified")
	}
}
