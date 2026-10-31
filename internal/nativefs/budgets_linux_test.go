//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxNoOverBudgetSentinelRead(t *testing.T) {
	r, d := fixture(t)
	f, err := r.OpenRegular(context.Background(), "dir/a", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = os.WriteFile(filepath.Join(d, "dir", "a"), []byte("abcd"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(f); !errors.Is(err, ErrLimit) {
		t.Fatalf("grow: %v", err)
	}
	if r.consumed > 3 {
		t.Fatalf("sentinel exceeded lease: read %d, cap 3", r.consumed)
	}
	if f.Stable() == nil {
		t.Fatal("limit failure certified")
	}
}
func TestLinuxRootBudgetSharedAcrossLeases(t *testing.T) {
	r, _ := fixture(t)
	a, err := r.OpenRegular(context.Background(), "dir/a", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := r.OpenRegular(context.Background(), "alias/a", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	r.consumed = maxTotal - 3
	if _, err = io.ReadAll(a); err != nil {
		t.Fatal(err)
	}
	if a.Stable() != nil {
		t.Fatal("exact budget completion rejected")
	}
	if _, err = b.Read(make([]byte, 1)); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if b.Stable() == nil {
		t.Fatal("ignored root budget failure certified")
	}
	if r.consumed != maxTotal {
		t.Fatal(r.consumed)
	}
}
func TestLinuxCancelAfterLeaseInvalidates(t *testing.T) {
	r, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	f, err := r.OpenRegular(ctx, "dir/a", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cancel()
	if _, err = f.Read(make([]byte, 3)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = f.Stable(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if r.consumed != 0 {
		t.Fatal("canceled lease read")
	}
}
func TestLinuxCycleAndOutsideRemainVisibleGaps(t *testing.T) {
	r, d := fixture(t)
	for n, target := range map[string]string{"loop": ".", "escape": "../elsewhere"} {
		if err := os.Symlink(target, filepath.Join(d, n)); err != nil {
			t.Fatal(err)
		}
	}
	s, err := r.Snapshot(context.Background(), Limits{})
	if err == nil || s.Complete {
		t.Fatal(s, err)
	}
	foundLoop, foundEscape := false, false
	for _, e := range s.Entries {
		if e.Name == "loop" {
			foundLoop = e.Kind == KindLink && e.Status != StatusComplete
		}
		if e.Name == "escape" {
			foundEscape = e.Kind == KindLink && e.Status == StatusExcluded
		}
	}
	if !foundLoop || !foundEscape {
		t.Fatal(s)
	}
}
