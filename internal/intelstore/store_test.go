package intelstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Removing readonly/create separation must fail these actual filesystem checks.
func TestReadOnlyNeverInitializes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	s, err := Open(context.Background(), path, ReadOnly)
	if err == nil || s != nil {
		t.Fatal("missing store admitted")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("readonly access created state")
	}
}

func TestUnmarkedDirectoryIsNotAdopted(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows store")
	}
	path := t.TempDir()
	if _, err := Open(context.Background(), path, CreateOwned); !errors.Is(err, ErrOwnership) {
		t.Fatal("unmarked directory adopted")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused initialization changed an unmarked directory")
	}
}

func TestStoreRejectsInvalidModeAndCancelledInitialization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	if s, err := Open(context.Background(), path, Mode(255)); err == nil || s != nil {
		t.Fatal("invalid mode admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := Open(ctx, path, CreateOwned); !errors.Is(err, context.Canceled) || s != nil {
		t.Fatal("cancelled initialization admitted")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected request created state")
	}
}

func TestStoreCreatesOwnedRootAndReopensReadOnly(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows store")
	}
	path := filepath.Join(t.TempDir(), "state")
	s, err := Open(context.Background(), path, CreateOwned)
	if err != nil || s == nil {
		t.Fatal("fresh owned store unavailable", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("fresh store close failed", err)
	}
	s, err = Open(context.Background(), path, ReadOnly)
	if err != nil || s == nil {
		t.Fatal("owned readonly reopen failed", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("readonly close failed", err)
	}
}

func TestStoreCloseRejectsZeroCapability(t *testing.T) {
	var s Store
	if err := s.Close(); err == nil {
		t.Fatal("zero store reported successful close")
	}
}
