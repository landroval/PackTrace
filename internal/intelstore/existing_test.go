package intelstore

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExistingOwnedCannotInitializeAbsentState(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned state")
	}
	path := filepath.Join(t.TempDir(), "absent")
	if store, e := OpenExistingOwned(context.Background(), path); e == nil {
		store.Close()
		t.Fatal("existing-only operation initialized state")
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("existing-only constructor mutated absence", e)
	}
}
