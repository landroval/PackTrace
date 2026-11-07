package nativefs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDistributionInputDoesNotWidenOrdinaryInputLimit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("large sparse admission control on Linux; no large allocation")
	}
	path := t.TempDir()
	file, e := os.Create(filepath.Join(path, "bundle"))
	if e != nil {
		t.Fatal(e)
	}
	if e := file.Truncate((512 << 20) + 1); e != nil {
		t.Fatal(e)
	}
	file.Close()
	root, e := OpenRoot(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if _, e := root.OpenInput(context.Background(), "bundle", 16<<30); !errors.Is(e, ErrLimit) {
		t.Fatal("ordinary input ceiling changed", e)
	}
	input, e := root.OpenDistributionInput(context.Background(), "bundle")
	if e != nil {
		t.Fatal("separate bounded distribution admission absent", e)
	}
	if e := input.Close(); e != nil {
		t.Fatal(e)
	}
}
