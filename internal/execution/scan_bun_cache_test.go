package execution

import (
	"context"
	"os"
	"runtime"
	"testing"
)

func TestBunCacheOriginalBindingAndOutputLifetime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("initial paired-manifest mechanism is Linux only")
	}
	ctx := context.Background()
	target, cache := t.TempDir(), t.TempDir()
	owner, err := openScanBunCache(ctx, nil, target, cache, "")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	worker, err := openScanBunCache(ctx, nil, target, cache, owner.binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.check(); err != nil {
		t.Fatal("worker release closed parent originals", err)
	}
	wrong, err := openScanBunCache(ctx, nil, target, t.TempDir(), owner.binding)
	if wrong != nil {
		wrong.close()
	}
	if err == nil {
		t.Fatal("different cache object accepted")
	}
	if err := os.Rename(cache, cache+"-old"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(cache + "-old") })
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := owner.check(); err == nil {
		t.Fatal("path replacement passed output checkpoint")
	}
}
