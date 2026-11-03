package nativefs

import (
	"context"
	"runtime"
	"testing"
)

func TestRootMetadataRetainsOriginalDirectoryWithoutContentGrant(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native metadata")
	}
	ctx := context.Background()
	root, e := OpenRoot(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	m, e := root.OpenMetadata(ctx, ".")
	if e != nil {
		t.Fatal("original root metadata unavailable", e)
	}
	defer m.Close()
	if m.Entry().Kind != KindDirectory {
		t.Fatal("root metadata not directory")
	}
	if _, e := m.Fingerprint(); e != nil {
		t.Fatal(e)
	}
	if f, e := root.OpenInput(ctx, ".", 1); e == nil {
		f.Close()
		t.Fatal("metadata admission became root content grant")
	}
}
