package nativefs

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMetadataLeaseRetainsObjectAndDetectsBindingChange(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("supported inventory metadata profile")
	}
	dir := t.TempDir()
	if os.Mkdir(filepath.Join(dir, "package"), 0700) != nil {
		t.Fatal("fixture")
	}
	root, e := OpenRoot(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	lease, e := root.OpenMetadata(context.Background(), "package")
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	if lease.Entry().Kind != KindDirectory || lease.Stable() != nil {
		t.Fatal("metadata lease not qualified")
	}
	if os.WriteFile(filepath.Join(dir, "package", "changed"), []byte("owned metadata change"), 0600) != nil {
		t.Fatal("fixture")
	}
	if lease.Stable() == nil {
		t.Fatal("changed directory metadata/binding accepted")
	}
}
func TestMetadataLeaseNeverGrantsAReadMethodOrOutlivesRoot(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("supported inventory metadata profile")
	}
	dir := t.TempDir()
	if os.WriteFile(filepath.Join(dir, "file"), []byte("owned no content read"), 0600) != nil {
		t.Fatal("fixture")
	}
	root, e := OpenRoot(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	lease, e := root.OpenMetadata(context.Background(), "file")
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	if lease.Entry().Kind != KindRegular || lease.Entry().Status != StatusComplete {
		t.Fatal("captured metadata lost")
	}
	if _, ok := any(lease).(interface{ Read([]byte) (int, error) }); ok {
		t.Fatal("metadata capability grants content read")
	}
	if root.Close() != nil || lease.Stable() == nil {
		t.Fatal("metadata lease survived closed anchor")
	}
}
