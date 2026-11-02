//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestMetadataLeaseNeverReadsLinkReferentAndRejectsRetarget(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if os.WriteFile(filepath.Join(dir, name), []byte("owned content canary"), 0600) != nil {
			t.Fatal("fixture")
		}
	}
	if os.Symlink("a", filepath.Join(dir, "link")) != nil {
		t.Fatal("fixture link")
	}
	r, e := OpenRoot(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	watch, e := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(watch)
	for _, name := range []string{"a", "b"} {
		if _, e := syscall.InotifyAddWatch(watch, filepath.Join(dir, name), syscall.IN_ACCESS); e != nil {
			t.Fatal(e)
		}
	}
	lease, e := r.OpenMetadata(context.Background(), "link")
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	if lease.Entry().Kind != KindLink || lease.Entry().LinkTarget != "a" || lease.Stable() != nil {
		t.Fatal("link metadata not captured")
	}
	if os.Remove(filepath.Join(dir, "link")) != nil || os.Symlink("b", filepath.Join(dir, "link")) != nil {
		t.Fatal("owned retarget")
	}
	if lease.Stable() == nil {
		t.Fatal("retargeted binding accepted")
	}
	buf := make([]byte, 4096)
	n, e := syscall.Read(watch, buf)
	if n > 0 || e != nil && e != syscall.EAGAIN {
		t.Fatal("metadata capability read referent", n, e)
	}
}
