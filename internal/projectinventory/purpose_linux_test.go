//go:build linux && (amd64 || arm64)

package projectinventory

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func watchedContent(t *testing.T, names ...string) func() bool {
	t.Helper()
	fd, e := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	for _, name := range names {
		if _, e := syscall.InotifyAddWatch(fd, name, syscall.IN_ACCESS); e != nil {
			t.Fatal(e)
		}
	}
	return func() bool {
		b := make([]byte, 4096)
		n, e := syscall.Read(fd, b)
		if e != nil && e != syscall.EAGAIN {
			t.Fatal(e)
		}
		return n > 0
	}
}
func TestEffectiveInputSelectionDoesNotReadNonGoverningOrSecretContent(t *testing.T) {
	r, root := ownedProject(t, map[string]string{"package.json": declaredRoot, "npm-shrinkwrap.json": "{invalid", "package-lock.json": emptyNPMLock, ".env": "owned secret canary", "src.js": "owned never execute/read"})
	read := watchedContent(t, filepath.Join(root, "package-lock.json"), filepath.Join(root, ".env"), filepath.Join(root, "src.js"))
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil || got.Selection.State != "unusable" {
		t.Fatal(got, e)
	}
	if read() {
		t.Fatal("purpose blocker: non-governing/secret content read")
	}
}
func TestUnsafeShrinkwrapCannotFallBackOrReadReferent(t *testing.T) {
	r, root := ownedProject(t, map[string]string{"package.json": declaredRoot, "package-lock.json": emptyNPMLock, "secret": emptyNPMLock})
	if os.Symlink("secret", filepath.Join(root, "npm-shrinkwrap.json")) != nil {
		t.Fatal("owned link")
	}
	read := watchedContent(t, filepath.Join(root, "secret"), filepath.Join(root, "package-lock.json"))
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil || got.Selection.File != "npm-shrinkwrap.json" || got.Selection.State != "unusable" || got.Complete {
		t.Fatal("unsafe input substituted", got, e)
	}
	if read() {
		t.Fatal("unsafe shrinkwrap/reference fallback read")
	}
}
