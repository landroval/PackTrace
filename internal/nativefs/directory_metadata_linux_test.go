//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDirectoryMetadataNeverOpensRegularContent(t *testing.T) {
	path := t.TempDir()
	canary := filepath.Join(path, "canary")
	if os.WriteFile(canary, []byte("private"), 0600) != nil {
		t.Fatal("owned canary")
	}
	r, err := OpenRoot(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	watch, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(watch)
	if _, err := syscall.InotifyAddWatch(watch, canary, syscall.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	if d, err := r.OpenDirectoryMetadata(context.Background(), "canary"); !errors.Is(err, ErrType) || d != nil {
		t.Fatal("regular file admitted as directory", err)
	}
	var events [4096]byte
	if n, err := syscall.Read(watch, events[:]); n > 0 || !errors.Is(err, syscall.EAGAIN) {
		t.Fatal("rejected directory selection opened regular content", n, err)
	}
	// Paired positive control: a real I/O open of this exact file is observed.
	f, err := os.Open(canary)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := syscall.Read(watch, events[:]); n <= 0 || err != nil {
		t.Fatal("regular-content open oracle inactive", n, err)
	}
}
