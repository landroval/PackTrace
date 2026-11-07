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

func TestOwnedIdentityReusesOnlyItsOriginalRootProofWithoutRepeatingDirectoryIO(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owned")
	owner, e := OpenOwnedDirectory(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	first, e := owner.ReadRoot().OwnedIdentity(ctx)
	if e != nil {
		t.Fatal(e)
	}
	watch, e := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(watch)
	if _, e := syscall.InotifyAddWatch(watch, path, syscall.IN_OPEN); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 10; i++ {
		got, e := owner.ReadRoot().OwnedIdentity(ctx)
		if e != nil || got != first {
			t.Fatal("original native proof changed", e)
		}
	}
	data := make([]byte, 4096)
	if n, e := syscall.Read(watch, data); n > 0 || !errors.Is(e, syscall.EAGAIN) {
		t.Fatal("stable original repeatedly opened directory I/O instead of reusing its minted proof", n, e)
	}
	positive, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	positive.Close()
	if n, e := syscall.Read(watch, data); n <= 0 || e != nil {
		t.Fatal("directory I/O canary did not detect the positive control", n, e)
	}
	native, unlock, e := owner.ReadRoot().lockNative()
	if e != nil {
		t.Fatal(e)
	}
	saved := *native.ownedProof
	native.ownedProof.uid++
	_, uidError := ownedIdentity(native)
	*native.ownedProof = saved
	native.ownedProof.mount++
	_, mountError := ownedIdentity(native)
	*native.ownedProof = saved
	unlock()
	if uidError == nil || mountError == nil {
		t.Fatal("cached proof escaped original owner/mount checks", uidError, mountError)
	}
}
