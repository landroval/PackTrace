//go:build linux

package nativefs

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOwnedPersistentIdentityUsesPhysicalCoordinatesNotKernelMountNumber(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owned")
	owner, e := OpenOwnedDirectory(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	got, e := owner.ReadRoot().OwnedIdentity(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var raw syscall.Stat_t
	if e := syscall.Stat(path, &raw); e != nil {
		t.Fatal(e)
	}
	var durable [24]byte
	binary.LittleEndian.PutUint64(durable[0:8], uint64(raw.Dev))
	binary.LittleEndian.PutUint64(durable[8:16], raw.Ino)
	binary.LittleEndian.PutUint64(durable[16:24], uint64(raw.Uid))
	expected := sha256.Sum256(append([]byte("PackTrace:owned-root:linux:v2\x00"), durable[:]...))
	if got != expected {
		t.Fatal("persistent cache identity includes an ephemeral mount number or omits physical coordinates")
	}
}
