//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// Independent UAPI oracle: a separately opened descriptor of the owned fixture,
// no production identity helper and no source-string/ephemeral-device assertion.
func durableIdentityOracle(t *testing.T, path string) [32]byte {
	t.Helper()
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	var st syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || syscall.Fstatfs(int(f.Fd()), &fs) != nil {
		t.Fatal("fixture stat")
	}
	var uuid [16]byte
	var request uintptr
	var data []byte
	offset := 0
	switch uint64(fs.Type) {
	case 0x9123683e:
		request = 0x8400941f
		data = make([]byte, 1024)
		offset = 16
	case 0xef53:
		request = 0x8008662c
		data = make([]byte, 24)
		binary.LittleEndian.PutUint32(data, 16)
		offset = 8
	case 0x58465342:
		request = 0x80705864
		data = make([]byte, 112)
		offset = 64
	default:
		t.Fatal("fixture has no durable owned profile")
	}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), request, uintptr(unsafe.Pointer(&data[0]))); e != 0 {
		t.Fatal("native UUID oracle", e)
	}
	copy(uuid[:], data[offset:offset+16])
	handle := struct {
		Size uint32
		Type int32
		Data [128]byte
	}{Size: 128}
	var mount int32
	empty := []byte{0}
	trap := uintptr(303)
	if runtime.GOARCH == "arm64" {
		trap = 264
	}
	if _, _, e := syscall.Syscall6(trap, f.Fd(), uintptr(unsafe.Pointer(&empty[0])), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&mount)), 0x1000, 0); e != 0 || handle.Size > 128 {
		t.Fatal("native handle oracle", e)
	}
	raw := append([]byte("PackTrace:owned-root:linux:v3\x00"), make([]byte, 8)...)
	binary.LittleEndian.PutUint64(raw[len(raw)-8:], uint64(fs.Type))
	raw = append(raw, uuid[:]...)
	number := make([]byte, 16)
	binary.LittleEndian.PutUint64(number, uint64(st.Uid))
	binary.LittleEndian.PutUint32(number[8:], uint32(handle.Type))
	binary.LittleEndian.PutUint32(number[12:], handle.Size)
	raw = append(raw, number...)
	raw = append(raw, handle.Data[:handle.Size]...)
	return sha256.Sum256(raw)
}
func TestOwnedPersistentIdentityUsesNativeVolumeAndObjectGenerationNotBootNumbers(t *testing.T) {
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
	expected := durableIdentityOracle(t, path)
	if got != expected {
		t.Fatal("persisted identity does not bind native filesystem UUID and object generation independently of boot device/mount numbers")
	}
	if e := owner.WriteControl(ctx, "ordinary-own-mutation", []byte("owned")); e != nil {
		t.Fatal(e)
	}
	after, e := owner.ReadRoot().OwnedIdentity(ctx)
	if e != nil || after != got || durableIdentityOracle(t, path) != got {
		t.Fatal("ordinary directory mutation changed durable identity", e)
	}
	reopened, e := OpenOwnedDirectory(ctx, path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	again, e := reopened.ReadRoot().OwnedIdentity(ctx)
	if e != nil || again != got {
		t.Fatal("fresh original handle did not retain durable identity", e)
	}
	other, e := OpenOwnedDirectory(ctx, filepath.Join(t.TempDir(), "other"), true)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	different, e := other.ReadRoot().OwnedIdentity(ctx)
	if e != nil || different == got {
		t.Fatal("another native object inherited durable identity", e)
	}
	// Only the persisted projection ignores a reboot's device number. The
	// actual original runtime guard below still refuses a forged device stamp.
	n, unlock, e := owner.ReadRoot().lockNative()
	if e != nil {
		t.Fatal(e)
	}
	var raw syscall.Stat_t
	if syscall.Fstat(int(n.root.Fd()), &raw) != nil {
		unlock()
		t.Fatal("original stat")
	}
	mount, e := n.mountID()
	if e != nil {
		unlock()
		t.Fatal(e)
	}
	raw.Dev++
	projected, e := durableLinuxOwnedIdentity(n, raw, mount)
	if e != nil || projected != got {
		unlock()
		t.Fatal("runtime device number entered persisted projection", e)
	}
	before := n.initial
	n.initial.dev++
	_, e = ownedIdentity(n)
	n.initial = before
	unlock()
	if e == nil {
		t.Fatal("persisted identity change weakened the original runtime device guard")
	}
}

func TestDurableLinuxIdentityRejectsUnknownOrIncompleteNativeCoordinates(t *testing.T) {
	var uuid [16]byte
	uuid[0] = 1
	handle := make([]byte, 20)
	binary.LittleEndian.PutUint64(handle, 7)
	binary.LittleEndian.PutUint64(handle[8:], 257)
	binary.LittleEndian.PutUint32(handle[16:], 9)
	good, e := hashDurableLinuxOwnedIdentity(0x9123683e, uuid, 1000, 7, 0x4d, handle)
	if e != nil {
		t.Fatal(e)
	}
	for _, variant := range []string{"uuid", "inode", "type", "length", "generation", "subvolume", "volatilefs"} {
		t.Run(variant, func(t *testing.T) {
			u := uuid
			h := append([]byte(nil), handle...)
			kind, ino, typ := uint64(0x9123683e), uint64(7), uint32(0x4d)
			switch variant {
			case "uuid":
				u = [16]byte{}
			case "inode":
				ino++
			case "type":
				typ++
			case "length":
				h = h[:19]
			case "generation":
				clear(h[16:])
			case "subvolume":
				clear(h[8:16])
			case "volatilefs":
				kind = 0x01021994
			}
			if _, e := hashDurableLinuxOwnedIdentity(kind, u, 1000, ino, typ, h); e == nil {
				t.Fatal("incomplete native proof accepted")
			}
		})
	}
	other := uuid
	other[0]++
	changed, e := hashDurableLinuxOwnedIdentity(0x9123683e, other, 1000, 7, 0x4d, handle)
	if e != nil || changed == good {
		t.Fatal("another native filesystem inherited identity", e)
	}
	for _, kind := range []uint64{0xef53, 0x58465342} {
		h := make([]byte, 8)
		binary.LittleEndian.PutUint32(h, 7)
		binary.LittleEndian.PutUint32(h[4:], 9)
		if _, e := hashDurableLinuxOwnedIdentity(kind, uuid, 1000, 7, 1, h); e != nil {
			t.Fatal("known UAPI shape rejected (not filesystem runtime qualification)", kind, e)
		}
	}
}
