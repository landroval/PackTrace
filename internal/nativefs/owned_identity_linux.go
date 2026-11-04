//go:build linux && (amd64 || arm64)

package nativefs

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// Linux st_dev and mount IDs are lifetime coordinates, not durable volume IDs.
// Query only the retained ORIGINAL directory. No path/marker/key can mint this
// identity, and unsupported volatile/unknown profiles have no fallback.
func durableLinuxOwnedIdentity(n *nativeRoot, st syscall.Stat_t, mount uint64) (identity [32]byte, failure error) {
	f, e := n.readCaptured(n.root, n.initial)
	if e != nil {
		return identity, e
	}
	defer func() {
		if e := f.Close(); e != nil {
			failure = ErrRead
		}
	}()
	var fs syscall.Statfs_t
	if syscall.Fstatfs(int(f.Fd()), &fs) != nil {
		return identity, ErrRead
	}
	kind := uint64(fs.Type)
	uuid, e := ownedFilesystemUUID(f, kind)
	if e != nil {
		return identity, e
	}
	handle := struct {
		Bytes uint32
		Type  int32
		Data  [128]byte
	}{Bytes: 128}
	var returnedMount int32
	empty := []byte{0}
	// Linux amd64/arm64 UAPI; Go's frozen syscall package omits these constants.
	trap := uintptr(303)
	if runtime.GOARCH == "arm64" {
		trap = 264
	}
	_, _, errno := syscall.Syscall6(trap, f.Fd(), uintptr(unsafe.Pointer(&empty[0])), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&returnedMount)), 0x1000, 0)
	runtime.KeepAlive(f)
	runtime.KeepAlive(empty)
	runtime.KeepAlive(&handle)
	if errno != 0 || returnedMount <= 0 || uint64(returnedMount) != mount || handle.Bytes > 128 {
		return identity, ErrUnavailable
	}
	again, e := ownedFilesystemUUID(f, kind)
	if e != nil || again != uuid {
		return identity, ErrUnstable
	}
	return hashDurableLinuxOwnedIdentity(kind, uuid, uint64(st.Uid), st.Ino, uint32(handle.Type), handle.Data[:handle.Bytes])
}
func ownedFilesystemUUID(f *os.File, kind uint64) ([16]byte, error) {
	var uuid [16]byte
	var data [1024]byte
	var request uintptr
	offset := 0
	// ABI: linux/{btrfs,ext4}.h and xfs/xfs_fs.h. All are read-only ioctls.
	switch kind {
	case 0x9123683e:
		request, offset = 0x8400941f, 16 // BTRFS_IOC_FS_INFO, sizeof1024
	case 0xef53:
		request, offset = 0x8008662c, 8
		binary.LittleEndian.PutUint32(data[:4], 16) // EXT4_IOC_GETFSUUID, header8 + UUID16
	case 0x58465342:
		request, offset = 0x80705864, 64 // XFS_IOC_FSGEOMETRY_V1, sizeof112
	default:
		return uuid, ErrUnavailable
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), request, uintptr(unsafe.Pointer(&data[0])))
	runtime.KeepAlive(f)
	runtime.KeepAlive(&data)
	if errno != 0 {
		return uuid, ErrUnavailable
	}
	if kind == 0xef53 && (binary.LittleEndian.Uint32(data[:4]) != 16 || binary.LittleEndian.Uint32(data[4:8]) != 0) {
		return uuid, ErrUnavailable
	}
	copy(uuid[:], data[offset:offset+16])
	if uuid == ([16]byte{}) {
		return uuid, ErrUnavailable
	}
	return uuid, nil
}
func hashDurableLinuxOwnedIdentity(kind uint64, uuid [16]byte, uid, inode uint64, handleType uint32, handle []byte) ([32]byte, error) {
	fail := func() ([32]byte, error) { return [32]byte{}, ErrUnavailable }
	if uuid == ([16]byte{}) || inode == 0 {
		return fail()
	}
	switch kind {
	case 0x9123683e:
		// exportfs FILEID_BTRFS_WITHOUT_PARENT: object64/root64/generation32.
		if handleType != 0x4d || len(handle) != 20 || binary.LittleEndian.Uint64(handle[:8]) != inode || binary.LittleEndian.Uint64(handle[8:16]) == 0 || binary.LittleEndian.Uint32(handle[16:20]) == 0 {
			return fail()
		}
	case 0xef53:
		if handleType != 1 || len(handle) != 8 || uint64(binary.LittleEndian.Uint32(handle[:4])) != inode || binary.LittleEndian.Uint32(handle[4:8]) == 0 {
			return fail()
		}
	case 0x58465342:
		switch handleType {
		case 1:
			if len(handle) != 8 || uint64(binary.LittleEndian.Uint32(handle[:4])) != inode || binary.LittleEndian.Uint32(handle[4:8]) == 0 {
				return fail()
			}
		case 0x81:
			if len(handle) != 12 || binary.LittleEndian.Uint64(handle[:8]) != inode || binary.LittleEndian.Uint32(handle[8:12]) == 0 {
				return fail()
			}
		default:
			return fail()
		}
	default:
		return fail()
	}
	var numbers [8]byte
	h := sha256.New()
	h.Write([]byte("PackTrace:owned-root:linux:v3\x00"))
	binary.LittleEndian.PutUint64(numbers[:], kind)
	h.Write(numbers[:])
	h.Write(uuid[:])
	binary.LittleEndian.PutUint64(numbers[:], uid)
	h.Write(numbers[:])
	binary.LittleEndian.PutUint32(numbers[:4], handleType)
	binary.LittleEndian.PutUint32(numbers[4:], uint32(len(handle)))
	h.Write(numbers[:])
	h.Write(handle)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
