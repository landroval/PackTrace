//go:build linux && (amd64 || arm64)

package nativefs

import (
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

func ownedCreatePath(n *nativeRoot, name string, directory bool) (*os.File, error) {
	return ownedCreatePathMode(n, name, directory, true)
}
func ownedCreatePathMode(n *nativeRoot, name string, directory, durable bool) (*os.File, error) {
	parentName, leaf := ".", name
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		parentName, leaf = name[:i], name[i+1:]
	}
	parent, e := n.captureMetadata(parentName)
	if e != nil {
		return nil, e
	}
	if parent.initial.kind() != KindDirectory {
		parent.close()
		return nil, ErrType
	}
	dir, e := n.readCaptured(parent.handle, parent.initial)
	parent.close()
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	if directory {
		e := syscall.Mkdirat(int(dir.Fd()), leaf, 0700)
		if e != nil && e != syscall.EEXIST {
			return nil, ErrWrite
		}
		f, e := openat2(int(dir.Fd()), leaf, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, resolveBeneath|resolveNoMagic|resolveNoLinks|resolveNoXdev)
		if e != nil {
			return nil, e
		}
		var st syscall.Stat_t
		if syscall.Fstat(int(f.Fd()), &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 {
			f.Close()
			return nil, ErrPath
		}
		if durable && dir.Sync() != nil {
			f.Close()
			return nil, ErrWrite
		}
		return f, nil
	}
	p, e := syscall.BytePtrFromString(leaf)
	if e != nil {
		return nil, ErrPath
	}
	how := openHow{flags: uint64(syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_CREAT | syscall.O_EXCL | syscall.O_NOFOLLOW), mode: 0600, resolve: resolveBeneath | resolveNoMagic | resolveNoLinks | resolveNoXdev}
	fd, _, errno := syscall.Syscall6(437, dir.Fd(), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	runtime.KeepAlive(dir)
	runtime.KeepAlive(p)
	runtime.KeepAlive(how)
	if errno != 0 {
		return nil, ErrPath
	}
	f := os.NewFile(fd, "owned-stream")
	st, e := statNative(f)
	if e != nil || st.kind() != KindRegular || st.links != 1 {
		f.Close()
		return nil, ErrUnstable
	}
	if durable && dir.Sync() != nil {
		f.Close()
		return nil, ErrWrite
	}
	return f, nil
}

func (o *ownedNative) refresh(n *nativeRoot) error {
	selected, st, e := o.parent.native.captureMode(o.name, false, true)
	if e != nil {
		return ErrUnstable
	}
	defer selected.Close()
	now, e := statNative(n.root)
	if e != nil || !sameObject(st, n.initial) || now != st || st.kind() != KindDirectory {
		return ErrUnstable
	}
	n.initial = st
	return o.guard(n)
}
