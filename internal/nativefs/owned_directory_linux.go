//go:build linux && (amd64 || arm64)

package nativefs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

type ownedNative struct {
	parent *Root
	chain  []ancestor
	name   string
}

func openOwnedDirectory(path string, create bool) (*OwnedDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrPath
	}
	name := filepath.Base(path)
	if validRelative(name) != nil {
		return nil, ErrPath
	}
	parent, err := openNativeRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	// The ordinary reader may capture physical aliases. A writable constructor
	// additionally refuses every symlink component before any mutation.
	strict, err := openat2(-100, filepath.Dir(path), oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, resolveNoMagic|resolveNoLinks)
	if err != nil {
		parent.close()
		return nil, err
	}
	st, err := statNative(strict)
	closeErr := strict.Close()
	if err != nil || closeErr != nil || !sameObject(st, parent.initial) {
		parent.close()
		return nil, ErrUnstable
	}
	if create {
		if err := syscall.Mkdirat(int(parent.root.Fd()), name, 0700); err != nil {
			parent.close()
			return nil, ErrPath
		}
	}
	child, err := parent.subroot(name)
	if err != nil {
		parent.close()
		return nil, err
	}
	if _, err := ownedIdentity(child); err != nil {
		child.close()
		parent.close()
		return nil, err
	}
	chain, err := ancestry(parent.root)
	if err != nil {
		child.close()
		parent.close()
		return nil, err
	}
	p := &Root{native: parent}
	n := &ownedNative{parent: p, chain: chain, name: name}
	r := &Root{native: child, anchor: p, owned: n}
	d := &OwnedDirectory{root: r, native: n}
	if err := n.guard(child); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func ownedIdentity(n *nativeRoot) ([32]byte, error) {
	var raw syscall.Stat_t
	if n == nil || n.guard() != nil || syscall.Fstat(int(n.root.Fd()), &raw) != nil {
		return [32]byte{}, ErrUnstable
	}
	if raw.Uid != uint32(os.Geteuid()) || raw.Mode&07777 != 0700 || raw.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return [32]byte{}, ErrPath
	}
	// Both device and mount numbers are runtime guards, never stored identity.
	mount, err := n.mountID()
	if err != nil {
		return [32]byte{}, err
	}
	var identity [32]byte
	if proof := n.ownedProof; proof != nil {
		if proof.uid != raw.Uid || proof.mount != mount {
			return [32]byte{}, ErrUnstable
		}
		identity = proof.identity
	} else {
		identity, err = durableLinuxOwnedIdentity(n, raw, mount)
		if err != nil {
			return [32]byte{}, err
		}
	}
	var after syscall.Stat_t
	if n.guard() != nil || syscall.Fstat(int(n.root.Fd()), &after) != nil || after.Dev != raw.Dev || after.Ino != raw.Ino || after.Uid != raw.Uid || after.Mode != raw.Mode {
		return [32]byte{}, ErrUnstable
	}
	if n.ownedProof == nil {
		n.ownedProof = &linuxOwnedRootProof{identity, raw.Uid, mount}
	}
	return identity, nil
}

// Caller holds the root and original parent mutexes. The full retained chain
// checks object identities. The selected parent additionally retains its change
// stamp: unrelated churn in that parent conservatively invalidates this writer.
func (o *ownedNative) guard(n *nativeRoot) error {
	if o == nil || o.parent == nil || o.parent.native == nil || n == nil {
		return ErrClosed
	}
	parent := o.parent.native
	chain, err := ancestry(parent.root)
	if err != nil {
		return err
	}
	defer closeAncestors(chain)
	if len(chain) != len(o.chain) {
		return ErrUnstable
	}
	for i, a := range o.chain {
		now, err := statNative(a.handle)
		if err != nil || !sameObject(now, a.initial) || !sameObject(chain[i].initial, a.initial) || i == 0 && (now != a.initial || chain[i].initial != a.initial) {
			return ErrUnstable
		}
	}
	f, st, err := parent.captureMode(o.name, false, true)
	if err != nil {
		return ErrUnstable
	}
	defer f.Close()
	now, err := statNative(n.root)
	if err != nil || st != n.initial || now != n.initial || st.kind() != KindDirectory {
		return ErrUnstable
	}
	_, err = ownedIdentity(n)
	return err
}

func (o *ownedNative) writeControl(n *nativeRoot, name string, data []byte) (failure error) {
	if err := o.guard(n); err != nil {
		return err
	}
	// Retain the same directory I/O handle BEFORE the known mutation changes
	// its stamp; post-mutation path reopening would correctly fail the guard.
	dir, err := n.readCaptured(n.root, n.initial)
	if err != nil {
		return err
	}
	defer func() {
		if dir.Close() != nil {
			failure = errors.Join(failure, ErrWrite)
		}
	}()
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return ErrPath
	}
	how := openHow{flags: uint64(syscall.O_WRONLY | syscall.O_CLOEXEC | syscall.O_CREAT | syscall.O_EXCL | syscall.O_NOFOLLOW), mode: 0600, resolve: resolveBeneath | resolveNoMagic | resolveNoLinks | resolveNoXdev}
	fd, _, errno := syscall.Syscall6(437, n.root.Fd(), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	runtime.KeepAlive(n.root)
	runtime.KeepAlive(p)
	runtime.KeepAlive(&how)
	if errno != 0 {
		return ErrPath
	}
	f := os.NewFile(fd, "owned-control")
	defer func() {
		if f.Close() != nil {
			failure = errors.Join(failure, ErrWrite)
		}
	}()
	written, writeErr := f.Write(data)
	syncErr := f.Sync()
	if writeErr != nil || written != len(data) || syncErr != nil {
		return ErrWrite
	}
	if err := ownedControlBinding(n, f, name, len(data)); err != nil {
		return err
	}
	// Synchronize the retained original directory, never a current pathname.
	if dir.Sync() != nil {
		return ErrWrite
	}
	// Only this successful owned mutation may refresh the directory stamp.
	selected, st, err := o.parent.native.captureMode(o.name, false, true)
	if err != nil {
		return ErrUnstable
	}
	defer selected.Close()
	now, err := statNative(n.root)
	if err != nil || !sameObject(st, n.initial) || now != st || st.kind() != KindDirectory {
		return ErrUnstable
	}
	n.initial = st
	return o.guard(n)
}

func ownedControlMetadata(n *nativeRoot, name string) (*os.File, stamp, error) {
	return n.captureMode(name, false, true)
}

func (o *ownedNative) close() error {
	var err error
	for _, a := range o.chain {
		err = errors.Join(err, a.handle.Close())
	}
	return errors.Join(err, o.parent.Close())
}
