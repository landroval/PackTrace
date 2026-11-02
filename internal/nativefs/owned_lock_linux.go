//go:build linux && (amd64 || arm64)

package nativefs

import (
	"errors"
	"os"
	"syscall"
)

func ownedLockFile(n *nativeRoot, name string, exclusive bool) (*os.File, error) {
	path, st, err := n.captureMode(name, false, true)
	if err != nil {
		return nil, err
	}
	defer path.Close()
	if st.kind() != KindRegular || st.links != 1 || st.size != 0 {
		return nil, ErrType
	}
	f, err := n.readCaptured(path, st)
	if err != nil {
		return nil, err
	}
	kind := syscall.LOCK_SH | syscall.LOCK_NB
	if exclusive {
		kind = syscall.LOCK_EX | syscall.LOCK_NB
	}
	if err := syscall.Flock(int(f.Fd()), kind); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrBusy
		}
		return nil, ErrRead
	}
	if err := ownedControlBinding(n, f, name, 0); err != nil {
		return nil, errors.Join(err, ownedUnlock(f), f.Close())
	}
	return f, nil
}

func ownedUnlock(f *os.File) error {
	if syscall.Flock(int(f.Fd()), syscall.LOCK_UN) != nil {
		return ErrRead
	}
	return nil
}
