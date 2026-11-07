//go:build windows && amd64

package nativefs

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func ownedLockFile(n *nativeRoot, name string, exclusive bool) (*os.File, error) {
	selected, st, err := n.capture(name, false, true)
	if err != nil {
		return nil, err
	}
	defer selected.Close()
	if st.kind() != KindRegular || st.links != 1 || st.size != 0 {
		return nil, ErrType
	}
	// A SAME-object empty-name open, never the old path. Shared readers allow
	// only READ sharing; an exclusive writer adds WRITE access and share0.
	// Metadata-only enumeration retains its existing all-sharing handles.
	u := winUnicode{}
	a := winAttributes{root: syscall.Handle(selected.Fd()), name: &u, attributes: winDontReparse}
	a.length = uint32(unsafe.Sizeof(a))
	access := uint32(1 | winReadAttrs | winSync)
	share := uint32(1)
	if exclusive {
		access |= 2
		share = 0
	}
	var handle syscall.Handle
	statusBlock := new(winIOStatus)
	status, _, _ := winReopen.Call(uintptr(unsafe.Pointer(&handle)), uintptr(access), uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(statusBlock)), uintptr(share), winSynchronous|winOpenReparse|winNoRecall|winNonDirectory)
	ok := winFinish(status, handle, statusBlock)
	runtime.KeepAlive(a)
	runtime.KeepAlive(u)
	runtime.KeepAlive(selected)
	runtime.KeepAlive(statusBlock)
	if !ok {
		if handle != 0 && handle != syscall.InvalidHandle {
			syscall.CloseHandle(handle)
		}
		if uint32(statusBlock.status) == 0xc0000043 || uint32(status) == 0xc0000043 {
			return nil, ErrBusy
		}
		return nil, ErrRead
	}
	f := os.NewFile(uintptr(handle), "owned-lease")
	if err := ownedControlBinding(n, f, name, 0); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// Windows share-denial is attached to this noninheritable original handle.
// Closing it below is the release; there is no PID or lock-file deletion.
func ownedUnlock(*os.File) error { return nil }
