//go:build windows && amd64

package nativefs

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

var ownedAdvapi = syscall.NewLazyDLL("advapi32.dll")
var ownedConvertSD = ownedAdvapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
var ownedGetSecurity = ownedAdvapi.NewProc("GetSecurityInfo")
var ownedGetControl = ownedAdvapi.NewProc("GetSecurityDescriptorControl")

type ownedNative struct {
	parent  *Root
	initial stamp
	name    string
}

func ownedUserSID() (string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", ErrUnavailable
	}
	defer token.Close()
	var user struct {
		info syscall.Tokenuser
		sid  [68]byte
	}
	var needed uint32
	if syscall.GetTokenInformation(token, syscall.TokenUser, (*byte)(unsafe.Pointer(&user)), uint32(unsafe.Sizeof(user)), &needed) != nil || user.info.User.Sid == nil {
		return "", ErrUnavailable
	}
	sid, err := user.info.User.Sid.String()
	runtime.KeepAlive(&user)
	if err != nil {
		return "", ErrUnavailable
	}
	return sid, nil
}

func ownedSecurityDescriptor() (unsafe.Pointer, error) {
	sid, err := ownedUserSID()
	if err != nil {
		return nil, err
	}
	text, err := syscall.UTF16PtrFromString("O:" + sid + "D:P(A;;GA;;;" + sid + ")")
	if err != nil || ownedConvertSD.Find() != nil {
		return nil, ErrUnavailable
	}
	var sd unsafe.Pointer
	ok, _, _ := ownedConvertSD.Call(uintptr(unsafe.Pointer(text)), 1, uintptr(unsafe.Pointer(&sd)), 0)
	runtime.KeepAlive(text)
	if ok == 0 || sd == nil {
		return nil, ErrUnavailable
	}
	return sd, nil
}

// Every create is relative to a previously typed NTFS directory and exclusive.
// The fresh child gets a protected current-user-only owner/DACL. No ambient
// inheritance, security-setting change or arbitrary NT path is accepted.
func ownedCreate(parent *os.File, name string, directory bool) (*os.File, error) {
	return ownedCreateAccess(parent, name, directory, 0)
}

func ownedCreateAccess(parent *os.File, name string, directory bool, extra uint32) (*os.File, error) {
	if parent == nil || winComponent(name) != nil {
		return nil, ErrPath
	}
	parentWrite, err := winOpen(parent, "", 0x6|0x20000, winDirectory, true)
	if err != nil {
		return nil, err
	}
	defer parentWrite.Close()
	before, err := statNative(parent)
	opened, openedErr := statNative(parentWrite)
	if err != nil || openedErr != nil || !winSame(before, opened) || before.kind() != KindDirectory {
		return nil, ErrUnstable
	}
	sd, err := ownedSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(sd)))
	units, err := syscall.UTF16FromString(name)
	if err != nil {
		return nil, ErrPath
	}
	u := winUnicode{length: uint16((len(units) - 1) * 2), maximum: uint16(len(units) * 2), buffer: &units[0]}
	a := winAttributes{root: syscall.Handle(parentWrite.Fd()), name: &u, attributes: winDontReparse, security: uintptr(sd)}
	a.length = uint32(unsafe.Sizeof(a))
	options := uint32(winSynchronous | winOpenReparse | winNonDirectory)
	access := uint32(0x40000000 | winReadAttrs | winSync | 0x20000 | extra)
	if directory {
		// DIRECTORY_FILE + NO_RECALL is invalid on the admitted NTFS baseline.
		// This is CREATE of a new typed directory, not opening unknown content.
		options = winSynchronous | winOpenReparse | winDirectory
		access = winReadAttrs | winSync | 0x20000
	} else {
		options |= winNoRecall
	}
	var handle syscall.Handle
	statusBlock := new(winIOStatus)
	status, _, _ := winCreate.Call(uintptr(unsafe.Pointer(&handle)), uintptr(access), uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(statusBlock)), 0, 0, 7, 2, uintptr(options), 0, 0)
	ok := winFinish(status, handle, statusBlock)
	runtime.KeepAlive(units)
	runtime.KeepAlive(u)
	runtime.KeepAlive(a)
	runtime.KeepAlive(sd)
	runtime.KeepAlive(parentWrite)
	runtime.KeepAlive(statusBlock)
	if !ok {
		if handle != 0 && handle != syscall.InvalidHandle {
			syscall.CloseHandle(handle)
		}
		return nil, ErrPath
	}
	f := os.NewFile(uintptr(handle), "owned-created")
	st, err := statNative(f)
	want := KindRegular
	if directory {
		want = KindDirectory
	}
	if err != nil || st.kind() != want || st.dev != before.dev || winExactName(f, name) != nil || !directory && st.links != 1 {
		f.Close()
		return nil, ErrUnstable
	}
	if _, err := ownedCheckSecurity(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func ownedCheckSecurity(f *os.File) (string, error) {
	want, err := ownedUserSID()
	if err != nil || ownedGetSecurity.Find() != nil || ownedGetControl.Find() != nil {
		return "", ErrUnavailable
	}
	var owner *syscall.SID
	var dacl, sd unsafe.Pointer
	status, _, _ := ownedGetSecurity.Call(f.Fd(), 1, 5, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&sd)))
	runtime.KeepAlive(f)
	if status != 0 || sd == nil {
		return "", ErrUnavailable
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(sd)))
	if owner == nil || dacl == nil {
		return "", ErrPath
	}
	got, err := owner.String()
	if err != nil || got != want {
		return "", ErrPath
	}
	var control uint16
	var revision uint32
	ok, _, _ := ownedGetControl.Call(uintptr(sd), uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if ok == 0 || control&0x1004 != 0x1004 {
		return "", ErrPath
	}
	acl := (*struct {
		Revision, Reserved byte
		Size, Count, Pad   uint16
	})(dacl)
	if acl.Count != 1 || acl.Size < 24 {
		return "", ErrPath
	}
	ace := unsafe.Add(dacl, 8)
	aceSize := *(*uint16)(unsafe.Add(ace, 2))
	if *(*byte)(ace) != 0 || *(*byte)(unsafe.Add(ace, 1)) != 0 || aceSize < 16 || uint32(aceSize)+8 > uint32(acl.Size) {
		return "", ErrPath
	}
	mask := *(*uint32)(unsafe.Add(ace, 4))
	if mask != 0x10000000 && mask != 0x1f01ff {
		return "", ErrPath
	}
	principal, err := (*syscall.SID)(unsafe.Add(ace, 8)).String()
	if err != nil || principal != want {
		return "", ErrPath
	}
	return want, nil
}

func openOwnedDirectory(path string, create bool) (*OwnedDirectory, error) {
	_, parts, err := winRootPath(path)
	if err != nil || len(parts) == 0 {
		return nil, ErrPath
	}
	name := parts[len(parts)-1]
	parent, err := openNativeRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if create {
		f, err := ownedCreate(parent.root, name, true)
		if err != nil {
			parent.close()
			return nil, err
		}
		if f.Close() != nil {
			parent.close()
			return nil, ErrWrite
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
	initial, err := statNative(parent.root)
	if err != nil {
		child.close()
		parent.close()
		return nil, err
	}
	p := &Root{native: parent}
	n := &ownedNative{parent: p, initial: initial, name: name}
	r := &Root{native: child, anchor: p, owned: n}
	d := &OwnedDirectory{root: r, native: n}
	if err := n.guard(child); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func ownedIdentity(n *nativeRoot) ([32]byte, error) {
	if n == nil || n.guard() != nil {
		return [32]byte{}, ErrUnstable
	}
	f, err := winOpen(n.root, "", 0x20000, winDirectory, true)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	st, err := statNative(f)
	if err != nil || !winSame(st, n.initial) || st.kind() != KindDirectory {
		return [32]byte{}, ErrUnstable
	}
	sid, err := ownedCheckSecurity(f)
	if err != nil {
		return [32]byte{}, err
	}
	var raw [16]byte
	binary.LittleEndian.PutUint64(raw[0:8], st.dev)
	binary.LittleEndian.PutUint64(raw[8:16], st.ino)
	h := sha256.New()
	h.Write(raw[:])
	h.Write([]byte(n.volume))
	h.Write([]byte{0})
	h.Write([]byte(sid))
	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id, nil
}

func (o *ownedNative) guard(n *nativeRoot) error {
	if o == nil || o.parent == nil || o.parent.native == nil || n == nil {
		return ErrClosed
	}
	parent := o.parent.native
	if parent.guard() != nil || n.guard() != nil {
		return ErrUnstable
	}
	st, err := statNative(parent.root)
	if err != nil || st != o.initial {
		return ErrUnstable
	}
	f, selected, err := parent.capture(o.name, false, true)
	if err != nil {
		return ErrUnstable
	}
	defer f.Close()
	current, err := statNative(n.root)
	if err != nil || selected != n.initial || current != n.initial || selected.kind() != KindDirectory {
		return ErrUnstable
	}
	_, err = ownedIdentity(n)
	return err
}

func (o *ownedNative) writeControl(n *nativeRoot, name string, data []byte) (failure error) {
	if err := o.guard(n); err != nil {
		return err
	}
	f, err := ownedCreate(n.root, name, false)
	if err != nil {
		return err
	}
	defer func() {
		if f.Close() != nil {
			failure = errors.Join(failure, ErrWrite)
		}
	}()
	written, writeErr := f.Write(data)
	syncErr := f.Sync()
	if written != len(data) || writeErr != nil || syncErr != nil {
		return ErrWrite
	}
	if err := ownedControlBinding(n, f, name, len(data)); err != nil {
		return err
	}
	// Flush of the regular file is checked. This is not a claim that Windows
	// supports directory FlushFileBuffers or physical-power-loss durability.
	current, err := statNative(n.root)
	if err != nil || !winSame(current, n.initial) || current.kind() != KindDirectory {
		return ErrUnstable
	}
	selected, st, err := o.parent.native.capture(o.name, false, true)
	if err != nil {
		return ErrUnstable
	}
	defer selected.Close()
	if current != st {
		return ErrUnstable
	}
	n.initial = st
	n.chain[len(n.chain)-1].initial = st
	return o.guard(n)
}

func ownedControlMetadata(n *nativeRoot, name string) (*os.File, stamp, error) {
	// A single generated component under the retained directory. Ordinary
	// capture would reject its expected pre-creation directory stamp; the
	// owned transaction revalidates root/ancestry before refreshing that stamp.
	if n == nil || !controlName(name) {
		return nil, stamp{}, ErrPath
	}
	f, err := winChild(n.root, name, n.initial.dev)
	if err != nil {
		return nil, stamp{}, err
	}
	st, err := statNative(f)
	if err != nil {
		f.Close()
		return nil, stamp{}, err
	}
	return f, st, nil
}

func (o *ownedNative) close() error {
	if o == nil || o.parent == nil {
		return ErrClosed
	}
	return errors.Join(o.parent.Close())
}
