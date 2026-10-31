//go:build windows && amd64

package nativefs

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// ABI/constants: Go SDK internal/syscall/windows/{types,at}_windows.go;
// ntifs.h NtCreateFile, FILE_*_INFORMATION and winioctl.h. This candidate is
// Windows Server 2022 amd64 / local NTFS only, NOT native qualification.
// All blocking native I/O belongs in the existing terminable worker.
var (
	winNT          = syscall.NewLazyDLL("ntdll.dll")
	winCreate      = winNT.NewProc("NtCreateFile")
	winReopen      = winNT.NewProc("NtOpenFile")
	winQueryFile   = winNT.NewProc("NtQueryInformationFile")
	winQueryVolume = winNT.NewProc("NtQueryVolumeInformationFile")
	winDosDevice   = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryDosDeviceW")
)

const (
	winSync         = 0x00100000
	winReadAttrs    = 0x80
	winDirectory    = 0x1
	winNonDirectory = 0x40
	winSynchronous  = 0x20
	winOpenReparse  = 0x00200000
	winNoRecall     = 0x00400000
	winDontReparse  = 0x1000
	winPending      = 0x103
)

type winUnicode struct {
	length, maximum uint16
	buffer          *uint16
}
type winAttributes struct {
	length        uint32
	root          syscall.Handle
	name          *winUnicode
	attributes    uint32
	security, qos uintptr
}
type winIOStatus struct{ status, information uintptr }
type winAncestor struct {
	handle  *os.File
	initial stamp
	name    string
}
type winSeparation struct {
	target *nativeRoot
	common int
}
type nativeRoot struct {
	root       *os.File
	initial    stamp
	volume     string        // captured kernel volume name, never a current DOS alias
	chain      []winAncestor // volume root through the physical root, all owned
	external   *winSeparation
	parent     *nativeRoot
	parentName string
}

// Synchronous non-alertable handles serialize native I/O. If an API does return
// PENDING, keep EVERY request object alive until completion. A failed wait on an
// owned valid handle is an unrecoverable worker invariant violation: terminate,
// never unwind/free a buffer still owned by the kernel. No detached goroutines,
// cancellation loops, or parent-side blocking reads are introduced.
func winFinish(status uintptr, h syscall.Handle, io *winIOStatus) bool {
	if uint32(status) == winPending {
		if h == 0 || h == syscall.InvalidHandle {
			os.Exit(2)
		}
		s, e := syscall.WaitForSingleObject(h, syscall.INFINITE)
		if e != nil || s != syscall.WAIT_OBJECT_0 {
			os.Exit(2)
		}
		status = io.status
	}
	return uint32(status) == 0
}
func winOpen(parent *os.File, name string, access, options uint32, noReparse bool) (*os.File, error) {
	var units []uint16
	if name != "" {
		var e error
		units, e = syscall.UTF16FromString(name)
		if e != nil || len(units) > 4097 {
			return nil, ErrPath
		}
	}
	u := winUnicode{}
	if len(units) > 0 {
		u.length = uint16((len(units) - 1) * 2)
		u.maximum = uint16(len(units) * 2)
		u.buffer = &units[0]
	}
	a := winAttributes{name: &u}
	a.length = uint32(unsafe.Sizeof(a))
	if parent != nil {
		a.root = syscall.Handle(parent.Fd())
	}
	// No OBJ_CASE_INSENSITIVE: exact spelling is additionally checked on the
	// selected descriptor, preventing short-name and case alias admission.
	if noReparse {
		a.attributes = winDontReparse
	}
	var h syscall.Handle
	io := new(winIOStatus)
	var status uintptr
	if name == "" {
		if parent == nil {
			return nil, ErrPath
		}
		// Match the SDK's same-object empty-name NtOpenFile route exactly;
		// do not rely on create-disposition behavior for a non-directory root.
		status, _, _ = winReopen.Call(uintptr(unsafe.Pointer(&h)), uintptr(access|winReadAttrs|winSync), uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(io)), 7, uintptr(options|winSynchronous|winOpenReparse|winNoRecall))
	} else {
		status, _, _ = winCreate.Call(uintptr(unsafe.Pointer(&h)), uintptr(access|winReadAttrs|winSync), uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(io)), 0, 0, 7, 1, uintptr(options|winSynchronous|winOpenReparse|winNoRecall), 0, 0)
	}
	ok := winFinish(status, h, io)
	runtime.KeepAlive(units)
	runtime.KeepAlive(u)
	runtime.KeepAlive(a)
	runtime.KeepAlive(parent)
	runtime.KeepAlive(io)
	if !ok {
		if h != 0 && h != syscall.InvalidHandle {
			syscall.CloseHandle(h)
		}
		return nil, ErrPath
	}
	return os.NewFile(uintptr(h), "native-owned"), nil
}
func winQuery(f *os.File, volume bool, class uint32, b []byte, min int) error {
	if f == nil || len(b) == 0 {
		return ErrRead
	}
	io := new(winIOStatus)
	proc := winQueryFile
	if volume {
		proc = winQueryVolume
	}
	status, _, _ := proc.Call(f.Fd(), uintptr(unsafe.Pointer(io)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(class))
	ok := winFinish(status, syscall.Handle(f.Fd()), io)
	runtime.KeepAlive(f)
	runtime.KeepAlive(b)
	runtime.KeepAlive(io)
	if !ok || io.information < uintptr(min) || io.information > uintptr(len(b)) {
		return ErrRead
	}
	return nil
}
func winASCII16(b []byte) (string, error) {
	if len(b)%2 != 0 || len(b) > 8192 {
		return "", ErrPath
	}
	out := make([]byte, len(b)/2)
	for i := range out {
		u := binary.LittleEndian.Uint16(b[2*i:])
		if u < 32 || u > 126 {
			return "", ErrPath
		}
		out[i] = byte(u)
	}
	return string(out), nil
}
func winName(f *os.File) (string, error) {
	b := make([]byte, 8200)
	if winQuery(f, false, 9, b, 4) != nil {
		return "", ErrRead
	}
	n := int(binary.LittleEndian.Uint32(b))
	if n > len(b)-4 {
		return "", ErrPath
	}
	return winASCII16(b[4 : 4+n])
}
func winExactName(f *os.File, component string) error {
	name, e := winName(f)
	if e != nil {
		return e
	}
	i := strings.LastIndexByte(name, '\\')
	if i < 0 || name[i+1:] != component {
		return ErrPath
	}
	return nil
}
func winVolumeName(drive string) (string, error) {
	p, _ := syscall.UTF16PtrFromString(drive)
	b := make([]uint16, 4096)
	n, _, _ := winDosDevice.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	runtime.KeepAlive(p)
	if n == 0 || n > uintptr(len(b)) {
		return "", ErrUnavailable
	}
	// QueryDosDevice can return old mappings as additional strings; only the
	// first (current) mapping is captured. Never reopen the DOS drive alias.
	name := syscall.UTF16ToString(b[:n])
	const prefix = `\Device\HarddiskVolume`
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) || len(name) > len(prefix)+10 {
		return "", ErrUnavailable
	}
	for _, c := range name[len(prefix):] {
		if c < '0' || c > '9' {
			return "", ErrUnavailable
		}
	}
	return name, nil
}
func winQualifyVolume(f *os.File) error {
	var device [8]byte // FILE_FS_DEVICE_INFORMATION, FileFsDeviceInformation=4
	if winQuery(f, true, 4, device[:], 8) != nil {
		return ErrUnavailable
	}
	// Remote providers and every filesystem except NTFS are unqualified.
	b := make([]byte, 128)
	if winQuery(f, true, 5, b, 20) != nil {
		return ErrUnavailable
	}
	return winVolumeReply(device[:], b)
}
func prepareNative() error {
	for _, p := range []*syscall.LazyProc{winCreate, winReopen, winQueryFile, winQueryVolume, winDosDevice} {
		if p.Find() != nil {
			return ErrUnavailable
		}
	}
	return nil
}
func openNativeRoot(path string) (*nativeRoot, error) {
	drive, parts, e := winRootPath(path)
	if e != nil {
		return nil, e
	}
	if e = prepareNative(); e != nil {
		return nil, e
	}
	volume, e := winVolumeName(drive)
	if e != nil {
		return nil, e
	}
	// The ONLY absolute native open is a synthesized trusted OS volume DIRECTORY
	// root. No target component reaches this call. System namespace ownership is
	// assumed; a compromised kernel/privileged fake device is outside the model.
	f, e := winOpen(nil, volume+`\`, 0, winDirectory, true)
	if e != nil {
		return nil, ErrUnavailable
	}
	if e = winQualifyVolume(f); e != nil {
		f.Close()
		return nil, e
	}
	r := &nativeRoot{volume: volume}
	s, e := statNative(f)
	if e != nil || s.kind() != KindDirectory {
		f.Close()
		return nil, ErrUnavailable
	}
	r.chain = append(r.chain, winAncestor{handle: f, initial: s})
	for _, p := range parts {
		f, e = winChild(r.chain[len(r.chain)-1].handle, p, r.chain[0].initial.dev)
		if e != nil {
			r.close()
			return nil, e
		}
		s, e = statNative(f)
		if e != nil || s.kind() != KindDirectory {
			f.Close()
			r.close()
			return nil, ErrType
		}
		r.chain = append(r.chain, winAncestor{f, s, p})
	}
	r.root = r.chain[len(r.chain)-1].handle
	r.initial = r.chain[len(r.chain)-1].initial
	if e = r.guard(); e != nil {
		r.close()
		return nil, e
	}
	return r, nil
}
func (r *nativeRoot) close() error {
	var e error
	for _, a := range r.chain {
		e = errors.Join(e, a.handle.Close())
	}
	return e
}
func statNative(f *os.File) (stamp, error) {
	if f == nil {
		return stamp{}, ErrRead
	}
	var info syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &info) != nil {
		return stamp{}, ErrRead
	}
	var basic [40]byte
	var standard [24]byte
	if winQuery(f, false, 4, basic[:], 40) != nil || winQuery(f, false, 5, standard[:], 24) != nil {
		return stamp{}, ErrRead
	}
	attrs := binary.LittleEndian.Uint32(basic[32:])
	// Device, offline, recall-on-open/data and encrypted/provider-dependent data
	// do not enter this ordinary-file candidate. Unknown reparses are metadata
	// only and are rejected by the reparse decoder before any content transition.
	if attrs&(0x40|0x1000|0x4000|0x40000|0x400000) != 0 || standard[20] != 0 {
		return stamp{}, ErrType
	}
	if info.FileIndexHigh == 0 && info.FileIndexLow == 0 || binary.LittleEndian.Uint32(standard[16:]) == 0 {
		return stamp{}, ErrUnavailable
	}
	mode := uint32(0100000)
	if standard[21] != 0 && attrs&0x400 == 0 {
		// Case-sensitive NTFS directories can contain colliding portable names.
		// Do not pretend ASCII folding is a sufficient mapping proof. This
		// query/flag is supported by the Windows Server 2022 candidate only;
		// unknown/unsupported answers fail closed before directory reads.
		var sensitive [4]byte
		if winQuery(f, false, 71, sensitive[:], 4) != nil || binary.LittleEndian.Uint32(sensitive[:]) != 0 {
			return stamp{}, ErrUnavailable
		}
		mode = 0040000
	}
	if attrs&0x400 != 0 {
		mode = 0120000
	}
	return stamp{dev: uint64(info.VolumeSerialNumber), ino: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow), mode: mode, size: int64(binary.LittleEndian.Uint64(standard[8:])), mtSec: int64(binary.LittleEndian.Uint64(basic[16:])), ctSec: int64(binary.LittleEndian.Uint64(basic[24:])), links: uint64(binary.LittleEndian.Uint32(standard[16:]))}, nil
}
func winChild(parent *os.File, name string, dev uint64) (*os.File, error) {
	if winComponent(name) != nil {
		return nil, ErrPath
	}
	// One component, no separator/ADS/DOS namespace, relative to an already
	// captured actual NTFS directory. OPEN_REPARSE_POINT bypasses its processing.
	// NTFS children cannot be object-manager device/pipe/volume objects. This
	// filesystem namespace fact is the PRE-open guard, not a post-open type test.
	f, e := winOpen(parent, name, 0, 0, false)
	if e != nil {
		return nil, e
	}
	s, e := statNative(f)
	if e != nil || s.dev != dev || winExactName(f, name) != nil {
		f.Close()
		return nil, ErrPath
	}
	return f, nil
}
func winLink(f *os.File) (string, error) {
	// Metadata-only FSCTL on the captured NTFS reparse object, never an arbitrary
	// device experiment. FILE_OPEN_REPARSE_POINT prevented provider traversal.
	b := make([]byte, 16384)
	var n uint32
	e := syscall.DeviceIoControl(syscall.Handle(f.Fd()), 0x900a8, nil, 0, &b[0], uint32(len(b)), &n, nil)
	runtime.KeepAlive(f)
	runtime.KeepAlive(b)
	if e != nil || n > uint32(len(b)) {
		return "", ErrPath
	}
	return winReparseTarget(b[:n])
}

// Retain the intermediate directory capabilities until the entire metadata
// selection is checked. Unlike a naive component loop, a moved intermediate
// cannot silently turn later component selection into unobserved outside I/O.
func (r *nativeRoot) captureAttempt(name string, follow, input bool) (*os.File, stamp, string, error) {
	if name == "." {
		f, e := winOpen(r.root, "", 0, winDirectory, true)
		if e != nil {
			return nil, stamp{}, "", e
		}
		s, e := statNative(f)
		if e != nil {
			f.Close()
			return nil, stamp{}, "", e
		}
		return f, s, "", nil
	}
	if validRelative(name) != nil {
		return nil, stamp{}, "", ErrPath
	}
	parts := strings.Split(name, "/")
	for _, p := range parts {
		if winComponent(p) != nil {
			return nil, stamp{}, "", ErrPath
		}
	}
	trail := []winAncestor{{handle: r.root, initial: r.initial}}
	defer func() {
		for _, a := range trail[1:] {
			a.handle.Close()
		}
	}()
	for i, p := range parts {
		f, e := winChild(trail[len(trail)-1].handle, p, r.initial.dev)
		if e != nil {
			return nil, stamp{}, "", e
		}
		s, e := statNative(f)
		if e != nil {
			f.Close()
			return nil, stamp{}, "", e
		}
		if e = winCheckTrail(trail); e != nil {
			f.Close()
			return nil, stamp{}, "", e
		}
		last := i == len(parts)-1
		if s.kind() == KindLink && (!last || follow) {
			if input || r.parent != nil || r.external != nil {
				f.Close()
				return nil, stamp{}, "", ErrPath
			}
			target, e := winLink(f)
			f.Close()
			if e != nil {
				return nil, stamp{}, "", e
			}
			next, e := winLinkPath(parts[:i], target, parts[i+1:])
			return nil, stamp{}, next, e
		}
		if last {
			if e = r.guard(); e != nil {
				f.Close()
				return nil, stamp{}, "", e
			}
			return f, s, "", nil
		}
		if s.kind() != KindDirectory {
			f.Close()
			return nil, stamp{}, "", ErrType
		}
		trail = append(trail, winAncestor{f, s, p})
	}
	return nil, stamp{}, "", ErrPath
}
func winCheckTrail(trail []winAncestor) error {
	for i, a := range trail {
		now, e := statNative(a.handle)
		if e != nil || !winSame(now, a.initial) {
			return ErrUnstable
		}
		if i == 0 {
			continue
		}
		if now != a.initial {
			return ErrUnstable
		}
		f, e := winChild(trail[i-1].handle, a.name, trail[0].initial.dev)
		if e != nil {
			return ErrUnstable
		}
		bound, e := statNative(f)
		f.Close()
		if e != nil || bound != a.initial {
			return ErrUnstable
		}
	}
	return nil
}
func (r *nativeRoot) capture(name string, follow, input bool) (*os.File, stamp, error) {
	for hops := 0; hops < 40; hops++ {
		f, s, next, e := r.captureAttempt(name, follow, input)
		if e != nil || next == "" {
			return f, s, e
		}
		name = next
	}
	return nil, stamp{}, ErrLimit
}
func (r *nativeRoot) lookup(name string, follow bool) (*object, error) {
	return r.lookupMode(name, follow, true, false)
}
func (r *nativeRoot) lookupMode(name string, follow, content, input bool) (*object, error) {
	if e := r.guard(); e != nil {
		return nil, e
	}
	f, s, e := r.capture(name, follow, input)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	o := &object{initial: s}
	switch s.kind() {
	case KindLink:
		o.target, e = winLink(f)
		if e != nil {
			return nil, e
		}
		return o, nil
	case KindRegular:
		if !content {
			return o, nil
		}
		if (input || r.parent != nil || r.external != nil) && s.links != 1 {
			return nil, ErrPath
		}
	case KindDirectory:
	default:
		return nil, ErrType
	}
	// Reobserve the root-relative binding before granting read access, while
	// retaining the ORIGINAL metadata handle for the actual reopen below.
	if e = r.binding(name, s, input); e != nil {
		return nil, e
	}
	options := uint32(winNonDirectory)
	if s.kind() == KindDirectory {
		options = winDirectory
	}
	// Empty-name handle-relative reopen selects the SAME object, even after a
	// rename. It is not a second pathname identity. READ_DATA/LIST_DIRECTORY is
	// requested only after metadata type, volume and authority checks above.
	o.handle, e = winOpen(f, "", 1, options, true)
	if e != nil {
		return nil, e
	}
	now, e := statNative(o.handle)
	if e != nil || now != s {
		o.close()
		return nil, ErrUnstable
	}
	if e = r.validateReadForKind(o.handle, s, input); e != nil {
		o.close()
		return nil, e
	}
	return o, nil
}
func (r *nativeRoot) validateReadForKind(f *os.File, s stamp, input bool) error {
	if e := r.guard(); e != nil {
		return e
	}
	now, e := statNative(f)
	if e != nil || now != s {
		return ErrUnstable
	}
	if s.kind() == KindRegular && (input || r.parent != nil || r.external != nil) && now.links != 1 {
		return ErrUnstable
	}
	return nil
}
func (r *nativeRoot) validateRead(f *os.File, s stamp, input bool) error {
	return r.validateReadForKind(f, s, input)
}
func (r *nativeRoot) check(name string, initial stamp) error { return r.binding(name, initial, false) }
func (r *nativeRoot) binding(name string, initial stamp, input bool) error {
	if e := r.guard(); e != nil {
		return e
	}
	f, s, e := r.capture(name, true, input)
	if e != nil {
		return ErrUnstable
	}
	defer f.Close()
	if s != initial {
		return ErrUnstable
	}
	return nil
}
