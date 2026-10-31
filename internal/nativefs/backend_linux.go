//go:build linux && (amd64 || arm64)

package nativefs

import (
	"bufio"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Linux UAPI: include/uapi/linux/{openat2.h,fcntl.h}; openat2 is syscall 437
// on the two supported Linux architectures. No newer OPENAT2_REGULAR assumption.
const (
	oPath          = 0x200000
	resolveNoXdev  = 0x01
	resolveNoMagic = 0x02
	resolveNoLinks = 0x04
	resolveBeneath = 0x08
	procSuperMagic = 0x9fa0
)

type openHow struct{ flags, mode, resolve uint64 }
type nativeRoot struct {
	root, procFD *os.File
	initial      stamp
	external     *separation
	parent       *nativeRoot
	parentName   string
}

func openat2(dir int, name string, flags int, resolve uint64) (*os.File, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, ErrPath
	}
	how := openHow{flags: uint64(flags), resolve: resolve}
	fd, _, e := syscall.Syscall6(437, uintptr(dir), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	runtime.KeepAlive(p)
	runtime.KeepAlive(&how)
	if e != 0 {
		return nil, ErrPath
	}
	return os.NewFile(fd, "native-owned"), nil
}
func procDescriptors() (*os.File, error) {
	// Bootstrap only from the system procfs namespace, never a target path. Verify
	// filesystem type before following proc's PID/fd entries. Fail without fallback.
	fd, err := syscall.Open("/proc", oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	proc := os.NewFile(uintptr(fd), "own-proc")
	defer proc.Close()
	var fs syscall.Statfs_t
	if syscall.Fstatfs(fd, &fs) != nil || uint64(fs.Type) != procSuperMagic {
		return nil, ErrUnavailable
	}
	f, err := openat2(fd, strconv.Itoa(os.Getpid())+"/fd", oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, resolveBeneath|resolveNoMagic|resolveNoXdev)
	if err != nil {
		return nil, ErrUnavailable
	}
	return f, nil
}
func prepareNative() error {
	f, err := procDescriptors()
	if err == nil {
		err = f.Close()
	}
	return err
}
func openNativeRoot(path string) (*nativeRoot, error) {
	proc, err := procDescriptors()
	if err != nil {
		return nil, err
	}
	root, err := openat2(-100, path, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, resolveNoMagic)
	if err != nil {
		proc.Close()
		return nil, err
	}
	s, err := statNative(root)
	if err != nil || s.kind() != KindDirectory {
		proc.Close()
		root.Close()
		return nil, ErrType
	}
	// procfs/sysfs and other pseudo-filesystems are not investigation roots. The
	// unqualified candidate admits local ext4, XFS, Btrfs, tmpfs and overlayfs
	// fixture profiles; other filesystems are explicit unavailable gaps.
	var fs syscall.Statfs_t
	if syscall.Fstatfs(int(root.Fd()), &fs) != nil {
		proc.Close()
		root.Close()
		return nil, ErrUnavailable
	}
	switch uint64(fs.Type) {
	case 0xef53, 0x58465342, 0x9123683e, 0x01021994, 0x794c7630:
	default:
		proc.Close()
		root.Close()
		return nil, ErrUnavailable
	}
	return &nativeRoot{root: root, procFD: proc, initial: s}, nil
}
func (r *nativeRoot) close() error {
	if r.external != nil {
		r.external.close()
	}
	return errors.Join(r.root.Close(), r.procFD.Close())
}
func statNative(f *os.File) (stamp, error) {
	var s syscall.Stat_t
	if f == nil {
		return stamp{}, ErrRead
	}
	err := syscall.Fstat(int(f.Fd()), &s)
	runtime.KeepAlive(f)
	if err != nil {
		return stamp{}, ErrRead
	}
	return stamp{dev: uint64(s.Dev), ino: s.Ino, mode: s.Mode, size: s.Size, mtSec: s.Mtim.Sec, mtNS: s.Mtim.Nsec, ctSec: s.Ctim.Sec, ctNS: s.Ctim.Nsec, links: uint64(s.Nlink)}, nil
}
func (r *nativeRoot) capture(name string, follow bool) (*os.File, stamp, error) {
	return r.captureMode(name, follow, false)
}
func (r *nativeRoot) captureMode(name string, follow, input bool) (*os.File, stamp, error) {
	flags := oPath | syscall.O_CLOEXEC
	if !follow {
		flags |= syscall.O_NOFOLLOW
	}
	resolve := uint64(resolveBeneath | resolveNoMagic | resolveNoXdev)
	if input || r.parent != nil || r.external != nil {
		resolve |= resolveNoLinks
	}
	f, err := openat2(int(r.root.Fd()), name, flags, resolve)
	if err != nil {
		return nil, stamp{}, err
	}
	s, err := statNative(f)
	if err != nil {
		f.Close()
		return nil, stamp{}, err
	}
	return f, s, nil
}
func readlinkHandle(f *os.File) (string, error) {
	// Empty-path readlinkat on an O_PATH|O_NOFOLLOW symlink refers to that exact
	// symlink, not a later directory entry at its old name (Linux >= 2.6.39).
	empty := []byte{0}
	buf := make([]byte, 4097)
	n, _, e := syscall.Syscall6(syscall.SYS_READLINKAT, f.Fd(), uintptr(unsafe.Pointer(&empty[0])), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	runtime.KeepAlive(f)
	runtime.KeepAlive(empty)
	if e != 0 || n == 0 || n > 4096 {
		return "", ErrPath
	}
	return string(buf[:n]), nil
}
func (r *nativeRoot) lookup(name string, follow bool) (*object, error) {
	return r.lookupMode(name, follow, true, false)
}
func (r *nativeRoot) lookupMode(name string, follow, content, input bool) (*object, error) {
	if err := r.guard(); err != nil {
		return nil, err
	}
	path, s, err := r.captureMode(name, follow, input)
	if err != nil {
		return nil, err
	}
	defer path.Close()
	o := &object{initial: s}
	switch s.kind() {
	case KindLink:
		o.target, err = readlinkHandle(path)
		if err != nil {
			return nil, err
		}
		return o, nil
	case KindRegular, KindDirectory:
		if s.kind() == KindRegular {
			if !content {
				return o, nil
			}
			if input && s.links != 1 {
				return nil, ErrPath
			}
		}
		// This is NOT lstat/open/fstat: O_PATH owns the selected inode without
		// invoking its device open. Only a captured regular/directory inode is
		// reopened through the kernel's own proc FD view. File type is inode-stable;
		// no target component is resolved at the read transition.
		o.handle, err = r.readCaptured(path, s)
		if err != nil {
			return nil, err
		}
		now, e := statNative(o.handle)
		if e != nil || now != s {
			o.close()
			return nil, ErrUnstable
		}
		return o, nil
	default:
		// Metadata observation only: no I/O descriptor for a special object.
		return o, nil
	}
}
func (r *nativeRoot) readCaptured(path *os.File, selected stamp) (*os.File, error) {
	if err := r.guard(); err != nil {
		return nil, err
	}
	if selected.kind() == KindRegular && (r.parent != nil || r.external != nil) && selected.links != 1 {
		return nil, ErrPath
	}
	if selected.kind() != KindRegular && selected.kind() != KindDirectory {
		return nil, ErrType
	}
	// Revalidate the owned non-I/O descriptor itself, never a target pathname.
	now, err := statNative(path)
	if err != nil || now.dev != selected.dev || now.ino != selected.ino || now.kind() != selected.kind() {
		return nil, ErrUnstable
	}
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	if selected.kind() == KindDirectory {
		flags |= syscall.O_DIRECTORY
	}
	fd, e := syscall.Openat(int(r.procFD.Fd()), strconv.FormatUint(uint64(path.Fd()), 10), flags, 0)
	runtime.KeepAlive(path)
	if e != nil {
		return nil, ErrRead
	}
	read := os.NewFile(uintptr(fd), "native-read")
	now, err = statNative(read)
	if err != nil || now.dev != selected.dev || now.ino != selected.ino || now.kind() != selected.kind() {
		read.Close()
		return nil, ErrUnstable
	}
	return read, nil
}
func (r *nativeRoot) check(name string, initial stamp) error {
	if err := r.guard(); err != nil {
		return err
	}
	root, err := statNative(r.root)
	if err != nil || root.dev != r.initial.dev || root.ino != r.initial.ino {
		return ErrUnstable
	}
	path, now, err := r.capture(name, true)
	if err != nil {
		return ErrUnstable
	}
	defer path.Close()
	if now != initial {
		return ErrUnstable
	}
	return nil
}
func parseRSS(r io.Reader) (uint64, error) {
	scan := bufio.NewScanner(io.LimitReader(r, (1<<20)+1))
	scan.Buffer(make([]byte, 4096), 8192)
	var rss uint64
	found := false
	total := 0
	for scan.Scan() {
		total += len(scan.Bytes()) + 1
		if total > 1<<20 {
			return 0, ErrRead
		}
		fields := strings.Fields(scan.Text())
		if len(fields) == 0 || fields[0] != "Rss:" {
			continue
		}
		if found || len(fields) != 3 || fields[2] != "kB" {
			return 0, ErrRead
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || n == 0 || n > ^uint64(0)/1024 {
			return 0, ErrRead
		}
		rss = n * 1024
		found = true
	}
	if scan.Err() != nil || !found {
		return 0, ErrRead
	}
	return rss, nil
}
func OwnResidentBytes() (uint64, error) {
	// smaps_rollup Rss is resident memory, unlike approximate statm or peak rusage.
	// This is a current own-process query, not a hard bound or committed memory.
	proc, err := procDescriptors()
	if err != nil {
		return 0, err
	}
	defer proc.Close()
	fd, err := syscall.Openat(int(proc.Fd()), "../smaps_rollup", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "own-rss")
	defer f.Close()
	return parseRSS(f)
}
