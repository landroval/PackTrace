//go:build darwin && cgo && (amd64 || arm64)

package nativefs

/*
#cgo CFLAGS: -D_DARWIN_C_SOURCE -Wno-deprecated-declarations
#cgo LDFLAGS: -lsandbox -lproc
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <sandbox.h>

// The installed SDK supplies every ABI, flag and declaration. These policies
// affect this terminable worker only, not the supervisor or host settings.
static int pt_prepare(char *detail, size_t cap) {
    char release[64] = {0}; size_t n = sizeof(release);
    if (sysctlbyname("kern.osrelease", release, &n, NULL, 0) != 0 || strncmp(release, "24.", 3) != 0) return 1;
    if (setiopolicy_np(IOPOL_TYPE_VFS_TRIGGER_RESOLVE, IOPOL_SCOPE_PROCESS, IOPOL_VFS_TRIGGER_RESOLVE_OFF) != 0 ||
        getiopolicy_np(IOPOL_TYPE_VFS_TRIGGER_RESOLVE, IOPOL_SCOPE_PROCESS) != IOPOL_VFS_TRIGGER_RESOLVE_OFF) return 2;
    if (setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_PROCESS, IOPOL_MATERIALIZE_DATALESS_FILES_OFF) != 0 ||
        getiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_PROCESS) != IOPOL_MATERIALIZE_DATALESS_FILES_OFF) return 3;
    // A selected-vnode predicate, not a pathname or post-open fstat guard.
    // Chromium common.sb uses vnode-type with file-read* / file-read-data.
    // XNU vn_authorize_open_existing runs the MAC open hook before VNOP_OPEN;
    // compound open receives that same existing-object authorizer callback.
    // No target path enters this constant profile. Unknown types are denied.
    const char *profile = "(version 1)(allow default)"
      "(deny file-read* (require-not (require-any (vnode-type REGULAR-FILE)"
      "(vnode-type DIRECTORY)(vnode-type SYMLINK))))";
    char *error = NULL;
    int result = sandbox_init(profile, 0, &error);
    // Only this constant, caller-independent profile's compiler diagnosis.
    // No target path or bytes enter the compiler; the public error stays fixed.
    if (error != NULL) {
        if (cap > 0) {strncpy(detail,error,cap-1);detail[cap-1]=0;}
        sandbox_free_error(error);
    }
    if (result != 0) return 4;
    return 0;
}
static int pt_metadata(int parent, const char *name) {
    // O_SYMLINK clears namei FOLLOW and pins the link itself. Adding
    // O_NOFOLLOW instead makes vn_authorize_open_existing reject VLNK
    // with ELOOP, even alongside O_SYMLINK. Readable opens keep O_NOFOLLOW.
    return openat(parent, name, O_EVTONLY|O_SYMLINK|O_CLOEXEC|O_NONBLOCK);
}
static int pt_readable(int parent, const char *name, int directory) {
    int flags = O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK;
    if (directory) flags |= O_DIRECTORY;
    return openat(parent, name, flags);
}
static int pt_duplicate(int fd) { return fcntl(fd, F_DUPFD_CLOEXEC, 0); }
static int pt_local_apfs(int fd) {
    struct statfs s = {0};
    return fstatfs(fd, &s) == 0 && (s.f_flags & MNT_LOCAL) != 0 && strcmp(s.f_fstypename, "apfs") == 0;
}
struct pt_stamp { uint64_t dev, ino, mode, links; int64_t size, mtsec, mtns, ctsec, ctns; };
static int pt_stat(int fd, struct pt_stamp *out) {
    struct stat s = {0};
    if (fstat(fd, &s) != 0 || (s.st_flags & SF_DATALESS) != 0) return -1;
    out->dev = (uint32_t)s.st_dev; out->ino = s.st_ino; out->mode = s.st_mode;
    out->links = s.st_nlink; out->size = s.st_size;
    out->mtsec = s.st_mtimespec.tv_sec; out->mtns = s.st_mtimespec.tv_nsec;
    out->ctsec = s.st_ctimespec.tv_sec; out->ctns = s.st_ctimespec.tv_nsec;
    return 0;
}
static int pt_exact_name(int fd, const char *component) {
    char path[4096] = {0};
    if (fcntl(fd, F_GETPATH, path) != 0) return 0;
    char *last = strrchr(path, '/');
    return last != NULL && strcmp(last + 1, component) == 0;
}
// getattrlist packs attribute values on four-byte boundaries. The SDK owns
// attrlist and ATTR_CMN_PARENTID; copy the documented uint64 result without
// introducing a guessed Go structure or consulting a pathname.
static int pt_parent_id(int fd, uint64_t *out) {
    struct attrlist request = {0};
    request.bitmapcount = ATTR_BIT_MAP_COUNT;
    request.commonattr = ATTR_CMN_PARENTID;
    unsigned char reply[12] = {0}; uint32_t length = 0;
    if (fgetattrlist(fd, &request, reply, sizeof(reply), 0) != 0) return -1;
    memcpy(&length, reply, sizeof(length));
    if (length != sizeof(reply)) return -1;
    memcpy(out, reply + sizeof(length), sizeof(*out));
    return *out == 0 ? -1 : 0;
}
static int pt_link(int fd, const char *name, char *out, size_t cap) {
    ssize_t n = readlinkat(fd, name, out, cap);
    return n < 0 ? -1 : (int)n;
}
*/
import "C"

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type darwinNativeFailure struct {
	Stage string
	Errno int
	Cause error
}

func (e *darwinNativeFailure) Error() string { return e.Cause.Error() }
func (e *darwinNativeFailure) Unwrap() error { return e.Cause }
func macFailure(stage string, err, cause error) error {
	var n syscall.Errno
	errors.As(err, &n)
	return &darwinNativeFailure{stage, int(n), cause}
}

type darwinPreparationFailure struct {
	Stage  int
	Detail string
}

func (e *darwinPreparationFailure) Error() string { return ErrUnavailable.Error() }
func (e *darwinPreparationFailure) Unwrap() error { return ErrUnavailable }

var darwinPrepareOnce sync.Once
var darwinPrepareError error

func prepareNative() error {
	darwinPrepareOnce.Do(func() {
		var detail [513]byte
		if stage := int(C.pt_prepare((*C.char)(unsafe.Pointer(&detail[0])), C.size_t(len(detail)))); stage != 0 {
			darwinPrepareError = &darwinPreparationFailure{stage, C.GoString((*C.char)(unsafe.Pointer(&detail[0])))}
		}
	})
	return darwinPrepareError
}

type macAncestor struct {
	handle  *os.File
	initial stamp
	name    string
}
type macSeparation struct {
	target                 *nativeRoot
	external, investigated []macAncestor
}
type nativeRoot struct {
	root       *os.File
	initial    stamp
	chain      []macAncestor
	external   *macSeparation
	parent     *nativeRoot
	parentName string
}

func macComponent(s string) error {
	if s == "" || s == "." || s == ".." || len(s) > 255 {
		return ErrPath
	}
	for _, c := range s {
		if c < 32 || c > 126 || c == '/' || c == '\\' {
			return ErrPath
		}
	}
	return nil
}
func macOpen(parent *os.File, name string, readable, directory bool) (*os.File, error) {
	defer runtime.KeepAlive(parent)
	p := C.CString(name)
	defer C.free(unsafe.Pointer(p))
	fd := C.int(C.AT_FDCWD) // Used only for the fixed OS root "/".
	if parent != nil {
		fd = C.int(parent.Fd())
	}
	var n C.int
	var callErr error
	stage := "metadata-open"
	if readable {
		d := C.int(0)
		if directory {
			d = 1
		}
		n, callErr = C.pt_readable(fd, p, d)
		stage = "data-open"
	} else {
		n, callErr = C.pt_metadata(fd, p)
	}
	if n < 0 {
		return nil, macFailure(stage, callErr, ErrPath)
	}
	return os.NewFile(uintptr(n), "native-owned"), nil
}
func macDup(f *os.File) (*os.File, error) {
	defer runtime.KeepAlive(f)
	if f == nil {
		return nil, ErrClosed
	}
	n, callErr := C.pt_duplicate(C.int(f.Fd()))
	if n < 0 {
		return nil, macFailure("descriptor-duplicate", callErr, ErrRead)
	}
	return os.NewFile(uintptr(n), "native-owned"), nil
}
func statNative(f *os.File) (stamp, error) {
	defer runtime.KeepAlive(f)
	if f == nil {
		return stamp{}, ErrRead
	}
	var s C.struct_pt_stamp
	n, callErr := C.pt_stat(C.int(f.Fd()), &s)
	if n != 0 {
		return stamp{}, macFailure("descriptor-stat-or-dataless", callErr, ErrRead)
	}
	return stamp{dev: uint64(s.dev), ino: uint64(s.ino), mode: uint32(s.mode), size: int64(s.size), mtSec: int64(s.mtsec), mtNS: int64(s.mtns), ctSec: int64(s.ctsec), ctNS: int64(s.ctns), links: uint64(s.links)}, nil
}
func macSame(a, b stamp) bool { return a.dev == b.dev && a.ino == b.ino && a.kind() == b.kind() }
func macLocal(f *os.File) bool {
	defer runtime.KeepAlive(f)
	return C.pt_local_apfs(C.int(f.Fd())) != 0
}
func macParentID(f *os.File) (uint64, error) {
	defer runtime.KeepAlive(f)
	var n C.uint64_t
	result, callErr := C.pt_parent_id(C.int(f.Fd()), &n)
	if result != 0 {
		return 0, macFailure("descriptor-parent-id", callErr, ErrUnavailable)
	}
	return uint64(n), nil
}
func macChild(parent *os.File, name string, dev uint64) (*os.File, stamp, error) {
	if macComponent(name) != nil {
		return nil, stamp{}, ErrPath
	}
	f, e := macOpen(parent, name, false, false)
	if e != nil {
		return nil, stamp{}, e
	}
	s, e := statNative(f)
	p := C.CString(name)
	exactResult, nameErr := C.pt_exact_name(C.int(f.Fd()), p)
	exact := exactResult != 0
	C.free(unsafe.Pointer(p))
	if e != nil {
		f.Close()
		return nil, stamp{}, e
	}
	if !exact || dev != 0 && s.dev != dev {
		f.Close()
		return nil, stamp{}, macFailure("component-name-or-device", nameErr, ErrPath)
	}
	return f, s, nil
}
func openNativeRoot(request string) (*nativeRoot, error) {
	if !filepath.IsAbs(request) || filepath.Clean(request) != request {
		return nil, ErrPath
	}
	if e := prepareNative(); e != nil {
		return nil, e
	}
	parts := strings.Split(strings.TrimPrefix(request, "/"), "/")
	if request == "/" {
		parts = nil
	}
	if len(parts) > 128 {
		return nil, ErrLimit
	}
	for _, p := range parts {
		if macComponent(p) != nil {
			return nil, ErrPath
		}
	}
	f, e := macOpen(nil, "/", false, true)
	if e != nil {
		return nil, e
	}
	r := &nativeRoot{}
	s, e := statNative(f)
	if e != nil {
		f.Close()
		return nil, e
	}
	if s.kind() != KindDirectory || !macLocal(f) {
		f.Close()
		return nil, macFailure("os-root-local-apfs", nil, ErrUnavailable)
	}
	r.chain = append(r.chain, macAncestor{handle: f, initial: s})
	for _, p := range parts {
		f, s, e = macChild(r.chain[len(r.chain)-1].handle, p, 0)
		if e != nil {
			r.close()
			return nil, e
		}
		if s.kind() != KindDirectory || !macLocal(f) {
			f.Close()
			r.close()
			return nil, macFailure("bootstrap-directory-local-apfs", nil, ErrUnavailable)
		}
		r.chain = append(r.chain, macAncestor{f, s, p})
	}
	r.root = r.chain[len(r.chain)-1].handle
	r.initial = r.chain[len(r.chain)-1].initial
	if e := r.guard(); e != nil {
		r.close()
		return nil, e
	}
	return r, nil
}
func macClose(chain []macAncestor) error {
	var e error
	for _, a := range chain {
		e = errors.Join(e, a.handle.Close())
	}
	return e
}
func (r *nativeRoot) close() error {
	e := macClose(r.chain)
	if r.external != nil {
		e = errors.Join(e, macClose(r.external.external), macClose(r.external.investigated))
	}
	return e
}
func macTrail(trail []macAncestor) error {
	for i, a := range trail {
		s, e := statNative(a.handle)
		if e != nil || !macSame(s, a.initial) || s.kind() != KindDirectory {
			return ErrUnstable
		}
		if i == 0 {
			continue
		}
		f, now, e := macChild(trail[i-1].handle, a.name, 0)
		if e != nil {
			return ErrUnstable
		}
		f.Close()
		if now != a.initial || s != a.initial {
			return ErrUnstable
		}
	}
	return nil
}
func (r *nativeRoot) captureAttempt(name string, follow, input bool) (*os.File, stamp, string, error) {
	if name == "." {
		f, e := macDup(r.root)
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
		if macComponent(p) != nil {
			return nil, stamp{}, "", ErrPath
		}
	}
	trail := []macAncestor{{handle: r.root, initial: r.initial}}
	defer func() { macClose(trail[1:]) }()
	for i, p := range parts {
		parent := trail[len(trail)-1].handle
		f, s, e := macChild(parent, p, r.initial.dev)
		if e != nil {
			return nil, stamp{}, "", e
		}
		if e = macTrail(trail); e != nil {
			f.Close()
			return nil, stamp{}, "", e
		}
		last := i == len(parts)-1
		if s.kind() == KindLink && (!last || follow) {
			if input || r.parent != nil || r.external != nil {
				f.Close()
				return nil, stamp{}, "", ErrPath
			}
			target, e := macLink(parent, p, f, s)
			f.Close()
			if e != nil {
				return nil, stamp{}, "", e
			}
			next, e := macLinkPath(parts[:i], target, parts[i+1:])
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
		trail = append(trail, macAncestor{f, s, p})
	}
	return nil, stamp{}, "", ErrPath
}
func macLinkPath(prefix []string, target string, tail []string) (string, error) {
	if target == "" || len(target) > 4096 || strings.HasPrefix(target, "/") || strings.ContainsAny(target, "\x00\\") {
		return "", ErrPath
	}
	parts := append([]string(nil), prefix...)
	for _, p := range strings.Split(target, "/") {
		switch p {
		case "..":
			if len(parts) == 0 {
				return "", ErrPath
			}
			parts = parts[:len(parts)-1]
		case ".":
		case "":
			return "", ErrPath
		default:
			if macComponent(p) != nil {
				return "", ErrPath
			}
			parts = append(parts, p)
		}
	}
	parts = append(parts, tail...)
	if len(parts) == 0 {
		return ".", nil
	}
	s := strings.Join(parts, "/")
	if validRelative(s) != nil {
		return "", ErrPath
	}
	return s, nil
}
func macLink(parent *os.File, name string, original *os.File, s stamp) (string, error) {
	defer runtime.KeepAlive(parent)
	defer runtime.KeepAlive(original)
	p := C.CString(name)
	defer C.free(unsafe.Pointer(p))
	b := make([]byte, 4097)
	n, callErr := C.pt_link(C.int(parent.Fd()), p, (*C.char)(unsafe.Pointer(&b[0])), C.size_t(len(b)))
	if n <= 0 || int(n) > 4096 {
		return "", macFailure("symlink-read-or-size", callErr, ErrPath)
	}
	now, e := statNative(original)
	if e != nil || now != s {
		return "", ErrUnstable
	}
	f, bound, e := macChild(parent, name, s.dev)
	if e != nil {
		return "", ErrUnstable
	}
	f.Close()
	if bound != s {
		return "", ErrUnstable
	}
	return string(b[:int(n)]), nil
}
func (r *nativeRoot) captureResolved(name string, follow, input bool) (*os.File, stamp, string, error) {
	for hops := 0; hops < 40; hops++ {
		f, s, next, e := r.captureAttempt(name, follow, input)
		if e != nil || next == "" {
			return f, s, name, e
		}
		name = next
	}
	return nil, stamp{}, "", ErrLimit
}
func (r *nativeRoot) capture(name string, follow, input bool) (*os.File, stamp, error) {
	f, s, _, e := r.captureResolved(name, follow, input)
	return f, s, e
}
func (r *nativeRoot) lookup(name string, follow bool) (*object, error) {
	return r.lookupMode(name, follow, true, false)
}
func (r *nativeRoot) lookupMode(name string, follow, content, input bool) (*object, error) {
	if e := r.guard(); e != nil {
		return nil, e
	}
	f, s, resolved, e := r.captureResolved(name, follow, input)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	o := &object{initial: s}
	if s.kind() == KindLink {
		// Resolve only metadata here. Keep the original link descriptor while
		// rechecking its parent/name binding; never read a link as package bytes.
		parentName := path.Dir(name)
		parent, _, e := r.capture(parentName, true, input)
		if e != nil {
			return nil, e
		}
		defer parent.Close()
		o.target, e = macLink(parent, path.Base(name), f, s)
		return o, e
	}
	if s.kind() != KindRegular && s.kind() != KindDirectory {
		return nil, ErrType
	}
	if s.kind() == KindRegular && !content {
		return o, nil
	}
	if s.kind() == KindRegular && (input || r.parent != nil || r.external != nil) && s.links != 1 {
		return nil, ErrPath
	}
	if e = r.binding(name, s, input); e != nil {
		return nil, e
	}
	parentName := path.Dir(resolved)
	parent, _, e := r.capture(parentName, true, input)
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	leaf := path.Base(resolved)
	if resolved == "." {
		leaf = "."
	}
	o.handle, e = macOpen(parent, leaf, true, s.kind() == KindDirectory)
	if e != nil {
		return nil, e
	}
	now, e := statNative(o.handle)
	if e != nil || now != s {
		o.close()
		return nil, ErrUnstable
	}
	if e = r.validateRead(o.handle, s, input); e != nil {
		o.close()
		return nil, e
	}
	return o, nil
}
func (r *nativeRoot) validateRead(f *os.File, s stamp, input bool) error {
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
func (r *nativeRoot) check(name string, s stamp) error { return r.binding(name, s, false) }
func (r *nativeRoot) binding(name string, s stamp, input bool) error {
	if e := r.guard(); e != nil {
		return e
	}
	f, now, e := r.capture(name, true, input)
	if e != nil {
		return ErrUnstable
	}
	f.Close()
	if now != s {
		return ErrUnstable
	}
	return nil
}
