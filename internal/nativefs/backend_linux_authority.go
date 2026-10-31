//go:build linux && (amd64 || arm64)

package nativefs

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Retained ancestor descriptors prevent an inode-reuse substitution for the
// observed chain. Only paths below the common ancestor are authority-bearing;
// unrelated changes in /tmp or another shared ancestor do not invalidate them.
// This is a live, checked capability, NOT continuous ancestry or an OS sandbox.
type ancestor struct {
	handle  *os.File
	initial stamp
}
type separation struct {
	target                 *nativeRoot
	external, investigated []ancestor
	mount                  uint64
}

func closeAncestors(chain []ancestor) {
	for _, a := range chain {
		a.handle.Close()
	}
}
func (s *separation) close()     { closeAncestors(s.external); closeAncestors(s.investigated) }
func sameObject(a, b stamp) bool { return a.dev == b.dev && a.ino == b.ino }

func (r *nativeRoot) mountID() (uint64, error) {
	fd, e := syscall.Openat(int(r.procFD.Fd()), "../fdinfo/"+strconv.FormatUint(uint64(r.root.Fd()), 10), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return 0, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "own-fdinfo")
	defer f.Close()
	scan := bufio.NewScanner(io.LimitReader(f, 4097))
	scan.Buffer(make([]byte, 4097), 4097)
	var id uint64
	total := 0
	for scan.Scan() {
		total += len(scan.Bytes()) + 1
		if total > 4096 {
			return 0, ErrUnavailable
		}
		fields := strings.Fields(scan.Text())
		if len(fields) > 0 && fields[0] == "mnt_id:" {
			if id != 0 || len(fields) != 2 {
				return 0, ErrUnavailable
			}
			id, e = strconv.ParseUint(fields[1], 10, 64)
			if e != nil || id == 0 {
				return 0, ErrUnavailable
			}
		}
	}
	if scan.Err() != nil || id == 0 {
		return 0, ErrUnavailable
	}
	return id, nil
}
func ancestry(root *os.File) ([]ancestor, error) {
	current, e := openat2(int(root.Fd()), ".", oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, resolveNoMagic)
	if e != nil {
		return nil, e
	}
	var chain []ancestor
	for i := 0; i < 128; i++ {
		st, e := statNative(current)
		if e != nil {
			current.Close()
			closeAncestors(chain)
			return nil, e
		}
		chain = append(chain, ancestor{current, st})
		parent, e := openat2(int(current.Fd()), "..", oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, resolveNoMagic)
		if e != nil {
			closeAncestors(chain)
			return nil, e
		}
		ps, e := statNative(parent)
		if e != nil {
			parent.Close()
			closeAncestors(chain)
			return nil, e
		}
		if sameObject(st, ps) {
			parent.Close()
			return chain, nil
		}
		for _, a := range chain {
			if sameObject(a.initial, ps) {
				parent.Close()
				closeAncestors(chain)
				return nil, ErrPath
			}
		}
		current = parent
	}
	current.Close()
	closeAncestors(chain)
	return nil, ErrLimit
}
func disjoint(a, b []ancestor) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for _, x := range a {
		if sameObject(x.initial, b[0].initial) {
			return false
		}
	}
	for _, x := range b {
		if sameObject(x.initial, a[0].initial) {
			return false
		}
	}
	return true
}
func (r *nativeRoot) bindExternal(target *nativeRoot) error {
	if r.external != nil || r.parent != nil || target.external != nil || target.parent != nil {
		return ErrPath
	}
	mount, e := r.mountID()
	if e != nil {
		return e
	}
	other, e := target.mountID()
	if e != nil || mount != other {
		return ErrUnavailable
	}
	a, e := ancestry(r.root)
	if e != nil {
		return e
	}
	b, e := ancestry(target.root)
	if e != nil {
		closeAncestors(a)
		return e
	}
	if !disjoint(a, b) {
		closeAncestors(a)
		closeAncestors(b)
		return ErrPath
	}
	// Keep the common ancestor identity, but not its mutable timestamp/size.
	ai, bi := -1, -1
	for i, x := range a {
		for j, y := range b {
			if sameObject(x.initial, y.initial) {
				ai, bi = i, j
				break
			}
		}
		if ai >= 0 {
			break
		}
	}
	if ai < 0 {
		closeAncestors(a)
		closeAncestors(b)
		return ErrUnavailable
	}
	closeAncestors(a[ai+1:])
	closeAncestors(b[bi+1:])
	r.external = &separation{target: target, external: a[:ai+1], investigated: b[:bi+1], mount: mount}
	if e = r.guard(); e != nil {
		r.external.close()
		r.external = nil
		return e
	}
	return nil
}
func checkChain(root *os.File, old []ancestor) error {
	now, e := ancestry(root)
	if e != nil {
		return e
	}
	defer closeAncestors(now)
	if len(now) < len(old) {
		return ErrUnstable
	}
	for i, a := range old {
		retained, e := statNative(a.handle)
		if e != nil || !sameObject(now[i].initial, a.initial) || !sameObject(retained, a.initial) {
			return ErrUnstable
		}
		if i < len(old)-1 && (retained != a.initial || now[i].initial != a.initial) {
			return ErrUnstable
		}
	}
	return nil
}
func (r *nativeRoot) guard() error {
	if r.parent != nil {
		if e := r.parent.check(r.parentName, r.initial); e != nil {
			return e
		}
	}
	if s := r.external; s != nil {
		id, e := r.mountID()
		if e != nil || id != s.mount {
			return ErrUnstable
		}
		id, e = s.target.mountID()
		if e != nil || id != s.mount {
			return ErrUnstable
		}
		if e = checkChain(r.root, s.external); e != nil {
			return e
		}
		if e = checkChain(s.target.root, s.investigated); e != nil {
			return e
		}
	}
	return nil
}
func (r *nativeRoot) subroot(name string) (*nativeRoot, error) {
	path, s, e := r.captureMode(name, true, true)
	if e != nil {
		return nil, e
	}
	if s.kind() != KindDirectory {
		path.Close()
		return nil, ErrType
	}
	proc, e := openat2(int(r.procFD.Fd()), ".", oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, resolveBeneath|resolveNoMagic|resolveNoXdev)
	if e != nil {
		path.Close()
		return nil, e
	}
	sub := &nativeRoot{root: path, procFD: proc, initial: s, parent: r, parentName: name}
	if e = sub.guard(); e != nil {
		sub.close()
		return nil, e
	}
	return sub, nil
}
func (r *nativeRoot) validateRead(handle *os.File, initial stamp, input bool) error {
	if e := r.guard(); e != nil {
		return e
	}
	if input || r.parent != nil || r.external != nil {
		now, e := statNative(handle)
		if e != nil || now != initial || now.links != 1 {
			return ErrUnstable
		}
	}
	return nil
}
