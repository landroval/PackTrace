//go:build darwin && cgo && (amd64 || arm64)

package nativefs

import (
	"os"
	"strings"
)

// Logical root bindings alone are insufficient on the split system/data
// volume: a firmlink can hide an actual ancestor. The two OS-owned APFS volume
// roots below are namespace bootstrap capabilities, never investigated content.
// Physical edges are checked using the selected directory's SDK parent-ID
// attribute, not a pathname prefix or the apparent result of ".." alone.
func macVolumeRoots() ([]macAncestor, error) {
	root, e := macOpen(nil, "/", false, true)
	if e != nil {
		return nil, e
	}
	s, e := statNative(root)
	if e != nil || s.kind() != KindDirectory || !macLocal(root) {
		root.Close()
		return nil, ErrUnavailable
	}
	roots := []macAncestor{{handle: root, initial: s}}
	current, e := macDup(root)
	if e != nil {
		macClose(roots)
		return nil, e
	}
	for _, name := range []string{"System", "Volumes", "Data"} {
		next, st, err := macChild(current, name, 0)
		current.Close()
		if err != nil {
			macClose(roots)
			return nil, err
		}
		if st.kind() != KindDirectory || !macLocal(next) {
			next.Close()
			macClose(roots)
			return nil, ErrUnavailable
		}
		current = next
	}
	s, e = statNative(current)
	if e != nil {
		current.Close()
		macClose(roots)
		return nil, e
	}
	return append(roots, macAncestor{handle: current, initial: s}), nil
}
func macAncestry(root *os.File, volumes []macAncestor) ([]macAncestor, error) {
	current, e := macDup(root)
	if e != nil {
		return nil, e
	}
	var chain []macAncestor
	fail := func(e error) ([]macAncestor, error) { macClose(chain); return nil, e }
	for i := 0; i < 128; i++ {
		s, e := statNative(current)
		if e != nil {
			current.Close()
			return fail(e)
		}
		if s.kind() != KindDirectory || !macLocal(current) {
			current.Close()
			return fail(ErrUnavailable)
		}
		chain = append(chain, macAncestor{handle: current, initial: s})
		for _, v := range volumes {
			if macSame(s, v.initial) {
				return chain, nil
			}
		}
		id, e := macParentID(current)
		if e != nil {
			return fail(e)
		}
		parent, e := macOpen(current, "..", false, true)
		if e != nil {
			return fail(e)
		}
		ps, e := statNative(parent)
		if e != nil {
			parent.Close()
			return fail(e)
		}
		if ps.dev != s.dev || ps.ino != id {
			parent.Close()
			parent = nil
			// A logical firmlink parent is not accepted as physical ancestry.
			// Only an exact SDK parent-ID match to a retained trusted volume
			// root permits that one transition; anything else is unavailable.
			for _, v := range volumes {
				if v.initial.dev == s.dev && v.initial.ino == id {
					parent, e = macDup(v.handle)
					break
				}
			}
			if e != nil {
				return fail(e)
			}
			if parent == nil {
				return fail(macFailure("physical-parent-binding", nil, ErrUnavailable))
			}
			ps, e = statNative(parent)
			if e != nil {
				parent.Close()
				return fail(e)
			}
		}
		if ps.dev != s.dev || ps.ino != id || ps.kind() != KindDirectory || !macLocal(parent) {
			parent.Close()
			return fail(ErrUnavailable)
		}
		for _, a := range chain {
			if macSame(a.initial, ps) {
				parent.Close()
				return fail(ErrUnstable)
			}
		}
		current = parent
	}
	current.Close()
	return fail(ErrLimit)
}
func macPhysicalGuard(chain []macAncestor) error {
	if len(chain) == 0 {
		return ErrUnstable
	}
	for i, a := range chain {
		now, e := statNative(a.handle)
		if e != nil {
			return e
		}
		if !macSame(now, a.initial) || now.kind() != KindDirectory {
			return ErrUnstable
		}
		if i == len(chain)-1 {
			continue
		} // shared ancestor churn is not authority
		if now != a.initial {
			return ErrUnstable
		}
		id, e := macParentID(a.handle)
		if e != nil {
			return e
		}
		if id != chain[i+1].initial.ino || now.dev != chain[i+1].initial.dev {
			return ErrUnstable
		}
	}
	return nil
}
func (r *nativeRoot) guard() error {
	if len(r.chain) == 0 || len(r.chain) > 129 {
		return ErrUnstable
	}
	for i, a := range r.chain {
		now, e := statNative(a.handle)
		if e != nil {
			return e
		}
		if !macSame(now, a.initial) || now.kind() != KindDirectory || !macLocal(a.handle) {
			return ErrUnstable
		}
		if i == 0 {
			continue
		}
		f, s, e := macChild(r.chain[i-1].handle, a.name, 0)
		if e != nil {
			return e
		}
		f.Close()
		if !macSame(s, a.initial) {
			return ErrUnstable
		}
	}
	if r.parent != nil {
		if e := r.parent.check(r.parentName, r.initial); e != nil {
			return e
		}
	}
	if x := r.external; x != nil {
		if x.target == nil || x.target.initial.dev != r.initial.dev {
			return ErrUnstable
		}
		if e := x.target.guard(); e != nil {
			return e
		}
		if e := macPhysicalGuard(x.external); e != nil {
			return e
		}
		if e := macPhysicalGuard(x.investigated); e != nil {
			return e
		}
	}
	return nil
}
func (r *nativeRoot) bindExternal(target *nativeRoot) error {
	if r.external != nil || r.parent != nil || target.external != nil || target.parent != nil {
		return ErrPath
	}
	if r.initial.dev != target.initial.dev {
		return ErrUnavailable
	}
	if e := r.guard(); e != nil {
		return e
	}
	if e := target.guard(); e != nil {
		return e
	}
	volumes, e := macVolumeRoots()
	if e != nil {
		return e
	}
	defer macClose(volumes)
	a, e := macAncestry(r.root, volumes)
	if e != nil {
		return e
	}
	b, e := macAncestry(target.root, volumes)
	if e != nil {
		macClose(a)
		return e
	}
	refuse := func(e error) error { macClose(a); macClose(b); return e }
	for _, x := range a {
		if macSame(x.initial, b[0].initial) {
			return refuse(ErrPath)
		}
	}
	for _, x := range b {
		if macSame(x.initial, a[0].initial) {
			return refuse(ErrPath)
		}
	}
	ai, bi := -1, -1
	for i, x := range a {
		for j, y := range b {
			if macSame(x.initial, y.initial) {
				ai, bi = i, j
				break
			}
		}
		if ai >= 0 {
			break
		}
	}
	if ai < 0 {
		return refuse(ErrUnavailable)
	}
	macClose(a[ai+1:])
	macClose(b[bi+1:])
	r.external = &macSeparation{target: target, external: a[:ai+1], investigated: b[:bi+1]}
	if e := r.guard(); e != nil {
		macClose(r.external.external)
		macClose(r.external.investigated)
		r.external = nil
		return e
	}
	return nil
}
func (r *nativeRoot) subroot(name string) (*nativeRoot, error) {
	if e := r.guard(); e != nil {
		return nil, e
	}
	selected, s, e := r.capture(name, true, true)
	if e != nil {
		return nil, e
	}
	defer selected.Close()
	if s.kind() != KindDirectory {
		return nil, ErrType
	}
	sub := &nativeRoot{parent: r, parentName: name}
	for _, a := range r.chain {
		f, e := macDup(a.handle)
		if e != nil {
			sub.close()
			return nil, e
		}
		now, e := statNative(f)
		if e != nil || !macSame(now, a.initial) {
			f.Close()
			sub.close()
			return nil, ErrUnstable
		}
		sub.chain = append(sub.chain, macAncestor{f, now, a.name})
	}
	for _, name := range strings.Split(name, "/") {
		f, st, e := macChild(sub.chain[len(sub.chain)-1].handle, name, r.initial.dev)
		if e != nil {
			sub.close()
			return nil, e
		}
		if st.kind() != KindDirectory {
			f.Close()
			sub.close()
			return nil, ErrType
		}
		sub.chain = append(sub.chain, macAncestor{f, st, name})
	}
	sub.root = sub.chain[len(sub.chain)-1].handle
	sub.initial = sub.chain[len(sub.chain)-1].initial
	if len(sub.chain) > 129 || sub.initial != s {
		sub.close()
		return nil, ErrUnstable
	}
	if e := sub.guard(); e != nil {
		sub.close()
		return nil, e
	}
	return sub, nil
}
