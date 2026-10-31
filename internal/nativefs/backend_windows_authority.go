//go:build windows && amd64

package nativefs

import "strings"

// NTFS has no directory hardlinks. A chain rooted at the captured actual volume
// root, with no reparse traversal and an identity-checked relative binding for
// EVERY directory edge, proves physical ancestry. This is not lexical prefix
// exclusion, a DOS drive mapping, or a claim of Linux mount-ID equivalence.
func (r *nativeRoot) chainGuard(common int, changes bool) error {
	if len(r.chain) == 0 || len(r.chain) > 129 || winQualifyVolume(r.chain[0].handle) != nil {
		return ErrUnstable
	}
	for i, a := range r.chain {
		s, e := statNative(a.handle)
		if e != nil || !winSame(s, a.initial) || s.kind() != KindDirectory {
			return ErrUnstable
		}
		// Shared ancestors can have unrelated directory churn. Below the common
		// ancestor, retain change/write stamps to detect observable move-and-return.
		if changes && i > common && s != a.initial {
			return ErrUnstable
		}
		if i == 0 {
			continue
		}
		f, e := winChild(r.chain[i-1].handle, a.name, r.initial.dev)
		if e != nil {
			return ErrUnstable
		}
		now, e := statNative(f)
		f.Close()
		if e != nil || !winSame(now, a.initial) || (changes && i > common && now != a.initial) {
			return ErrUnstable
		}
	}
	return nil
}
func (r *nativeRoot) guard() error {
	if e := r.chainGuard(0, false); e != nil {
		return e
	}
	if r.parent != nil {
		if e := r.parent.check(r.parentName, r.initial); e != nil {
			return e
		}
	}
	if s := r.external; s != nil {
		if s.target == nil || s.target.volume != r.volume {
			return ErrUnstable
		}
		if e := r.chainGuard(s.common, true); e != nil {
			return e
		}
		if e := s.target.chainGuard(s.common, true); e != nil {
			return e
		}
	}
	return nil
}
func (r *nativeRoot) bindExternal(target *nativeRoot) error {
	if r.external != nil || r.parent != nil || target.external != nil || target.parent != nil {
		return ErrPath
	}
	// Different volumes and unprovable bootstrap conditions are unavailable, not
	// guessed disjoint from potentially colliding serial numbers. Equality here
	// is the captured kernel device name PLUS retained volume-root descriptor ID.
	if r.volume != target.volume || len(r.chain) == 0 || len(target.chain) == 0 || !winSame(r.chain[0].initial, target.chain[0].initial) {
		return ErrUnavailable
	}
	if e := r.guard(); e != nil {
		return e
	}
	if e := target.guard(); e != nil {
		return e
	}
	a, b := make([]stamp, len(r.chain)), make([]stamp, len(target.chain))
	for i := range a {
		a[i] = r.chain[i].initial
	}
	for i := range b {
		b[i] = target.chain[i].initial
	}
	common, e := winDisjointChains(a, b)
	if e != nil {
		return e
	}
	r.external = &winSeparation{target: target, common: common}
	if e := r.guard(); e != nil {
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
	// Independently retain the lineage using SAME-object empty-name reopens of
	// the volume and each ancestor. The child owns all handles it later closes.
	sub := &nativeRoot{volume: r.volume, parent: r, parentName: name}
	for _, a := range r.chain {
		f, e := winOpen(a.handle, "", 0, winDirectory, true)
		if e != nil {
			sub.close()
			return nil, e
		}
		now, e := statNative(f)
		if e != nil || !winSame(now, a.initial) {
			f.Close()
			sub.close()
			return nil, ErrUnstable
		}
		sub.chain = append(sub.chain, winAncestor{f, now, a.name})
	}
	for _, p := range strings.Split(name, "/") {
		f, e := winChild(sub.chain[len(sub.chain)-1].handle, p, r.initial.dev)
		if e != nil {
			sub.close()
			return nil, e
		}
		now, e := statNative(f)
		if e != nil || now.kind() != KindDirectory {
			f.Close()
			sub.close()
			return nil, ErrType
		}
		sub.chain = append(sub.chain, winAncestor{f, now, p})
	}
	sub.root = sub.chain[len(sub.chain)-1].handle
	sub.initial = sub.chain[len(sub.chain)-1].initial
	if len(sub.chain) > 129 || sub.initial != s {
		sub.close()
		return nil, ErrUnstable
	}
	if e = sub.guard(); e != nil {
		sub.close()
		return nil, e
	}
	return sub, nil
}
