//go:build windows && amd64

package nativefs

import (
	"os"
	"strings"
)

func ownedCreatePath(n *nativeRoot, name string, directory bool) (*os.File, error) {
	return ownedCreatePathMode(n, name, directory, true)
}
func ownedCreatePathMode(n *nativeRoot, name string, directory, durable bool) (*os.File, error) {
	parentName, leaf := ".", name
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		parentName, leaf = name[:i], name[i+1:]
	}
	parent, e := n.captureMetadata(parentName)
	if e != nil {
		return nil, e
	}
	defer parent.close()
	if parent.initial.kind() != KindDirectory {
		return nil, ErrType
	}
	// Only freshly created owned files receive READ_DATA and DELETE capability.
	f, e := ownedCreateAccess(parent.handle, leaf, directory, 1|0x10000)
	if e == nil {
		return f, nil
	}
	if !directory {
		return nil, e
	}
	existing, e := winChild(parent.handle, leaf, n.initial.dev)
	if e != nil {
		return nil, e
	}
	st, e := statNative(existing)
	if e != nil || st.kind() != KindDirectory {
		existing.Close()
		return nil, ErrType
	}
	protected, e := winOpen(existing, "", 0x20000, winDirectory, true)
	existing.Close()
	if e != nil {
		return nil, e
	}
	if _, e := ownedCheckSecurity(protected); e != nil {
		protected.Close()
		return nil, e
	}
	return protected, nil
}
func (o *ownedNative) refresh(n *nativeRoot) error {
	now, e := statNative(n.root)
	if e != nil || !winSame(now, n.initial) || now.kind() != KindDirectory {
		return ErrUnstable
	}
	selected, st, e := o.parent.native.capture(o.name, false, true)
	if e != nil {
		return ErrUnstable
	}
	defer selected.Close()
	if now != st {
		return ErrUnstable
	}
	n.initial = st
	n.chain[len(n.chain)-1].initial = st
	return o.guard(n)
}
