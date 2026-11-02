//go:build windows && amd64

package nativefs

import "os"

func publicationRefreshForbidden(output *nativeRoot, source *Root) error {
	if source.owned == nil {
		return source.native.guard()
	}
	o := source.owned
	parent := o.parent.native
	now, e := statNative(parent.root)
	if e != nil {
		return e
	}
	destination, e := statNative(output.root)
	if e != nil {
		return e
	}
	if !winSame(now, destination) {
		return o.guard(source.native)
	}
	selected, st, e := parent.capture(o.name, false, true)
	if e != nil {
		return e
	}
	selected.Close()
	if st != source.native.initial {
		return ErrUnstable
	}
	old, initial := o.initial, parent.initial
	last := len(parent.chain) - 1
	chain := parent.chain[last].initial
	o.initial = now
	parent.initial = now
	parent.chain[last].initial = now
	if e := o.guard(source.native); e != nil {
		o.initial = old
		parent.initial = initial
		parent.chain[last].initial = chain
		return e
	}
	return nil
}
func publicationMetadata(n *nativeRoot, name string) (*os.File, stamp, error) {
	f, e := winChild(n.root, name, n.initial.dev)
	if e != nil {
		return nil, stamp{}, e
	}
	st, e := statNative(f)
	if e != nil {
		f.Close()
		return nil, stamp{}, e
	}
	return f, st, nil
}
func publicationRefresh(n *nativeRoot) error {
	if n.external == nil || len(n.chain) == 0 {
		return ErrUnavailable
	}
	now, e := statNative(n.root)
	if e != nil || !winSame(now, n.initial) || now.kind() != KindDirectory {
		return ErrUnstable
	}
	last := len(n.chain) - 1
	old, root := n.chain[last].initial, n.initial
	n.chain[last].initial = now
	n.initial = now
	if e := n.guard(); e != nil {
		n.chain[last].initial = old
		n.initial = root
		return e
	}
	return nil
}
