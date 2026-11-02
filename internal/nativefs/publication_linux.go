//go:build linux && (amd64 || arm64)

package nativefs

import "os"

func publicationRefreshForbidden(output *nativeRoot, source *Root) error {
	if source.owned == nil {
		return source.native.guard()
	}
	o := source.owned
	now, e := statNative(o.parent.native.root)
	if e != nil {
		return e
	}
	destination, e := statNative(output.root)
	if e != nil {
		return e
	}
	if !sameObject(now, destination) {
		return o.guard(source.native)
	}
	selected, st, e := o.parent.native.captureMode(o.name, false, true)
	if e != nil {
		return e
	}
	selected.Close()
	if st != source.native.initial {
		return ErrUnstable
	}
	old, initial := o.chain[0].initial, o.parent.native.initial
	o.chain[0].initial = now
	o.parent.native.initial = now
	if e := o.guard(source.native); e != nil {
		o.chain[0].initial = old
		o.parent.native.initial = initial
		return e
	}
	return nil
}
func publicationMetadata(n *nativeRoot, name string) (*os.File, stamp, error) {
	return n.captureMode(name, false, true)
}
func publicationRefresh(n *nativeRoot) error {
	if n.external == nil || len(n.external.external) == 0 {
		return ErrUnavailable
	}
	now, e := statNative(n.root)
	if e != nil || !sameObject(now, n.initial) || now.kind() != KindDirectory {
		return ErrUnstable
	}
	old, oldRoot := n.external.external[0].initial, n.initial
	n.external.external[0].initial = now
	n.initial = now
	// Only the original output parent's known mutation is refreshed. Every
	// retained ancestry edge and the forbidden root still revalidates in guard.
	if e := n.guard(); e != nil {
		n.external.external[0].initial = old
		n.initial = oldRoot
		return e
	}
	return nil
}
