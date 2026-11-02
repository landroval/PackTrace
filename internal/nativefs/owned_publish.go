package nativefs

import (
	"context"
	"errors"
)

// Publish moves the retained original within the same owned root. replace is
// allowed only for the controller's explicit activation/maintenance transition.
func (d *OwnedDirectory) Publish(ctx context.Context, f *OwnedFile, dest string, replace bool) error {
	if d == nil || f == nil {
		return ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	if d.closed || f.root != d.root || f.file == nil || ctx == nil || !ownedRelative(dest) {
		return ErrPath
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if f.failed != nil {
		return f.failed
	}
	if e := f.binding(true); e != nil {
		return e
	}
	n, unlock, e := d.root.lockNative()
	if e != nil {
		return e
	}
	defer unlock()
	if e := ownedRename(n, f.file, f.name, dest, replace); e != nil {
		return e
	}
	current, e := statNative(f.file)
	if e != nil || current.dev != f.initial.dev || current.ino != f.initial.ino || current.kind() != KindRegular || current.links != 1 || current.size != f.size {
		return ErrUnstable
	}
	f.name = dest
	f.initial = current
	if e := d.native.refresh(n); e != nil {
		return e
	}
	selected, e := n.captureMetadata(dest)
	if e != nil {
		return e
	}
	closeErr := selected.handle.Close()
	if closeErr != nil || selected.initial != current {
		return errors.Join(ErrUnstable, closeErr)
	}
	return ctx.Err()
}
