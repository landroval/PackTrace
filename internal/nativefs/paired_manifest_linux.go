//go:build linux

package nativefs

import (
	"context"
	"path"
)

// OpenPairedManifest admits one selected manifest only when its complete set of
// hardlink names is the project name and an explicitly admitted disjoint cache
// name. The cache is additional untrusted input, never publisher authority.
func (r *Root) OpenPairedManifest(ctx context.Context, name string, cache *Root, peer string, maxbytes int64) (*File, error) {
	if ctx == nil || r == nil || cache == nil || cache.anchor != r || cache.owned != nil || path.Base(name) != "package.json" || path.Base(peer) != "package.json" || validRelative(name) != nil || validRelative(peer) != nil {
		return nil, ErrPath
	}
	if maxbytes < 0 || maxbytes > 2<<20 {
		return nil, ErrLimit
	}
	selected, err := r.OpenMetadata(ctx, name)
	if err != nil {
		return nil, err
	}
	defer selected.Close()
	other, err := cache.OpenMetadata(ctx, peer)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			other.Close()
		}
	}()
	initial := selected.object.initial
	if initial.kind() != KindRegular || initial.links != 2 || initial != other.object.initial {
		return nil, ErrPath
	}
	if initial.size < 0 || initial.size > maxbytes {
		return nil, ErrLimit
	}
	if err := other.Stable(); err != nil {
		return nil, err
	}
	n, unlock, err := r.lockNative()
	if err != nil {
		return nil, err
	}
	handle, err := n.readPairedCaptured(selected.object.handle, initial)
	unlock()
	if err != nil {
		return nil, err
	}
	file := &File{root: r, handle: handle, ctx: ctx, name: name, initial: initial, remaining: maxbytes, input: true, pair: other}
	if err := file.validateRead(); err != nil {
		handle.Close()
		return nil, err
	}
	keep = true
	return file, nil
}
