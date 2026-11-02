package nativefs

import (
	"context"
	"sync"
)

// MetadataLease retains a non-following metadata handle, never a content reader.
// Stable rechecks that original object and its current root-relative binding;
// this is a bounded live observation, not an immutable filesystem snapshot.
type MetadataLease struct {
	mu     sync.Mutex
	root   *Root
	ctx    context.Context
	name   string
	object *object
}

func (r *Root) OpenMetadata(ctx context.Context, name string) (*MetadataLease, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := validRelative(name); e != nil {
		return nil, e
	}
	n, unlock, e := r.lockNative()
	if e != nil {
		return nil, e
	}
	o, e := n.captureMetadata(name)
	unlock()
	if e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		o.close()
		return nil, e
	}
	return &MetadataLease{root: r, ctx: ctx, name: name, object: o}, nil
}
func (m *MetadataLease) Entry() Entry {
	if m == nil {
		return Entry{Status: StatusUnknown}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.object == nil {
		return Entry{Status: StatusUnknown}
	}
	return Entry{Name: m.name, Kind: m.object.initial.kind(), Status: StatusComplete, Size: m.object.initial.size, LinkTarget: m.object.target}
}
func (m *MetadataLease) Stable() error {
	if m == nil {
		return ErrClosed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.object == nil {
		return ErrClosed
	}
	if e := m.ctx.Err(); e != nil {
		return e
	}
	n, unlock, e := m.root.lockNative()
	if e != nil {
		return e
	}
	defer unlock()
	now, e := statNative(m.object.handle)
	if e != nil || now != m.object.initial {
		return ErrUnstable
	}
	current, e := n.captureMetadata(m.name)
	if e != nil {
		return e
	}
	defer current.close()
	if current.initial != m.object.initial || current.target != m.object.target {
		return ErrUnstable
	}
	return nil
}
func (m *MetadataLease) Close() error {
	if m == nil {
		return ErrClosed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.object == nil {
		return ErrClosed
	}
	e := m.object.handle.Close()
	m.object = nil
	return e
}
