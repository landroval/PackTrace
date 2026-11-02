package nativefs

import (
	"context"
	"os"
	"sync"
)

// OwnedRetired is minted only by an owned root after moving and verifying the
// retained original. Failed/uncertain retirement leaves bytes in quarantine.
type OwnedRetired struct {
	mu      sync.Mutex
	owner   *OwnedDirectory
	file    *os.File
	name    string
	initial stamp
}

func (d *OwnedDirectory) Quarantine(ctx context.Context, metadata *MetadataLease, dest string) (*OwnedRetired, error) {
	if d == nil || metadata == nil || ctx == nil || !ownedRelative(dest) {
		return nil, ErrPath
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	metadata.mu.Lock()
	defer metadata.mu.Unlock()
	if d.closed || metadata.root != d.root || metadata.object == nil {
		return nil, ErrPath
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	initial := metadata.object.initial
	if initial.kind() != KindRegular || initial.links != 1 {
		return nil, ErrType
	}
	n, unlock, e := d.root.lockNative()
	if e != nil {
		return nil, e
	}
	defer unlock()
	if e := d.native.guard(n); e != nil {
		return nil, e
	}
	if e := n.check(metadata.name, initial); e != nil {
		return nil, e
	}
	f, e := ownedRetireHandle(n, metadata.object.handle, initial)
	if e != nil {
		return nil, e
	}
	failed := func(e error) (*OwnedRetired, error) { f.Close(); return nil, e }
	if now, e := statNative(f); e != nil || now != initial {
		return failed(ErrUnstable)
	}
	if e := ownedMove(n, f, metadata.name, dest, false, false); e != nil {
		return failed(e)
	}
	now, e := statNative(f)
	if e != nil || !retiredSame(initial, now) {
		return failed(ErrUnstable)
	}
	if e := d.native.refresh(n); e != nil {
		return failed(e)
	}
	selected, e := n.captureMetadata(dest)
	if e != nil {
		return failed(e)
	}
	same := selected.initial == now
	selected.close()
	if !same {
		return failed(ErrUnstable)
	}
	return &OwnedRetired{owner: d, file: f, name: dest, initial: now}, nil
}

// RetirementFingerprint admits only a current-user private ordinary single-link
// file in this issuing owned root, using metadata access only (no DELETE grant).
func (d *OwnedDirectory) RetirementFingerprint(ctx context.Context, m *MetadataLease) ([32]byte, error) {
	if d == nil || m == nil || ctx == nil {
		return [32]byte{}, ErrPath
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || m.root != d.root {
		return [32]byte{}, ErrPath
	}
	if e := ctx.Err(); e != nil {
		return [32]byte{}, e
	}
	fingerprint, e := m.Fingerprint()
	if e != nil {
		return [32]byte{}, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.object == nil {
		return [32]byte{}, ErrClosed
	}
	n, unlock, e := d.root.lockNative()
	if e != nil {
		return [32]byte{}, e
	}
	defer unlock()
	if e := d.native.guard(n); e != nil {
		return [32]byte{}, e
	}
	if e := ownedRetireCheck(n, m.object.handle, m.object.initial); e != nil {
		return [32]byte{}, e
	}
	return fingerprint, nil
}
func retiredSame(before, after stamp) bool {
	before.ctSec = after.ctSec
	before.ctNS = after.ctNS
	return before == after
}
func (r *OwnedRetired) Remove(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrPath
	}
	d := r.owner
	d.mu.Lock()
	defer d.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if d.closed || r.file == nil {
		return ErrClosed
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	n, unlock, e := d.root.lockNative()
	if e != nil {
		return e
	}
	defer unlock()
	if e := d.native.guard(n); e != nil {
		return e
	}
	now, e := statNative(r.file)
	if e != nil || now != r.initial {
		return ErrUnstable
	}
	selected, e := n.captureMetadata(r.name)
	if e != nil {
		return e
	}
	same := selected.initial == r.initial
	selected.close()
	if !same {
		return ErrUnstable
	}
	if e := ownedRetireUnlink(n, r.file, r.name, r.initial); e != nil {
		return e
	}
	closeErr := r.file.Close()
	r.file = nil
	if closeErr != nil {
		return ErrWrite
	}
	return d.native.refresh(n)
}
func (r *OwnedRetired) Close() error {
	if r == nil {
		return ErrClosed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	e := r.file.Close()
	r.file = nil
	return e
}

func ownedRename(n *nativeRoot, f *os.File, source, dest string, replace bool) error {
	return ownedMove(n, f, source, dest, replace, true)
}
