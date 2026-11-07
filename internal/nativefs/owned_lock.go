package nativefs

import (
	"context"
	"errors"
	"os"
	"sync"
)

// OwnedLock owns an original kernel lease, never a PID claim. It is not
// cloneable. Readonly acquisition only uses existing zero-length lease files.
type OwnedLock struct {
	mu        sync.Mutex
	file      *os.File
	root      *Root
	name      string
	exclusive bool
}

func (r *Root) TryOwnedLock(ctx context.Context, name string, exclusive bool) (*OwnedLock, error) {
	if ctx == nil || !ownedRelative(name) {
		return nil, ErrPath
	}
	if _, err := r.OwnedIdentity(ctx); err != nil {
		return nil, err
	}
	n, unlock, err := r.lockNative()
	if err != nil {
		return nil, err
	}
	defer unlock()
	f, err := ownedLockFile(n, name, exclusive)
	if err != nil {
		return nil, err
	}
	lease := &OwnedLock{file: f, root: r, name: name, exclusive: exclusive}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, lease.Close())
	}
	return lease, nil
}

// Matches binds the retained lease to its exact issuing root/name/mode. A live
// lock on another file or a shared reader is not an exclusive writer grant.
func (l *OwnedLock) Matches(ctx context.Context, root *Root, name string, exclusive bool) error {
	if l == nil || root == nil {
		return ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil || l.root != root || l.name != name || l.exclusive != exclusive {
		return ErrPath
	}
	return l.stable(ctx)
}

func (l *OwnedLock) Stable(ctx context.Context) error {
	if l == nil || ctx == nil {
		return ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stable(ctx)
}

func (l *OwnedLock) stable(ctx context.Context) error {
	if ctx == nil {
		return ErrPath
	}
	if l.file == nil || l.root == nil {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n, unlock, err := l.root.lockNative()
	if err != nil {
		return err
	}
	defer unlock()
	if err := n.guard(); err != nil {
		return err
	}
	if err := ownedControlBinding(n, l.file, l.name, 0); err != nil {
		return err
	}
	return ctx.Err()
}

func (l *OwnedLock) Close() error {
	if l == nil {
		return ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return ErrClosed
	}
	// Explicit unlock matters for Linux's transient fork-inherited OFD: closing
	// only this descriptor does not necessarily release that shared description.
	err := errors.Join(ownedUnlock(l.file), l.file.Close())
	l.file = nil
	return err
}
