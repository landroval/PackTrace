package nativefs

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

func ownedRelative(name string) bool {
	if validRelative(name) != nil {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if !controlName(part) {
			return false
		}
	}
	return true
}

// Mkdir creates only one generated component below already captured parents.
// An existing directory is admitted only after native type/protection checks.
func (d *OwnedDirectory) Mkdir(ctx context.Context, name string) error {
	return d.mkdir(ctx, name, nil)
}
func (d *OwnedDirectory) mkdir(ctx context.Context, name string, batch *DurabilityBatch) error {
	if d == nil {
		return ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || ctx == nil || !ownedRelative(name) {
		return ErrPath
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	n, unlock, e := d.root.lockNative()
	if e != nil {
		return e
	}
	defer unlock()
	if batch != nil {
		if e := batch.before(n, name); e != nil {
			return e
		}
	}
	f, e := ownedCreatePathMode(n, name, true, batch == nil)
	if e != nil {
		return e
	}
	closeErr := f.Close()
	refreshErr := d.native.refresh(n)
	if closeErr != nil || refreshErr != nil {
		return errors.Join(ErrWrite, refreshErr)
	}
	if batch != nil {
		if e := batch.after(n, name); e != nil {
			return e
		}
	}
	return ctx.Err()
}

type OwnedFile struct {
	mu      sync.Mutex
	root    *Root
	ctx     context.Context
	file    *os.File
	name    string
	size    int64
	initial stamp
	failed  error
}

// CopyExclusive retains actual failed bytes and their original file capability.
// Readers can block: callers still need the terminable bounded worker boundary.
func (d *OwnedDirectory) CopyExclusive(ctx context.Context, name string, input io.Reader, max uint64) (*OwnedFile, error) {
	return d.copyExclusive(ctx, name, input, max, nil)
}
func (d *OwnedDirectory) copyExclusive(ctx context.Context, name string, input io.Reader, max uint64, batch *DurabilityBatch) (*OwnedFile, error) {
	if d == nil {
		return nil, ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || ctx == nil || input == nil || !ownedRelative(name) {
		return nil, ErrPath
	}
	if max > 16<<30 {
		return nil, ErrLimit
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	n, unlock, e := d.root.lockNative()
	if e != nil {
		return nil, e
	}
	if batch != nil {
		if e := batch.before(n, name); e != nil {
			unlock()
			return nil, e
		}
	}
	raw, e := ownedCreatePathMode(n, name, false, batch == nil)
	if e == nil {
		e = d.native.refresh(n)
	}
	if e == nil && batch != nil {
		e = batch.after(n, name)
	}
	unlock()
	if e != nil {
		if raw != nil {
			raw.Close()
		}
		return nil, e
	}
	f := &OwnedFile{root: d.root, ctx: ctx, file: raw, name: name}
	var buf [64 << 10]byte
	var failure error
	for {
		if e := ctx.Err(); e != nil {
			failure = e
			break
		}
		request := uint64(len(buf))
		left := max - uint64(f.size)
		if request > left+1 {
			request = left + 1
		}
		count, readErr := input.Read(buf[:int(request)])
		if count < 0 || count > int(request) {
			failure = ErrRead
			break
		}
		accepted := count
		if uint64(accepted) > left {
			accepted = int(left)
		}
		if accepted > 0 {
			if e := f.binding(false); e != nil {
				failure = e
				break
			}
			written, writeErr := raw.Write(buf[:accepted])
			f.size += int64(written)
			if writeErr != nil || written != accepted {
				failure = ErrWrite
				break
			}
		}
		if e := ctx.Err(); e != nil {
			failure = e
			break
		}
		if uint64(count) > left {
			failure = ErrLimit
			break
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				failure = ErrRead
			}
			break
		}
		if count == 0 {
			failure = ErrRead
			break
		}
	}
	if batch == nil || failure != nil {
		if raw.Sync() != nil {
			failure = errors.Join(failure, ErrWrite)
		}
	}
	current, statErr := statNative(raw)
	if statErr != nil || current.size != f.size {
		failure = errors.Join(failure, ErrUnstable)
	} else {
		f.initial = current
	}
	if e := f.binding(false); e != nil {
		failure = errors.Join(failure, e)
	}
	f.failed = failure
	return f, failure
}

func (f *OwnedFile) Size() int64 {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.size
}
func (f *OwnedFile) binding(sealed bool) error {
	if f.file == nil || f.root == nil {
		return ErrClosed
	}
	if e := f.ctx.Err(); e != nil {
		return e
	}
	n, unlock, e := f.root.lockNative()
	if e != nil {
		return e
	}
	defer unlock()
	if e := n.guard(); e != nil {
		return e
	}
	current, e := statNative(f.file)
	if e != nil || current.kind() != KindRegular || current.links != 1 {
		return ErrUnstable
	}
	if sealed && current != f.initial {
		return ErrUnstable
	}
	selected, e := n.captureMetadata(f.name)
	if e != nil {
		return e
	}
	closeErr := selected.handle.Close()
	if closeErr != nil || selected.initial != current {
		return ErrUnstable
	}
	return nil
}
func (f *OwnedFile) Stable() error {
	if f == nil {
		return ErrClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed != nil {
		return f.failed
	}
	return f.binding(true)
}
func (f *OwnedFile) ReadAt(p []byte, off int64) (int, error) {
	if f == nil {
		return 0, ErrClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed != nil {
		return 0, f.failed
	}
	if off < 0 {
		return 0, ErrPath
	}
	if e := f.binding(true); e != nil {
		return 0, e
	}
	if off >= f.size {
		return 0, io.EOF
	}
	if e := f.root.charge(int64(len(p))); e != nil {
		return 0, e
	}
	n, e := f.file.ReadAt(p, off)
	if after := f.binding(true); after != nil {
		return n, after
	}
	if e != nil && !errors.Is(e, io.EOF) {
		return n, ErrRead
	}
	return n, e
}
func (f *OwnedFile) Close() error {
	if f == nil {
		return ErrClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return ErrClosed
	}
	e := f.file.Close()
	f.file = nil
	return e
}
