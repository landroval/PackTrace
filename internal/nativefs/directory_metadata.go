package nativefs

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
)

// DirectoryMetadata retains one original directory and returns at most64 rows.
// It never opens regular content; old Snapshot entry/retention limits stay intact.
// EOF means this directory's checked enumeration ended, not recursive coverage.
type DirectoryMetadata struct {
	mu      sync.Mutex
	root    *Root
	ctx     context.Context
	name    string
	file    *os.File
	initial stamp
	eof     bool
	failed  error
}

func (r *Root) OpenDirectoryMetadata(ctx context.Context, name string) (*DirectoryMetadata, error) {
	if ctx == nil {
		return nil, ErrPath
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if name != "." && validRelative(name) != nil {
		return nil, ErrPath
	}
	n, unlock, err := r.lockNative()
	if err != nil {
		return nil, err
	}
	defer unlock()
	selected, err := n.captureMetadata(name)
	if err != nil {
		return nil, err
	}
	if selected.initial.kind() != KindDirectory {
		return nil, errors.Join(ErrType, selected.handle.Close())
	}
	f, err := readDirectoryCaptured(n, selected)
	closeErr := selected.handle.Close()
	if err != nil || closeErr != nil {
		if f != nil {
			f.Close()
		}
		return nil, errors.Join(err, closeErr)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return &DirectoryMetadata{root: r, ctx: ctx, name: name, file: f, initial: selected.initial}, nil
}

func (d *DirectoryMetadata) stable() error {
	if err := d.ctx.Err(); err != nil {
		return err
	}
	current, err := statNative(d.file)
	if err != nil || current != d.initial {
		return ErrUnstable
	}
	return d.root.check(d.name, d.initial)
}

func (d *DirectoryMetadata) Next() ([]Entry, error) {
	if d == nil {
		return nil, ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return nil, ErrClosed
	}
	if d.failed != nil {
		return nil, d.failed
	}
	if err := d.stable(); err != nil {
		d.failed = err
		return nil, err
	}
	if d.eof {
		return nil, io.EOF
	}
	names, readErr := d.file.ReadDir(64)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		d.failed = ErrRead
		return nil, d.failed
	}
	if len(names) == 0 && readErr == nil {
		d.failed = ErrRead
		return nil, d.failed
	}
	entries := make([]Entry, 0, len(names))
	for _, name := range names {
		rel := name.Name()
		if d.name != "." {
			rel = d.name + "/" + rel
		}
		if validRelative(rel) != nil {
			d.failed = ErrPath
			return nil, d.failed
		}
		lease, err := d.root.OpenMetadata(d.ctx, rel)
		if err != nil {
			d.failed = err
			return nil, err
		}
		entry := lease.Entry()
		stableErr := lease.Stable()
		closeErr := lease.Close()
		if stableErr != nil || closeErr != nil {
			d.failed = errors.Join(stableErr, closeErr)
			return nil, d.failed
		}
		entries = append(entries, entry)
	}
	if err := d.stable(); err != nil {
		d.failed = err
		return nil, err
	}
	if errors.Is(readErr, io.EOF) {
		d.eof = true
		return entries, io.EOF
	}
	return entries, nil
}

func (d *DirectoryMetadata) Close() error {
	if d == nil {
		return ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return ErrClosed
	}
	err := d.file.Close()
	d.file = nil
	return err
}
