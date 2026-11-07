package nativefs

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

// DurabilityBatch defers persistence, never binding/ownership checks. Only an
// actual original exclusive writer can mint it. Fence is mandatory before seal.
// Pending originals<=128, directory handles<=272, concurrent flushes<=16.
type DurabilityBatch struct {
	mu     sync.Mutex
	owner  *OwnedDirectory
	ctx    context.Context
	writer *OwnedLock
	files  map[*OwnedFile]*batchOriginal
	dirs   map[string]*batchOriginal
	failed error
	closed bool
}
type batchOriginal struct {
	file    *os.File
	name    string
	initial stamp
}

func (d *OwnedDirectory) BeginDurabilityBatch(ctx context.Context, writer *OwnedLock) (*DurabilityBatch, error) {
	if d == nil || ctx == nil {
		return nil, ErrPath
	}
	if e := writer.Matches(ctx, d.root, "writer.lock", true); e != nil {
		return nil, e
	}
	return &DurabilityBatch{owner: d, ctx: ctx, writer: writer, files: make(map[*OwnedFile]*batchOriginal), dirs: make(map[string]*batchOriginal)}, nil
}
func (b *DurabilityBatch) check(ctx context.Context) error {
	if b == nil || b.closed {
		return ErrClosed
	}
	if b.failed != nil {
		return b.failed
	}
	if ctx == nil {
		b.failed = ErrPath
		return b.failed
	}
	if e := b.ctx.Err(); e != nil {
		b.failed = e
		return e
	}
	if e := b.writer.Matches(ctx, b.owner.root, "writer.lock", true); e != nil {
		b.failed = e
		return e
	}
	return nil
}
func batchParent(name string) string {
	if at := strings.LastIndexByte(name, '/'); at >= 0 {
		return name[:at]
	}
	return "."
}

// Caller holds batch, owner and native root locks; capture BEFORE mutation.
func (b *DurabilityBatch) before(n *nativeRoot, name string) error {
	parent := batchParent(name)
	if existing := b.dirs[parent]; existing != nil {
		return batchOriginalStable(n, existing)
	}
	if len(b.dirs) >= 272 {
		return ErrLimit
	}
	selected, e := n.captureMetadata(parent)
	if e != nil {
		return e
	}
	defer selected.close()
	if selected.initial.kind() != KindDirectory {
		return ErrType
	}
	f, e := batchDirectory(n, selected)
	if e != nil {
		return e
	}
	if e := batchPrivate(f, true); e != nil {
		f.Close()
		return e
	}
	b.dirs[parent] = &batchOriginal{f, parent, selected.initial}
	return nil
}
func (b *DurabilityBatch) after(n *nativeRoot, name string) error {
	parent := batchParent(name)
	old := b.dirs[parent]
	if old == nil {
		return ErrUnstable
	}
	if e := batchPrivate(old.file, true); e != nil {
		return e
	}
	now, e := statNative(old.file)
	if e != nil || now.dev != old.initial.dev || now.ino != old.initial.ino || now.mode != old.initial.mode || now.kind() != KindDirectory {
		return ErrUnstable
	}
	selected, e := n.captureMetadata(parent)
	if e != nil {
		return e
	}
	defer selected.close()
	if selected.initial != now {
		return ErrUnstable
	}
	old.initial = now
	return nil
}
func batchOriginalStable(n *nativeRoot, original *batchOriginal) error {
	if e := batchPrivate(original.file, original.initial.kind() == KindDirectory); e != nil {
		return e
	}
	now, e := statNative(original.file)
	if e != nil || now != original.initial {
		return ErrUnstable
	}
	selected, e := n.captureMetadata(original.name)
	if e != nil {
		return e
	}
	defer selected.close()
	if selected.initial != now {
		return ErrUnstable
	}
	return nil
}
func (b *DurabilityBatch) Mkdir(ctx context.Context, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.check(ctx); e != nil {
		return e
	}
	e := b.owner.mkdir(ctx, name, b)
	if e != nil {
		b.failed = e
	}
	return e
}
func (b *DurabilityBatch) CopyExclusive(ctx context.Context, name string, input io.Reader, max uint64) (*OwnedFile, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.check(ctx); e != nil {
		return nil, e
	}
	if len(b.files) >= 128 {
		if e := b.fence(ctx); e != nil {
			return nil, e
		}
	}
	f, e := b.owner.copyExclusive(ctx, name, input, max, b)
	if e != nil {
		b.failed = e
		return f, e
	}
	f.mu.Lock()
	original, e := batchDuplicate(f.file)
	if e == nil {
		b.files[f] = &batchOriginal{original, f.name, f.initial}
	}
	f.mu.Unlock()
	if e != nil {
		b.failed = e
	}
	return f, e
}
func (b *DurabilityBatch) Publish(ctx context.Context, file *OwnedFile, dest string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.check(ctx); e != nil {
		return e
	}
	original := b.files[file]
	if original == nil {
		return ErrPath
	}
	e := b.owner.publish(ctx, file, dest, false, b)
	if e == nil {
		file.mu.Lock()
		original.name, original.initial = file.name, file.initial
		file.mu.Unlock()
	} else if !errors.Is(e, ErrExists) {
		b.failed = e
	}
	return e
}
func (b *DurabilityBatch) Fence(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.check(ctx); e != nil {
		return e
	}
	return b.fence(ctx)
}
func batchSync(ctx context.Context, items []*batchOriginal) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failure error
	slots := make(chan struct{}, 16)
	for _, item := range items {
		if e := ctx.Err(); e != nil {
			mu.Lock()
			failure = errors.Join(failure, e)
			mu.Unlock()
			break
		}
		slots <- struct{}{}
		wg.Add(1)
		go func(original *batchOriginal) {
			defer wg.Done()
			defer func() { <-slots }()
			e := original.file.Sync()
			if e != nil {
				mu.Lock()
				failure = errors.Join(failure, ErrWrite)
				mu.Unlock()
			}
		}(item)
	}
	wg.Wait()
	return failure
}
func (b *DurabilityBatch) fence(ctx context.Context) (failure error) {
	if e := b.check(ctx); e != nil {
		return e
	}
	b.owner.mu.Lock()
	defer b.owner.mu.Unlock()
	fail := func(e error) error { b.failed = e; return e }
	n, unlock, e := b.owner.root.lockNative()
	if e != nil {
		return fail(e)
	}
	var files, dirs []*batchOriginal
	for _, f := range b.files {
		files = append(files, f)
	}
	for _, d := range b.dirs {
		dirs = append(dirs, d)
	}
	for _, group := range [][]*batchOriginal{files, dirs} {
		for _, item := range group {
			if e := batchOriginalStable(n, item); e != nil {
				unlock()
				return fail(e)
			}
		}
	}
	unlock()
	// File data first, then names in their retained ORIGINAL directories. The
	// same bounded worker owns blocking flushes; no syncfs/global flush fallback.
	if e := batchSync(ctx, files); e != nil {
		return fail(e)
	}
	if e := batchSync(ctx, dirs); e != nil {
		return fail(e)
	}
	n, unlock, e = b.owner.root.lockNative()
	if e != nil {
		return fail(e)
	}
	for _, group := range [][]*batchOriginal{files, dirs} {
		for _, item := range group {
			if e := batchOriginalStable(n, item); e != nil {
				unlock()
				return fail(e)
			}
		}
	}
	unlock()
	if e := b.writer.Matches(ctx, b.owner.root, "writer.lock", true); e != nil {
		return fail(e)
	}
	for _, group := range [][]*batchOriginal{files, dirs} {
		for _, item := range group {
			failure = errors.Join(failure, item.file.Close())
		}
	}
	b.files = make(map[*OwnedFile]*batchOriginal)
	b.dirs = make(map[string]*batchOriginal)
	if failure != nil {
		return fail(ErrWrite)
	}
	return nil
}
func (b *DurabilityBatch) Close() (failure error) {
	if b == nil {
		return ErrClosed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return b.failed
	}
	if b.failed == nil {
		failure = b.fence(b.ctx)
	} else {
		failure = b.failed
	}
	for _, f := range b.files {
		failure = errors.Join(failure, f.file.Close())
	}
	for _, d := range b.dirs {
		failure = errors.Join(failure, d.file.Close())
	}
	b.files = nil
	b.dirs = nil
	b.closed = true
	b.failed = failure
	return failure
}
