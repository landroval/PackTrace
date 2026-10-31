// Package nativefs provides owned, bounded native read capabilities. It does not
// authenticate policy, references, packages, or immutable filesystem snapshots.
package nativefs

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

type Kind uint8

const (
	KindUnknown Kind = iota
	KindRegular
	KindDirectory
	KindLink
)

type Status uint8

const (
	StatusUnknown Status = iota
	StatusComplete
	StatusUnreadable
	StatusUnstable
	StatusExcluded
)

type Limits struct {
	FileBytes, TotalBytes int64
	Entries, Depth        int
}
type Entry struct {
	Name, LinkTarget string
	Kind             Kind
	Status           Status
	Size             int64
	SHA256           [32]byte
}
type Snapshot struct {
	// ReadBytes includes failed partial content reads for shared selection budgets.
	ReadBytes int64
	// Enumerated attests checked directory enumeration, not readable content.
	// Failed entries still carry a negative observation for their own prefix.
	Enumerated bool
	Entries    []Entry
	Complete   bool
	Reasons    []string
}

var (
	ErrUnavailable = errors.New("nativefs: mechanism-unavailable")
	ErrClosed      = errors.New("nativefs: closed-capability")
	ErrPath        = errors.New("nativefs: unsafe-path")
	ErrType        = errors.New("nativefs: unsupported-type")
	ErrLimit       = errors.New("nativefs: limit")
	ErrUnstable    = errors.New("nativefs: unstable")
	ErrRead        = errors.New("nativefs: read-failed")
)

const maxTotal int64 = 16 << 30

// Constructors retain the original root/object capability. Stable also checks
// the current root-relative binding. Neither promises continuous live ancestry.
type Root struct {
	mu       sync.Mutex
	native   *nativeRoot
	consumed int64
	// anchor is retained by the caller and locked for all dependent native use.
	// Only native constructors can mint external/subroot bindings.
	anchor *Root
	budget *Root
}
type File struct {
	mu                   sync.Mutex
	root                 *Root
	handle               *os.File
	ctx                  context.Context
	name                 string
	initial              stamp
	remaining, readBytes int64
	eof                  bool
	failed               error
	input                bool
}
type stamp struct {
	dev, ino                       uint64
	mode                           uint32
	size, mtSec, mtNS, ctSec, ctNS int64
	links                          uint64
}

func (s stamp) kind() Kind {
	switch s.mode & 0170000 {
	case 0100000:
		return KindRegular
	case 0040000:
		return KindDirectory
	case 0120000:
		return KindLink
	}
	return KindUnknown
}

type object struct {
	handle  *os.File
	initial stamp
	target  string
}

func (o *object) close() {
	if o != nil && o.handle != nil {
		o.handle.Close()
	}
}

func normalizeLimits(l Limits) (Limits, error) {
	max := Limits{256 << 20, maxTotal, 100000, 128}
	if l.FileBytes < 0 || l.TotalBytes < 0 || l.Entries < 0 || l.Depth < 0 || l.FileBytes > max.FileBytes || l.TotalBytes > max.TotalBytes || l.Entries > max.Entries || l.Depth > max.Depth {
		return Limits{}, ErrLimit
	}
	if l.FileBytes == 0 {
		l.FileBytes = max.FileBytes
	}
	if l.TotalBytes == 0 {
		l.TotalBytes = max.TotalBytes
	}
	if l.Entries == 0 {
		l.Entries = max.Entries
	}
	if l.Depth == 0 {
		l.Depth = max.Depth
	}
	return l, nil
}
func validRelative(name string) error {
	if len(name) == 0 || len(name) > 4096 || strings.ContainsAny(name, "\x00\\") {
		return ErrPath
	}
	c := strings.Split(name, "/")
	if len(c) > 128 {
		return ErrPath
	}
	for _, p := range c {
		if p == "" || p == "." || p == ".." {
			return ErrPath
		}
	}
	return nil
}
func PrepareProcess() error { return prepareNative() }
func OpenRoot(ctx context.Context, path string) (*Root, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(path) == 0 || len(path) > 4096 || strings.IndexByte(path, 0) >= 0 {
		return nil, ErrPath
	}
	n, err := openNativeRoot(path)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		n.close()
		return nil, err
	}
	return &Root{native: n}, nil
}
func (r *Root) Close() error {
	if r == nil {
		return ErrClosed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.native == nil {
		return ErrClosed
	}
	err := r.native.close()
	r.native = nil
	return err
}

// OpenExternalRoot admits a descriptor-proven disjoint controller/reference
// directory, not an assertion from a worker. The target must remain open. All
// external regular reads require a single link and recheck observable ancestry.
func (r *Root) OpenExternalRoot(ctx context.Context, path string) (*Root, error) {
	ext, err := OpenRoot(ctx, path)
	if err != nil {
		return nil, err
	}
	n, unlock, err := r.lockNative()
	if err == nil {
		if r.anchor != nil {
			err = ErrPath
		} else {
			err = ext.native.bindExternal(n)
		}
		unlock()
	}
	if err != nil {
		ext.Close()
		return nil, err
	}
	ext.anchor = r
	return ext, nil
}

// OpenSubroot confines acquisition to the captured physical directory. No
// symlink component or multiply linked content is admitted. Budgets are shared
// with the original root; closing the anchor invalidates the dependent root.
func (r *Root) OpenSubroot(ctx context.Context, name string) (*Root, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validRelative(name); err != nil {
		return nil, err
	}
	n, unlock, err := r.lockNative()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if r.anchor != nil {
		return nil, ErrPath
	}
	sub, err := n.subroot(name)
	if err != nil {
		return nil, err
	}
	return &Root{native: sub, anchor: r, budget: r}, nil
}

func (r *Root) lockNative() (*nativeRoot, func(), error) {
	if r == nil {
		return nil, nil, ErrClosed
	}
	r.mu.Lock()
	if r.native == nil {
		r.mu.Unlock()
		return nil, nil, ErrClosed
	}
	if r.anchor != nil {
		r.anchor.mu.Lock()
		if r.anchor.native == nil {
			r.anchor.mu.Unlock()
			r.mu.Unlock()
			return nil, nil, ErrClosed
		}
	}
	return r.native, func() {
		if r.anchor != nil {
			r.anchor.mu.Unlock()
		}
		r.mu.Unlock()
	}, nil
}

func (r *Root) lookup(ctx context.Context, name string, follow bool) (*object, error) {
	return r.lookupMode(ctx, name, follow, true, false)
}
func (r *Root) lookupMode(ctx context.Context, name string, follow, content, input bool) (*object, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if name != "." {
		if err := validRelative(name); err != nil {
			return nil, err
		}
	}
	n, unlock, err := r.lockNative()
	if err != nil {
		return nil, err
	}
	defer unlock()
	o, err := n.lookupMode(name, follow, content, input)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		o.close()
		return nil, err
	}
	return o, nil
}
func (r *Root) OpenRegular(ctx context.Context, name string, maxbytes int64) (*File, error) {
	return r.openRegular(ctx, name, maxbytes, false)
}

// OpenInput selects one necessary manifest/lock file without following links or
// permitting a hardlink alias to turn that selection into unrelated content.
func (r *Root) OpenInput(ctx context.Context, name string, maxbytes int64) (*File, error) {
	return r.openRegular(ctx, name, maxbytes, true)
}
func (r *Root) openRegular(ctx context.Context, name string, maxbytes int64, input bool) (*File, error) {
	if err := validRelative(name); err != nil {
		return nil, err
	}
	if maxbytes < 0 || maxbytes > 512<<20 {
		return nil, ErrLimit
	}
	o, err := r.lookupMode(ctx, name, true, true, input)
	if err != nil {
		return nil, err
	}
	if o.initial.kind() != KindRegular {
		o.close()
		return nil, ErrType
	}
	if o.initial.size < 0 || o.initial.size > maxbytes {
		o.close()
		return nil, ErrLimit
	}
	return &File{root: r, handle: o.handle, ctx: ctx, name: name, initial: o.initial, remaining: maxbytes, input: input}, nil
}
func (r *Root) charge(n int64) error {
	if r.budget != nil {
		return r.budget.charge(n)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.native == nil {
		return ErrClosed
	}
	if n < 0 || r.consumed > maxTotal-n {
		return ErrLimit
	}
	r.consumed += n
	return nil
}
func (r *Root) check(name string, initial stamp) error {
	n, unlock, err := r.lockNative()
	if err != nil {
		return err
	}
	defer unlock()
	return n.check(name, initial)
}
func (r *Root) validateRead(handle *os.File, initial stamp, input bool) error {
	n, unlock, err := r.lockNative()
	if err != nil {
		return err
	}
	defer unlock()
	return n.validateRead(handle, initial, input)
}
func (f *File) read(p []byte) (int, error) {
	if f.handle == nil || f.root == nil {
		return 0, ErrClosed
	}
	if f.failed != nil {
		return 0, f.failed
	}
	if err := f.ctx.Err(); err != nil {
		f.failed = err
		return 0, err
	}
	if f.eof {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := f.root.validateRead(f.handle, f.initial, f.input); err != nil {
		f.failed = err
		return 0, err
	}
	// Stop at the selected regular inode's initial size. Do NOT read an extra
	// sentinel beyond either lease or aggregate budget. Metadata is checked at
	// this boundary, then again by Stable; this remains a live observation, not
	// an immutable-snapshot claim. Growth never becomes admitted extra content.
	left := f.initial.size - f.readBytes
	if left == 0 {
		now, err := statNative(f.handle)
		if err != nil || now.size != f.initial.size {
			f.failed = ErrUnstable
			if err == nil && now.size > f.remaining+f.readBytes {
				f.failed = ErrLimit
			}
			return 0, f.failed
		}
		f.eof = true
		return 0, io.EOF
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	if int64(len(p)) > f.remaining {
		p = p[:f.remaining]
	}
	if len(p) == 0 {
		f.failed = ErrLimit
		return 0, ErrLimit
	}
	if err := f.root.charge(int64(len(p))); err != nil {
		f.failed = err
		return 0, err
	}
	n, err := f.handle.Read(p)
	// Reserve before I/O so parallel leases cannot bypass the root budget. Refund
	// only bytes not read, including EOF. No boundary sentinel is unaccounted.
	budget := f.root
	if budget.budget != nil {
		budget = budget.budget
	}
	budget.mu.Lock()
	budget.consumed -= int64(len(p) - n)
	budget.mu.Unlock()
	f.remaining -= int64(n)
	f.readBytes += int64(n)
	if err == io.EOF {
		f.eof = true
	} else if err != nil {
		f.failed = ErrRead
		err = ErrRead
	}
	return n, err
}
func (f *File) Read(p []byte) (int, error) {
	if f == nil {
		return 0, ErrClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.read(p)
}
func (f *File) Stable() error {
	if f == nil {
		return ErrClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.handle == nil || f.root == nil {
		return ErrClosed
	}
	if f.failed != nil {
		return f.failed
	}
	if err := f.ctx.Err(); err != nil {
		f.failed = err
		return err
	}
	if !f.eof {
		var b [1]byte
		n, err := f.read(b[:])
		if n != 0 || err != io.EOF {
			f.failed = ErrRead
			return f.failed
		}
	}
	if err := f.root.validateRead(f.handle, f.initial, f.input); err != nil {
		f.failed = err
		return err
	}
	now, err := statNative(f.handle)
	if err != nil || now != f.initial {
		f.failed = ErrUnstable
		return f.failed
	}
	if err = f.root.check(f.name, f.initial); err != nil {
		f.failed = err
		return err
	}
	return nil
}
func (f *File) Close() error {
	if f == nil {
		return ErrClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.handle == nil {
		return ErrClosed
	}
	err := f.handle.Close()
	f.handle = nil
	return err
}
