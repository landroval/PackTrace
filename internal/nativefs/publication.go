package nativefs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// Publication is an explicit one-file output grant, not a writable target Root.
// Its original parent must be physically disjoint from the forbidden root under
// the existing native profile. Uncommitted/uncertain temporaries are preserved.
type Publication struct {
	mu         sync.Mutex
	ctx        context.Context
	parent     *Root
	forbidden  *Root
	file       *os.File
	temp, name string
	initial    stamp
	written    uint64
	failed     error
	committed  bool
	// Each additional exclusion has its own original-parent native proof.
	// No nativeRoot.external binding is ever replaced.
	exclusions []publicationExclusion
	retained   bool // proof handles belong to a PublicationPlan
}

func OpenPublication(ctx context.Context, forbidden *Root, path string) (*Publication, error) {
	return openPublication(ctx, forbidden, path, nil)
}

func openPublication(ctx context.Context, forbidden *Root, path string, additional []*Root) (*Publication, error) {
	p, e := capturePublication(ctx, forbidden, path, additional)
	if e != nil {
		return nil, e
	}
	if e = p.begin(); e != nil {
		p.closeProofs()
		return nil, e
	}
	return p, nil
}

func capturePublication(ctx context.Context, forbidden *Root, path string, additional []*Root) (*Publication, error) {
	if ctx == nil || forbidden == nil || !filepath.IsAbs(path) {
		return nil, ErrPath
	}
	leaf := filepath.Base(path)
	if leaf == "." || leaf == ".." || validRelative(leaf) != nil {
		return nil, ErrPath
	}
	parent, e := OpenRoot(ctx, filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Publication, error) { parent.Close(); return nil, e }
	source, release, e := forbidden.lockNative()
	if e != nil {
		return fail(e)
	}
	e = parent.native.bindPublication(source)
	release()
	if e != nil {
		return fail(e)
	}
	p := &Publication{ctx: ctx, parent: parent, forbidden: forbidden, name: leaf}
	if e := p.bindExclusions(ctx, filepath.Dir(path), additional); e != nil {
		return fail(e)
	}
	return p, nil
}

func (p *Publication) begin() error {
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return ErrUnavailable
	}
	temp := "packtrace-export-" + hex.EncodeToString(nonce[:]) + ".tmp"
	n, unlock, e := p.lockNative()
	if e != nil {
		return e
	}
	if e = n.guard(); e != nil {
		unlock()
		return e
	}
	f, e := ownedCreatePath(n, temp, false)
	if e != nil {
		unlock()
		return e
	}
	initial, e := statNative(f)
	if e != nil || initial.kind() != KindRegular || initial.links != 1 || initial.size != 0 {
		f.Close()
		unlock()
		return ErrUnstable
	}
	p.file, p.temp, p.initial = f, temp, initial
	e = p.bind(n, temp)
	if e == nil {
		e = p.refresh(n)
	}
	unlock()
	if e != nil {
		p.file.Close()
		p.file = nil
		return e
	}
	return nil
}
func (p *Publication) lockNative() (*nativeRoot, func(), error) {
	if len(p.exclusions) != 0 {
		return p.lockExclusions()
	}
	source, release, e := p.forbidden.lockNative()
	if e != nil {
		return nil, nil, e
	}
	if e := source.guard(); e != nil {
		release()
		return nil, nil, e
	}
	n, unlock, e := p.parent.lockNative()
	if e != nil {
		release()
		return nil, nil, e
	}
	return n, func() { unlock(); release() }, nil
}
func (p *Publication) refresh(n *nativeRoot) error {
	if e := publicationRefresh(n); e != nil {
		return e
	}
	for _, exclusion := range p.exclusions {
		if e := publicationRefresh(exclusion.parent.native); e != nil {
			return e
		}
	}
	if e := publicationRefreshForbidden(n, p.forbidden); e != nil {
		return e
	}
	for _, exclusion := range p.exclusions {
		if e := publicationRefreshForbidden(exclusion.parent.native, exclusion.root); e != nil {
			return e
		}
	}
	return nil
}
func (p *Publication) bind(n *nativeRoot, name string) error {
	now, e := statNative(p.file)
	if e != nil || now.dev != p.initial.dev || now.ino != p.initial.ino || now.mode != p.initial.mode || now.kind() != KindRegular || now.links != 1 || now.size < 0 || uint64(now.size) != p.written {
		return ErrUnstable
	}
	selected, st, e := publicationMetadata(n, name)
	if e != nil {
		return e
	}
	closeErr := selected.Close()
	if closeErr != nil || st != now {
		return ErrUnstable
	}
	return nil
}
func (p *Publication) Write(data []byte) (int, error) {
	if p == nil {
		return 0, ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil || p.committed {
		return 0, ErrClosed
	}
	if p.failed != nil {
		return 0, p.failed
	}
	fail := func(e error) (int, error) { p.failed = e; return 0, e }
	if e := p.ctx.Err(); e != nil {
		return fail(e)
	}
	if uint64(len(data)) > (16<<30)-p.written {
		return fail(ErrLimit)
	}
	n, unlock, e := p.lockNative()
	if e != nil {
		return fail(e)
	}
	defer unlock()
	if e := n.guard(); e != nil {
		return fail(e)
	}
	// Refuse observable name/link substitution BEFORE writing, not just at
	// Commit. This is a live check, not continuous host-mutator isolation.
	if e := p.bind(n, p.temp); e != nil {
		return fail(e)
	}
	count, e := p.file.Write(data)
	if count < 0 || count > len(data) {
		return fail(ErrWrite)
	}
	p.written += uint64(count)
	if e != nil || count != len(data) {
		p.failed = ErrWrite
		return count, ErrWrite
	}
	return count, nil
}
func (p *Publication) Commit() error {
	if p == nil {
		return ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil || p.committed {
		return ErrClosed
	}
	if p.failed != nil {
		return p.failed
	}
	fail := func(e error) error { p.failed = e; return e }
	if e := p.ctx.Err(); e != nil {
		return fail(e)
	}
	n, unlock, e := p.lockNative()
	if e != nil {
		return fail(e)
	}
	defer unlock()
	if e := n.guard(); e != nil {
		return fail(e)
	}
	if p.file.Sync() != nil {
		return fail(ErrWrite)
	}
	if e := p.bind(n, p.temp); e != nil {
		return fail(e)
	}
	if e := ownedMove(n, p.file, p.temp, p.name, false, true); e != nil {
		return fail(e)
	}
	if e := p.bind(n, p.name); e != nil {
		return fail(e)
	}
	if e := p.refresh(n); e != nil {
		return fail(e)
	}
	p.committed = true
	return nil
}
func (p *Publication) Bytes() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.written
}
func (p *Publication) Close() error {
	if p == nil {
		return ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil {
		return nil
	}
	e := p.file.Close()
	if !p.retained {
		e = errors.Join(e, p.closeProofs())
	}
	p.file = nil
	return e
}

func (p *Publication) closeProofs() error {
	e := p.parent.Close()
	for _, exclusion := range p.exclusions {
		e = errors.Join(e, exclusion.parent.Close())
	}
	p.exclusions = nil
	return e
}
