package nativefs

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
)

const maxPublicationExclusions = 8

type publicationExclusion struct {
	root   *Root
	parent *Root
}

// OpenPublicationExcluding retains independent physical exclusions for an
// original target and its already target-bound external state/reference roots.
// It grants only one no-clobber publication, never an external writable Root.
// Unsupported native separation conditions fail closed. Callers must retain
// every source root (and its anchor) until Close; temporaries are not removed.
func OpenPublicationExcluding(ctx context.Context, target *Root, additional []*Root, path string) (*Publication, error) {
	if target == nil || target.anchor != nil || len(additional) > maxPublicationExclusions {
		return nil, ErrPath
	}
	seen := map[*Root]bool{target: true}
	for _, root := range additional {
		if root == nil || seen[root] || root.anchor != target {
			return nil, ErrPath
		}
		seen[root] = true
	}
	return openPublication(ctx, target, path, additional)
}

func (p *Publication) bindExclusions(ctx context.Context, path string, roots []*Root) (failure error) {
	defer func() {
		if failure != nil {
			for _, exclusion := range p.exclusions {
				exclusion.parent.Close()
			}
			p.exclusions = nil
		}
	}()
	for _, root := range roots {
		parent, e := OpenRoot(ctx, filepath.Clean(path))
		if e != nil {
			return e
		}
		source, release, e := root.lockNative()
		if e == nil {
			e = source.guard()
			if e == nil {
				e = parent.native.bindPublication(source)
			}
			release()
		}
		if e == nil {
			// These are independently opened ORIGINAL parent handles, not guessed
			// lexical ancestry and not replacements of the first external binding.
			e = publicationSameParent(p.parent.native, parent.native)
		}
		if e != nil {
			parent.Close()
			return e
		}
		p.exclusions = append(p.exclusions, publicationExclusion{root, parent})
	}
	// All acquisitions use the existing external-root -> target lock direction.
	// A stable leaf order prevents two concurrent publications from deadlocking.
	sort.Slice(p.exclusions, func(i, j int) bool {
		return reflect.ValueOf(p.exclusions[i].root).Pointer() < reflect.ValueOf(p.exclusions[j].root).Pointer()
	})
	return nil
}

func (p *Publication) lockSources() (*nativeRoot, func(), error) {
	for _, exclusion := range p.exclusions {
		exclusion.root.mu.Lock()
	}
	releaseLeaves := func() {
		for i := len(p.exclusions) - 1; i >= 0; i-- {
			p.exclusions[i].root.mu.Unlock()
		}
	}
	target, release, e := p.forbidden.lockNative()
	if e != nil {
		releaseLeaves()
		return nil, nil, e
	}
	fail := func(e error) (*nativeRoot, func(), error) { release(); releaseLeaves(); return nil, nil, e }
	if e := target.guard(); e != nil {
		return fail(e)
	}
	for _, exclusion := range p.exclusions {
		root := exclusion.root
		if root.native == nil {
			return fail(ErrClosed)
		}
		if root.owned != nil {
			if e := root.owned.guard(root.native); e != nil {
				return fail(e)
			}
		}
		if e := root.native.guard(); e != nil {
			return fail(e)
		}
	}
	return target, func() { release(); releaseLeaves() }, nil
}

func (p *Publication) lockExclusions() (*nativeRoot, func(), error) {
	_, release, e := p.lockSources()
	if e != nil {
		return nil, nil, e
	}
	fail := func(e error) (*nativeRoot, func(), error) { release(); return nil, nil, e }
	n, unlock, e := p.parent.lockNative()
	if e != nil {
		return fail(e)
	}
	for _, exclusion := range p.exclusions {
		// The publication mutex exclusively owns these proof roots; their source
		// roots/anchor remain locked through the operation, including write/sync.
		if e := exclusion.parent.native.guard(); e != nil {
			unlock()
			return fail(e)
		}
	}
	return n, func() { unlock(); release() }, nil
}
