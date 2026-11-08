package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"packtrace/internal/nativefs"
)

// The parent retains these original source capabilities through output/reap.
// Binding tokens compare two independent admissions; they grant no authority.
type scanBunCacheOwner struct {
	target, cache         *nativefs.Root
	targetMeta, cacheMeta *nativefs.MetadataLease
	binding               string
	ownsTarget, closed    bool
}

func openScanBunCache(ctx context.Context, target *nativefs.Root, targetPath, cachePath, expected string) (owner *scanBunCacheOwner, failure error) {
	o := &scanBunCacheOwner{target: target}
	fail := func(err error) (*scanBunCacheOwner, error) { return o, err }
	var err error
	if target == nil {
		o.target, err = nativefs.OpenRoot(ctx, targetPath)
		if err != nil {
			return fail(err)
		}
		o.ownsTarget = true
	}
	o.cache, err = o.target.OpenExternalRoot(ctx, cachePath)
	if err != nil {
		return fail(err)
	}
	o.targetMeta, err = o.target.OpenMetadata(ctx, ".")
	if err != nil {
		return fail(err)
	}
	o.cacheMeta, err = o.cache.OpenMetadata(ctx, ".")
	if err != nil {
		return fail(err)
	}
	o.binding, err = o.currentBinding()
	if err != nil {
		return fail(err)
	}
	if expected != "" && expected != o.binding {
		return fail(nativefs.ErrUnstable)
	}
	return o, nil
}
func (o *scanBunCacheOwner) currentBinding() (string, error) {
	if o == nil || o.closed || o.targetMeta == nil || o.cacheMeta == nil {
		return "", nativefs.ErrClosed
	}
	t, err := o.targetMeta.Fingerprint()
	if err != nil {
		return "", err
	}
	c, err := o.cacheMeta.Fingerprint()
	if err != nil {
		return "", err
	}
	data := append([]byte("PackTrace Bun cache pair roots v1\x00"), t[:]...)
	data = append(data, c[:]...)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func (o *scanBunCacheOwner) check() error {
	current, err := o.currentBinding()
	if err != nil {
		return err
	}
	if current != o.binding {
		return nativefs.ErrUnstable
	}
	return nil
}
func (o *scanBunCacheOwner) close() error {
	if o == nil || o.closed {
		return nil
	}
	var err error
	if o.cacheMeta != nil {
		err = errors.Join(err, o.cacheMeta.Close())
	}
	if o.cache != nil {
		err = errors.Join(err, o.cache.Close())
	}
	if o.targetMeta != nil {
		err = errors.Join(err, o.targetMeta.Close())
	}
	if o.ownsTarget && o.target != nil {
		err = errors.Join(err, o.target.Close())
	}
	o.closed = true
	return err
}
