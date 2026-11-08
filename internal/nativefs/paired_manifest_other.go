//go:build !linux

package nativefs

import "context"

func (r *Root) OpenPairedManifest(ctx context.Context, name string, cache *Root, peer string, maxbytes int64) (*File, error) {
	return nil, ErrUnavailable
}
