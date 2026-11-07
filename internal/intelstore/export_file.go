package intelstore

import (
	"context"
	"errors"
	"packtrace/internal/nativefs"
	"time"
)

// ExportFile streams directly into the explicitly selected external output.
// No second managed copy, arbitrary caller Writer or no-clobber fallback exists.
func (s *Store) ExportFile(ctx context.Context, snapshot *Snapshot, path string) (written uint64, failure error) {
	if s == nil || ctx == nil || snapshot == nil {
		return 0, ErrUnavailable
	}
	work, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	publication, e := nativefs.OpenPublication(work, s.root, path)
	if e != nil {
		return 0, ErrBinding
	}
	defer func() { failure = errors.Join(failure, publication.Close()) }()
	e = s.Export(work, snapshot, publication)
	written = publication.Bytes()
	if e != nil {
		return written, e
	}
	if e := publication.Commit(); e != nil {
		return written, ErrUnavailable
	}
	return written, nil
}
