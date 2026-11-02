package intelstore

import (
	"context"
	"errors"
	"packtrace/internal/nativefs"
)

// acquireWriter creates only the permanent zero-byte kernel-lock control. It
// does not reserve payload space or infer absence from PID/journal text.
func (s *Store) acquireWriter(ctx context.Context) (*nativefs.OwnedLock, uint64, error) {
	if s == nil || ctx == nil {
		return nil, 0, ErrUnavailable
	}
	if e := ctx.Err(); e != nil {
		return nil, 0, e
	}
	s.mu.Lock()
	if s.root == nil || s.owner == nil || s.mode != CreateOwned {
		s.mu.Unlock()
		return nil, 0, ErrUnavailable
	}
	if s.active {
		s.mu.Unlock()
		return nil, 0, ErrBusy
	}
	s.active = true
	limit := s.quotaLimit
	if limit == 0 {
		limit = 32 << 30
	}
	owner, root := s.owner, s.root
	s.mu.Unlock()
	fail := func(e error) (*nativefs.OwnedLock, uint64, error) {
		s.mu.Lock()
		s.active = false
		s.mu.Unlock()
		return nil, 0, e
	}
	marker, e := root.OpenMetadata(ctx, "writer.lock")
	if e != nil {
		e = owner.WriteControl(ctx, "writer.lock", nil)
	} else {
		e = errors.Join(marker.Stable(), marker.Close())
	}
	if e != nil {
		return fail(ErrUnavailable)
	}
	writer, e := root.TryOwnedLock(ctx, "writer.lock", true)
	if e != nil {
		if errors.Is(e, nativefs.ErrBusy) {
			return fail(ErrBusy)
		}
		return fail(ErrUnavailable)
	}
	return writer, limit, nil
}
