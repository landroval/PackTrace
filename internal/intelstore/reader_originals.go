package intelstore

import (
	"context"
	"errors"
	"io"
	"packtrace/internal/intel"
)

// WalkOriginals independently opens retained original objects under this exact
// selected generation lease. Failed reads and close/lease failures are charged.
func (s *Snapshot) WalkOriginals(ctx context.Context, remaining uint64, emit func(uint64, intel.SnapshotOriginalEvidence) error) (consumed uint64, err error) {
	if s == nil || ctx == nil || emit == nil {
		return 0, ErrUnavailable
	}
	if remaining > 8<<30 {
		return 0, ErrLimit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.pin.ID() == (ID{}) {
		return 0, ErrUnavailable
	}
	if s.pin.lease.Stable(ctx) != nil {
		return 0, ErrBinding
	}
	budget := &identityReadBudget{remaining: remaining}
	defer func() {
		consumed = budget.consumed
		err = errors.Join(err, budget.err, ctx.Err(), s.pin.lease.Stable(ctx))
	}()
	err = intel.WalkSnapshotCatalogOriginals(ctx, s.manifest, s.catalog, func(ref intel.SnapshotObjectReference) (io.ReadCloser, error) {
		return &lazyOriginal{ctx: ctx, store: s.store, ref: ObjectRef{ref.SHA256, ref.Bytes}, budget: budget}, nil
	}, emit)
	return budget.consumed, err
}
