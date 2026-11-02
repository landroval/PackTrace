package intelstore

import (
	"context"
	"errors"
	"fmt"
	"packtrace/internal/intel"
)

func (s *Store) sync(ctx context.Context, b *Budget, fetch sourceFetch) (result OperationResult, failure error) {
	pin, e := s.Pin(ctx, nil)
	if e != nil {
		if ctx != nil && ctx.Err() != nil {
			return result, ctx.Err()
		}
		return s.syncFull(ctx, b, fetch)
	}
	state, e := s.loadSourceState(ctx, pin.ID())
	if e != nil || zeroRef(state.descriptor.Cursor) || pin.fallback {
		closeErr := pin.Close()
		if closeErr != nil {
			return result, closeErr
		}
		return s.syncFull(ctx, b, fetch)
	}
	defer func() { failure = errors.Join(failure, pin.Close()) }()
	return s.syncIncremental(ctx, b, fetch, state)
}
func (s *Store) syncIncremental(ctx context.Context, b *Budget, fetch sourceFetch, old sourceState) (result OperationResult, failure error) {
	if e := s.verifyLocal(ctx, old.id); e != nil {
		return result, ErrUntrusted
	}
	cursor, e := s.readSourceCursor(ctx, old.descriptor.Cursor)
	if e != nil || cursor.BaseGeneration != old.receipt.Generation {
		return result, ErrUntrusted
	}
	if old.manifest.Source.ExportedAt.State != intel.TimestampValue {
		return result, ErrUntrusted
	}
	tx, e := s.begin(ctx, operationSync, b)
	if e != nil {
		return result, e
	}
	defer func() {
		if failure != nil {
			tx.mu.Lock()
			tx.failed = failure
			tx.mu.Unlock()
		}
		failure = errors.Join(failure, tx.Close())
	}()
	selection, _, e := s.readSelection(tx.work)
	if e != nil || selection.Current != fmt.Sprintf("%x", old.id) {
		return result, ErrBusy
	}
	draft, candidate, e := prepareListing(tx.work, tx, old.draft, old.preparation, old.manifest.Source.ExportedAt.Value, old.receipt.Generation, &cursor, fetch)
	if e != nil {
		return result, e
	}
	receipt := old.receipt
	receipt.Acquisition = "https-osv-incremental"
	result, e = publishSourceDraft(tx.work, tx, draft, receipt, old.manifest.Source.ExportedAt.Value, false)
	// The sealed cursor may exist before publication, but only this actual
	// activation result commits its point for the operation's caller.
	result.point = committedCursor(cursor.Point, candidate.Point, e == nil)
	return result, e
}
