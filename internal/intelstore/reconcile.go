package intelstore

import (
	"bufio"
	"context"
	"errors"
	"io"
)

func joinFullKnown(ctx context.Context, old, candidate io.Reader, emit func(updateAction) error) error {
	oldScan, newScan := bufio.NewScanner(old), bufio.NewScanner(candidate)
	oldScan.Buffer(make([]byte, 4096), 32<<10)
	newScan.Buffer(make([]byte, 4096), 32<<10)
	leftCursor, rightCursor := &sourceIDCursor{scan: oldScan}, &sourceIDCursor{scan: newScan}
	left, e := leftCursor.next()
	if e != nil {
		return e
	}
	right, e := rightCursor.next()
	if e != nil {
		return e
	}
	var count uint64
	for left != nil || right != nil {
		if e := ctx.Err(); e != nil {
			return e
		}
		var action updateAction
		if right == nil || left != nil && left.ID < right.ID {
			action = updateAction{ID: left.ID, Old: left, Fetch: true}
			left, e = leftCursor.next()
		} else if left == nil || right.ID < left.ID {
			action = updateAction{ID: right.ID, Old: right}
			right, e = rightCursor.next()
		} else {
			action = updateAction{ID: right.ID, Old: right}
			left, e = leftCursor.next()
			if e == nil {
				right, e = rightCursor.next()
			}
		}
		if e != nil {
			return e
		}
		if count >= 2_000_000 {
			return ErrLimit
		}
		count++
		if e := emit(action); e != nil {
			return e
		}
	}
	return nil
}
func reconcileKnown(ctx context.Context, t *Transaction, base generationDraft, prep preparationRecord, old sourceState, fetch sourceFetch) (generationDraft, error) {
	pass := func(emit func(updateAction) error) error {
		previous, e := t.store.objectReader(ctx, old.preparation.SourceIDs)
		if e != nil {
			return e
		}
		next, e := t.store.objectReader(ctx, prep.SourceIDs)
		if e != nil {
			previous.Close()
			return e
		}
		e = joinFullKnown(ctx, previous, next, emit)
		return errors.Join(e, previous.Close(), next.Close())
	}
	var missing uint64
	if e := pass(func(a updateAction) error {
		if a.Fetch {
			missing++
		}
		return nil
	}); e != nil {
		return generationDraft{}, e
	}
	if missing == 0 {
		return base, nil
	}
	if t.budget.Requests >= 10000 || missing > 10000-t.budget.Requests {
		return generationDraft{}, ErrLimit
	}
	t.prep = &preparationState{record: preparationRecord{Version: 1, Source: "caller-supplied"}}
	if e := pass(func(a updateAction) error { return applySourceAction(ctx, t, a, fetch) }); e != nil {
		return generationDraft{}, e
	}
	draft, e := buildIndexes(ctx, t)
	if e != nil {
		return draft, e
	}
	// Global listing state is still the already verified source cursor; disappeared
	// known IDs are kept independently through their explicit source dispositions.
	draft.Cursor = base.Cursor
	if !zeroRef(base.Cursor) {
		cursor, e := t.store.readSourceCursor(ctx, base.Cursor)
		if e != nil {
			return draft, e
		}
		draft.Objects = append(draft.Objects, base.Cursor, cursor.Metadata)
	}
	return draft, nil
}
