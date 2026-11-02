package intelstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"packtrace/internal/intel"
	"time"
)

type sourceCursor struct {
	Version                    int
	Point                      cursorPoint
	Generation, BaseGeneration string
	SHA256                     [32]byte
	Bytes                      uint64
	Metadata                   ObjectRef
}

func (s *Store) readSourceCursor(ctx context.Context, ref ObjectRef) (sourceCursor, error) {
	var c sourceCursor
	if zeroRef(ref) {
		return c, ErrUntrusted
	}
	raw, e := s.readRef(ctx, ref, 4096)
	if e != nil {
		return c, e
	}
	if !strictObject(raw, 4096, "Version", "Point", "Generation", "BaseGeneration", "SHA256", "Bytes", "Metadata") || json.Unmarshal(raw, &c) != nil || c.Version != 1 || c.Bytes > 256<<20 || !publicRecordID(c.Point.ID) || intel.ProjectOSVTimestampText(c.Point.Modified).State != intel.TimestampValue {
		return c, ErrCorrupt
	}
	return c, nil
}
func joinStoredChanges(ctx context.Context, t *Transaction, ids, groups ObjectRef, emit func(updateAction) error) error {
	old, e := t.store.objectReader(ctx, ids)
	if e != nil {
		return e
	}
	changes, e := t.store.objectReader(ctx, groups)
	if e != nil {
		old.Close()
		return e
	}
	e = joinSourceChanges(ctx, old, changes, emit)
	return errors.Join(e, old.Close(), changes.Close())
}
func prepareListing(ctx context.Context, t *Transaction, base generationDraft, prep preparationRecord, baseline time.Time, baseGeneration string, old *sourceCursor, fetch sourceFetch) (draft generationDraft, cursor sourceCursor, failure error) {
	meta, metadataBytes, e := readSourceMetadata(ctx, t, requestChanges, fetch)
	if e != nil {
		return draft, cursor, e
	}
	original, sum, e := captureSourceBody(ctx, t, requestChanges, meta, fetch)
	if e != nil {
		return draft, cursor, e
	}
	defer func() { failure = errors.Join(failure, original.Close()) }()
	if old != nil && old.Generation == meta.Generation && (old.SHA256 != sum || old.Bytes != meta.Size) {
		return draft, cursor, ErrUntrusted
	}
	cutoff := baseline.Add(-time.Minute)
	if old != nil {
		stamp := intel.ProjectOSVTimestampText(old.Point.Modified)
		if stamp.State != intel.TimestampValue {
			return draft, cursor, ErrCorrupt
		}
		cutoff = stamp.Value.Add(-time.Minute)
	}
	groups, point, e := collectChanges(ctx, t, io.NewSectionReader(original, 0, original.Size()), time.Now(), cutoff)
	if e != nil {
		return draft, cursor, e
	}
	if point.Modified == "" {
		return draft, cursor, ErrUntrusted
	}
	if old != nil {
		previous, next := intel.ProjectOSVTimestampText(old.Point.Modified), intel.ProjectOSVTimestampText(point.Modified)
		if next.Value.Before(previous.Value) {
			return draft, cursor, ErrUntrusted
		}
	}
	var requests uint64
	if e := joinStoredChanges(ctx, t, prep.SourceIDs, groups, func(a updateAction) error {
		if a.Fetch {
			requests++
		}
		return nil
	}); e != nil {
		return draft, cursor, e
	}
	if t.budget.Requests >= 9999 || requests > 9999-t.budget.Requests {
		return draft, cursor, ErrLimit
	}
	if requests == 0 {
		draft = base
		t.prep = &preparationState{record: prep}
	} else {
		t.prep = &preparationState{record: preparationRecord{Version: 1, Source: "caller-supplied"}}
		if e := joinStoredChanges(ctx, t, prep.SourceIDs, groups, func(a updateAction) error { return applySourceAction(ctx, t, a, fetch) }); e != nil {
			return draft, cursor, e
		}
		draft, e = buildIndexes(ctx, t)
		if e != nil {
			return draft, cursor, e
		}
	}
	after, _, e := readSourceMetadata(ctx, t, requestChanges, fetch)
	if e != nil || after != meta {
		return draft, cursor, ErrUntrusted
	}
	if e := original.Stable(); e != nil {
		return draft, cursor, ErrCorrupt
	}
	metadata, e := t.put(ctx, bytes.NewReader(metadataBytes), uint64(len(metadataBytes)))
	if e != nil {
		return draft, cursor, e
	}
	cursor = sourceCursor{Version: 1, Point: point, Generation: meta.Generation, BaseGeneration: baseGeneration, SHA256: sum, Bytes: meta.Size, Metadata: metadata}
	raw, e := json.Marshal(cursor)
	if e != nil {
		return draft, cursor, ErrCorrupt
	}
	ref, e := t.put(ctx, bytes.NewReader(raw), uint64(len(raw)))
	if e != nil {
		return draft, cursor, e
	}
	draft.Cursor = ref
	draft.Objects = append(draft.Objects, ref, metadata)
	return draft, cursor, nil
}
