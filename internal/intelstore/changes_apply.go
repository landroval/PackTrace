package intelstore

import (
	"bytes"
	"context"
	"encoding/json"
	"packtrace/internal/intel"
	"time"
)

func (b *Budget) advisory(n uint64) error {
	if b == nil || b.ExpandedBytes > 8<<30 || n > (8<<30)-b.ExpandedBytes {
		return ErrLimit
	}
	b.ExpandedBytes += n
	return nil
}
func (t *Transaction) existingAdvisory(ctx context.Context, ref ObjectRef) ([]byte, error) {
	if ref.Bytes > 4<<20 {
		return nil, ErrLimit
	}
	if e := t.budget.advisory(ref.Bytes); e != nil {
		return nil, e
	}
	raw, e := t.store.readRef(ctx, ref, 4<<20)
	if e != nil {
		return nil, e
	}
	// The completed, verified read transfers its charge directly to the common
	// preparation call. Failed/uncertain reads remain conservatively charged.
	t.budget.ExpandedBytes -= ref.Bytes
	return raw, nil
}
func applySourceAction(ctx context.Context, t *Transaction, a updateAction, fetch sourceFetch) error {
	if t == nil || t.prep == nil || fetch == nil || !publicRecordID(a.ID) || a.Old != nil && a.Old.ID != a.ID || a.Change != nil && a.Change.ID != a.ID {
		return ErrCorrupt
	}
	var raw []byte
	var existing *ObjectRef
	forced := sourceObserved
	if a.Fetch {
		var body bytes.Buffer
		ev, e := fetch(ctx, &t.budget, requestSpec{kind: requestRecord, id: a.ID}, &body)
		if e != nil {
			if charge := t.budget.advisory(uint64(body.Len())); charge != nil {
				return charge
			}
			return e
		}
		switch ev.status {
		case 200:
			raw = body.Bytes()
			if e := t.budget.advisory(uint64(len(raw))); e != nil {
				return e
			}
			if len(raw) > 4<<20 || ev.bytes != uint64(len(raw)) {
				return ErrCorrupt
			}
			doc, e := intel.ParseOSVRecord(raw)
			if e != nil {
				return ErrCorrupt
			}
			var observedID string
			if json.Unmarshal(doc.Fields["id"], &observedID) != nil || observedID != a.ID {
				return ErrCorrupt
			}
			times, e := intel.ProjectOSVTimes(doc)
			if e != nil || times.Modified.State != intel.TimestampValue || times.Modified.Value.After(time.Now()) {
				return ErrUntrusted
			}
			if a.Change != nil {
				listed := intel.ProjectOSVTimestampText(a.Change.Modified)
				if listed.State != intel.TimestampValue || times.Modified.Value.Before(listed.Value) {
					return ErrUntrusted
				}
			}
			t.budget.ExpandedBytes -= uint64(len(raw))
		case 404:
			if a.Old == nil {
				return ErrUnavailable
			}
			existing = &a.Old.Original
			forced = sourceUnresolved
		default:
			return ErrUnavailable
		}
	} else {
		if a.Old == nil {
			return ErrCorrupt
		}
		existing = &a.Old.Original
		if a.Old.Disposition == sourceUnresolved {
			forced = sourceUnresolved
		}
	}
	if existing != nil {
		var e error
		raw, e = t.existingAdvisory(ctx, *existing)
		if e != nil {
			return e
		}
	}
	return prepareOriginal(ctx, t, a.ID, raw, existing, forced)
}
