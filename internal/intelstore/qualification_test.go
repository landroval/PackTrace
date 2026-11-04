package intelstore

import (
	"bytes"
	"context"
	"packtrace/internal/intel"
	"testing"
	"time"
)

func TestPreparationCannotOmitAnotherRequiredAffectedSlot(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	const raw = `{"id":"OWNED-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"}},{"package":{"ecosystem":"npm","name":"left-pad"}}]}`
	data := ownedArchive(t, []archiveRecord{{"OWNED-1.json", raw, 0}})
	draft, e := prepareArchive(ctx, tx, bytes.NewReader(data), int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	if tx.prep.record.Records != 1 || tx.prep.record.Memberships != 2 {
		t.Fatal("a required affected slot disappeared from preparation", tx.prep.record.Memberships)
	}
	id, e := tx.seal(ctx, draft)
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.activate(ctx, id); e != nil {
		t.Fatal(e)
	}
	snapshot, e := s.ReadPinned(ctx, &id)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	got, e := snapshot.ReadIdentity(ctx, "left-pad")
	if e != nil || len(got.Records) != 1 || len(got.Records[0].Bindings) != 2 {
		t.Fatal("real reader lost duplicate identity's independent affected slots", e, got)
	}
	for i, b := range got.Records[0].Bindings {
		if b.SourceOrdinal != 0 || b.AffectedIndex != uint64(i) {
			t.Fatal("required ordinal/slot binding changed", b)
		}
	}
}

func TestFailedActualSourceUpdateCannotRenewExpiredObservationOrCursor(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fetch, closeBase := fullSourceFixture(t, "success")
	defer closeBase()
	initial, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if e != nil {
		t.Fatal(e)
	}
	old, e := s.loadSourceState(ctx, initial.Generation)
	if e != nil {
		t.Fatal(e)
	}
	oldCursor, e := s.readSourceCursor(ctx, old.descriptor.Cursor)
	if e != nil {
		t.Fatal(e)
	}
	pin, e := s.Pin(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	clock := old.receipt.CheckedAt.Add(24*time.Hour + time.Nanosecond)
	before, e := s.Observe(ctx, pin, clock, nil)
	if e != nil || before.Check != intel.FreshnessExpired {
		t.Fatal("positive expired baseline", before, e)
	}
	rejected, closeRejected := fullSourceFixture(t, "wrong-id-update")
	defer closeRejected()
	if _, e := s.syncIncremental(ctx, &Budget{StagingBytes: 16 << 20}, rejected, old); e == nil {
		t.Fatal("wrong-ID source update succeeded")
	}
	current, e := s.loadSourceState(ctx, initial.Generation)
	if e != nil {
		t.Fatal(e)
	}
	cursor, e := s.readSourceCursor(ctx, current.descriptor.Cursor)
	if e != nil || cursor != oldCursor || !current.receipt.CheckedAt.Equal(old.receipt.CheckedAt) {
		t.Fatal("failed update changed the selected source clock/cursor", e)
	}
	after, e := s.Observe(ctx, pin, clock, nil)
	if e != nil || after.Check != intel.FreshnessExpired || after.Generation != before.Generation {
		t.Fatal("failed update renewed expired evidence", after, e)
	}
}
