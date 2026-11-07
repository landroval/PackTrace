package intelstore

import (
	"bytes"
	"context"
	"packtrace/internal/intel"
	"testing"
)

func TestSnapshotDiskReaderUsesActualPreparedGeneration(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	id := fixtureGeneration(t, s, "OWNED-1", "2026-11-01T00:00:00Z")
	snapshot, e := s.ReadPinned(ctx, &id)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		got, e := snapshot.ReadIdentity(ctx, "left-pad")
		if e != nil || len(got.Records) != 1 || got.Records[0].State != intel.SnapshotOriginalVerified || !bytes.Contains(got.Records[0].Raw, []byte(`"id":"OWNED-1"`)) {
			t.Fatal("actual original binding unavailable", e)
		}
	}
	if e := snapshot.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := snapshot.ReadIdentity(ctx, "left-pad"); e == nil {
		t.Fatal("closed snapshot retained read authority")
	}
}
