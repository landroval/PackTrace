package intelstore

import (
	"context"
	"errors"
	"testing"
)

func TestSourceStateRequiresLocalAcquisitionSeal(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	unqualified := fixtureGeneration(t, s, "OWNED-1", "2026-11-01T00:00:00Z")
	if _, e := s.loadSourceState(ctx, unqualified); !errors.Is(e, ErrUntrusted) {
		t.Fatal("store text alone authorized source-derived lookups", e)
	}
	fetch, close := fullSourceFixture(t, "success")
	defer close()
	result, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if e != nil {
		t.Fatal(e)
	}
	state, e := s.loadSourceState(ctx, result.Generation)
	if e != nil || state.preparation.Records != 1 || zeroRef(state.preparation.SourceIDs) {
		t.Fatal("actual admitted source state unavailable", e)
	}
}
