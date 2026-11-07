package intelstore

import (
	"context"
	"testing"
)

func TestPruneCanConfirmAndApplyAtExactLogicalQuotaWithoutUnreservedPayload(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fixtureGeneration(t, s, "FIRST-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "SECOND-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "THIRD-1", "2026-11-01T00:00:00Z")
	writer, e := s.root.TryOwnedLock(ctx, "writer.lock", true)
	if e != nil {
		t.Fatal(e)
	}
	quota, e := s.observeQuota(ctx, writer, 32<<30)
	writer.Close()
	if e != nil {
		t.Fatal(e)
	}
	s.quotaLimit = quota.used
	preview, e := s.PreviewPrune(ctx)
	if e != nil {
		t.Fatal("full logical quota blocked zero-payload confirmation", e)
	}
	result, e := s.ApplyPrune(ctx, preview.Token)
	if e != nil || result.RemovedBytes == 0 {
		t.Fatal("could not recover confirmed owned bytes at full quota", e)
	}
}
