package intelstore

import (
	"context"
	"packtrace/internal/intel"
	"testing"
	"time"
)

func TestFreshnessObservationHasExactIndependentBoundaries(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fetch, close := fullSourceFixture(t, "success")
	defer close()
	result, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if e != nil {
		t.Fatal(e)
	}
	state, e := s.loadSourceState(ctx, result.Generation)
	if e != nil {
		t.Fatal(e)
	}
	pin, e := s.Pin(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	for _, tt := range []struct {
		now         time.Time
		check, full intel.FreshnessState
	}{
		{state.receipt.CheckedAt.Add(24 * time.Hour), intel.FreshnessCurrent, intel.FreshnessCurrent},
		{state.receipt.CheckedAt.Add(24*time.Hour + time.Nanosecond), intel.FreshnessExpired, intel.FreshnessCurrent},
		{state.receipt.ReconciledAt.Add(7 * 24 * time.Hour), intel.FreshnessExpired, intel.FreshnessCurrent},
		{state.receipt.ReconciledAt.Add(7*24*time.Hour + time.Nanosecond), intel.FreshnessExpired, intel.FreshnessExpired},
		{state.receipt.CheckedAt.Add(-time.Nanosecond), intel.FreshnessUnknown, intel.FreshnessUnknown},
	} {
		got, e := s.Observe(ctx, pin, tt.now, nil)
		if e != nil || got.Check != tt.check || got.FullReconciliation != tt.full || got.SourceAuthority != SourceLocal {
			t.Fatal("source ages/authority conflated", got, e)
		}
	}
}
func TestRawSnapshotObservationCannotGrantOwnSourceTrust(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fixtureGeneration(t, s, "OWNED-1", "2026-11-01T00:00:00Z")
	pin, e := s.Pin(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	got, e := s.Observe(ctx, pin, time.Now(), nil)
	if e != nil || got.SourceAuthority != SourceUnqualified || got.Check != intel.FreshnessUnknown || got.Records != 1 {
		t.Fatal("raw text authorized freshness or data lost", got, e)
	}
}
