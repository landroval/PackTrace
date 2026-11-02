package intelstore

import (
	"packtrace/internal/intel"
	"testing"
	"time"
)

func TestReconciliationDueUsesExactSevenDayBoundary(t *testing.T) {
	old := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	source := intel.SnapshotSource{LastFullReconciliation: intel.OSVTimestamp{State: intel.TimestampValue, Value: old}}
	if reconciliationDue(source, old.Add(7*24*time.Hour)) {
		t.Fatal("exact boundary expired")
	}
	if !reconciliationDue(source, old.Add(7*24*time.Hour+time.Nanosecond)) {
		t.Fatal("expired full check stayed incremental")
	}
	if !reconciliationDue(source, old.Add(-time.Nanosecond)) {
		t.Fatal("future source time granted currentness")
	}
}
