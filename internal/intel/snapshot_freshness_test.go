package intel

import (
	"reflect"
	"testing"
	"time"
)

func TestEvaluateSnapshotFreshnessBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		age  time.Duration
		want FreshnessState
	}{
		{"younger", 24*time.Hour - time.Nanosecond, FreshnessCurrent},
		{"exact", 24 * time.Hour, FreshnessCurrent},
		{"older", 24*time.Hour + time.Nanosecond, FreshnessExpired},
	} {
		t.Run("check-"+tc.name, func(t *testing.T) {
			source := SnapshotSource{LastSuccessfulCheck: OSVTimestamp{State: TimestampValue, Value: now.Add(-tc.age)}}
			got := EvaluateSnapshotFreshness(source, now, true)
			if got != (SnapshotFreshness{Check: tc.want}) {
				t.Fatalf("got %+v; want check %v, reconciliation unknown", got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		age  time.Duration
		want FreshnessState
	}{
		{"younger", 7*24*time.Hour - time.Nanosecond, FreshnessCurrent},
		{"exact", 7 * 24 * time.Hour, FreshnessCurrent},
		{"older", 7*24*time.Hour + time.Nanosecond, FreshnessExpired},
	} {
		t.Run("reconciliation-"+tc.name, func(t *testing.T) {
			source := SnapshotSource{LastFullReconciliation: OSVTimestamp{State: TimestampValue, Value: now.Add(-tc.age)}}
			got := EvaluateSnapshotFreshness(source, now, true)
			if got != (SnapshotFreshness{FullReconciliation: tc.want}) {
				t.Fatalf("got %+v; want reconciliation %v, check unknown", got, tc.want)
			}
		})
	}
}

func TestEvaluateSnapshotFreshnessUnusableEvidence(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		claim OSVTimestamp
	}{
		{"absent", OSVTimestamp{}},
		{"null", OSVTimestamp{State: TimestampNull}},
		{"wrong-type", OSVTimestamp{State: TimestampInvalidType}},
		{"uninterpretable", OSVTimestamp{State: TimestampUninterpretable, Text: "not a date"}},
		{"invalid-enum", OSVTimestamp{State: TimestampState(255), Value: now}},
		{"future", OSVTimestamp{State: TimestampValue, Value: now.Add(time.Nanosecond)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := SnapshotSource{LastSuccessfulCheck: tc.claim, LastFullReconciliation: tc.claim,
				AcquiredAt: OSVTimestamp{State: TimestampValue, Value: now}, ExportedAt: OSVTimestamp{State: TimestampValue, Value: now}}
			if got := EvaluateSnapshotFreshness(source, now, true); got != (SnapshotFreshness{}) {
				t.Fatalf("got %+v, want both unknown", got)
			}
		})
	}
	valid := OSVTimestamp{State: TimestampValue, Value: now}
	if got := EvaluateSnapshotFreshness(SnapshotSource{LastSuccessfulCheck: valid, LastFullReconciliation: valid}, now, false); got != (SnapshotFreshness{}) {
		t.Fatalf("untrusted source got %+v, want both unknown", got)
	}
}

func TestEvaluateSnapshotFreshnessParsedClaimsPreserved(t *testing.T) {
	m := snapshotTestBase()
	s := m["source"].(map[string]any)
	s["lastSuccessfulCheck"] = "0001-01-01T00:00:00Z"
	s["lastFullReconciliation"] = "2026-10-02T14:00:00+02:00"
	s["acquiredAt"] = "2026-10-02T12:00:00Z"
	s["exportedAt"] = "2026-10-02T12:00:00Z"
	source := snapshotTestSuccess(t, snapshotTestBytes(t, m)).Source
	original := source.LastSuccessfulCheck
	reconciliation := source.LastFullReconciliation
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	if got := EvaluateSnapshotFreshness(source, now, true); got != (SnapshotFreshness{Check: FreshnessExpired, FullReconciliation: FreshnessCurrent}) {
		t.Fatalf("got %+v, want expired check and current reconciliation", got)
	}
	if !reflect.DeepEqual(source.LastSuccessfulCheck, original) || !reflect.DeepEqual(source.LastFullReconciliation, reconciliation) || original.Text != "0001-01-01T00:00:00Z" || reconciliation.Text != "2026-10-02T14:00:00+02:00" {
		t.Fatal("original source timestamp evidence changed")
	}
}

func TestEvaluateSnapshotFreshnessExtremeDates(t *testing.T) {
	now := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	source := SnapshotSource{LastSuccessfulCheck: OSVTimestamp{State: TimestampValue, Value: time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)}, LastFullReconciliation: OSVTimestamp{State: TimestampValue, Value: time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)}}
	if got := EvaluateSnapshotFreshness(source, now, true); got != (SnapshotFreshness{Check: FreshnessExpired, FullReconciliation: FreshnessExpired}) {
		t.Fatalf("got %+v, want both expired", got)
	}
}
