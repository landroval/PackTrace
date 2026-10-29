package intel

import "time"

// FreshnessState classifies one timestamp claim, not snapshot coverage or activation.
type FreshnessState uint8

const (
	FreshnessUnknown FreshnessState = iota
	FreshnessCurrent
	FreshnessExpired
)

// SnapshotFreshness reports independent source-check and full-reconciliation ages.
type SnapshotFreshness struct {
	Check, FullReconciliation FreshnessState
}

// EvaluateSnapshotFreshness compares source claims against caller-supplied now.
// trusted is a caller assumption, not proof of publisher authenticity. This does
// not qualify trust, synchronize, renew dates, erase findings, or set exit status.
// Unknown includes absent, unusable, future, and untrusted evidence; exact
// 24-hour check and 7-day reconciliation age limits remain current.
func EvaluateSnapshotFreshness(source SnapshotSource, now time.Time, trusted bool) SnapshotFreshness {
	if !trusted {
		return SnapshotFreshness{}
	}
	return SnapshotFreshness{
		Check:              timestampFreshness(source.LastSuccessfulCheck, now, 24*time.Hour),
		FullReconciliation: timestampFreshness(source.LastFullReconciliation, now, 7*24*time.Hour),
	}
}

func timestampFreshness(claim OSVTimestamp, now time.Time, maxAge time.Duration) FreshnessState {
	if claim.State != TimestampValue || claim.Value.After(now) {
		return FreshnessUnknown
	}
	if now.After(claim.Value.Add(maxAge)) {
		return FreshnessExpired
	}
	return FreshnessCurrent
}
