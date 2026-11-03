package integrityscan

import (
	"encoding/hex"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	"packtrace/internal/projectinventory"
)

// Storage occupation is deliberately nullable: a readonly snapshot pin does
// not perform writer-serialized quota/reservation reconciliation or claim zero.
type Intelligence struct {
	ID                string   `json:"id"`
	State             string   `json:"state"`
	Selection         string   `json:"selection"`
	Provenance        string   `json:"provenance"`
	CheckAge          string   `json:"checkAge"`
	ReconciliationAge string   `json:"reconciliationAge"`
	Records           *uint64  `json:"records"`
	Objects           *uint64  `json:"objects"`
	Bytes             *uint64  `json:"bytes"`
	Reserved          *uint64  `json:"reserved"`
	Gaps              []string `json:"gaps"`
}

func UnavailableIntelligence() Intelligence {
	return Intelligence{State: "unavailable", Selection: "none", Provenance: "unknown", CheckAge: "unknown", ReconciliationAge: "unknown", Gaps: []string{"state-unavailable", "storage-usage-not-observed"}}
}
func intelligenceAge(v intel.FreshnessState) string {
	switch v {
	case intel.FreshnessUnknown:
		return "unknown"
	case intel.FreshnessCurrent:
		return "current"
	case intel.FreshnessExpired:
		return "expired"
	}
	return ""
}
func SnapshotIntelligence(v intelstore.Observation, selection string) Intelligence {
	n := v.Records
	gaps := make([]string, 0, len(v.Gaps)+2)
	for _, g := range v.Gaps {
		gaps = append(gaps, string(g))
	}
	gaps = append(gaps, "advisory-originals-lazy", "storage-usage-not-observed")
	return Intelligence{ID: v.Generation, State: "available", Selection: selection, Provenance: string(v.SourceAuthority), CheckAge: intelligenceAge(v.Check), ReconciliationAge: intelligenceAge(v.FullReconciliation), Records: &n, Gaps: gaps}
}
func ValidateIntelligence(v Intelligence) error {
	if v.Objects != nil || v.Bytes != nil || v.Reserved != nil || v.Gaps == nil || len(v.Gaps) > 12 {
		return ErrOptions
	}
	if v.State == "unavailable" {
		want := UnavailableIntelligence()
		if v.ID != "" || v.Selection != want.Selection || v.Provenance != want.Provenance || v.CheckAge != want.CheckAge || v.ReconciliationAge != want.ReconciliationAge || v.Records != nil || len(v.Gaps) != len(want.Gaps) {
			return ErrOptions
		}
		for i, g := range want.Gaps {
			if v.Gaps[i] != g {
				return ErrOptions
			}
		}
		return nil
	}
	raw, e := hex.DecodeString(v.ID)
	if e != nil || len(raw) != 32 || hex.EncodeToString(raw) != v.ID || [32]byte(raw) == ([32]byte{}) || v.State != "available" || !oneOf(v.Selection, "current", "previous-fallback", "expected-digest") || !oneOf(v.Provenance, "unqualified", "local-acquisition", "operator-designated") || v.Records == nil || *v.Records > 2_000_000 {
		return ErrOptions
	}
	for _, a := range []string{v.CheckAge, v.ReconciliationAge} {
		if !oneOf(a, "unknown", "current", "expired") {
			return ErrOptions
		}
	}
	if v.Provenance == "unqualified" && (v.CheckAge != "unknown" || v.ReconciliationAge != "unknown") {
		return ErrOptions
	}
	seen := map[string]bool{}
	for _, g := range v.Gaps {
		if seen[g] || !oneOf(g, "source-unqualified", "source-check-unknown", "source-check-expired", "full-reconciliation-unknown", "full-reconciliation-expired", "previous-generation-fallback", "identity-unqualified", "advisory-time-unqualified", "known-id-unresolved", "advisory-originals-lazy", "storage-usage-not-observed") {
			return ErrOptions
		}
		seen[g] = true
	}
	if !seen["advisory-originals-lazy"] || !seen["storage-usage-not-observed"] || seen["source-unqualified"] != (v.Provenance == "unqualified") || seen["source-check-unknown"] != (v.CheckAge == "unknown") || seen["source-check-expired"] != (v.CheckAge == "expired") || seen["full-reconciliation-unknown"] != (v.ReconciliationAge == "unknown") || seen["full-reconciliation-expired"] != (v.ReconciliationAge == "expired") || seen["previous-generation-fallback"] != (v.Selection == "previous-fallback") {
		return ErrOptions
	}
	return nil
}
func BuildReportWithIntelligence(plan Plan, records []Record, summary Summary, resources Resources, interrupted, abnormal bool, inventory *projectinventory.PublicInventory, intelligence *Intelligence) Report {
	r := BuildReportWithInventory(plan, records, summary, resources, interrupted, abnormal, inventory)
	if intelligence == nil {
		return r
	}
	copy := *intelligence
	if ValidateIntelligence(copy) != nil {
		copy = UnavailableIntelligence()
	}
	copy.Gaps = append([]string(nil), copy.Gaps...)
	if copy.Records != nil {
		n := *copy.Records
		copy.Records = &n
	}
	r.SchemaVersion = "1.2"
	r.Intelligence = &copy
	outcome := "incomplete"
	if copy.State == "available" && !abnormal && !resources.QueryFailed && !resources.Stale && !resources.Stopped {
		outcome = "completed"
	}
	r.Coverage = append(r.Coverage, Coverage{Check: "intelligence-access", Required: true, Outcome: outcome, Reason: "fixed-generation-metadata-and-catalog-only; original-objects-lazy; matching-not-implemented; storage-usage-not-observed"})
	return r
}
