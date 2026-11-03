package integrityscan

import (
	"bytes"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	"strings"
	"testing"
)

func TestIntelligenceProjectionKeepsUnknownOccupationAndClosedAges(t *testing.T) {
	missing := UnavailableIntelligence()
	if ValidateIntelligence(missing) != nil || missing.Records != nil || missing.Objects != nil || missing.Bytes != nil || missing.Reserved != nil {
		t.Fatal("unknown source/occupation became successful zero")
	}
	id := strings.Repeat("1", 64)
	ob := intelstore.Observation{Generation: id, SourceAuthority: intelstore.SourceUnqualified, Check: intel.FreshnessUnknown, FullReconciliation: intel.FreshnessUnknown, Records: 1, Gaps: []intelstore.Gap{intelstore.GapSourceUnqualified, intelstore.GapCheckUnknown, intelstore.GapFullUnknown}}
	good := SnapshotIntelligence(ob, "current")
	if ValidateIntelligence(good) != nil || good.CheckAge != "unknown" || good.Provenance != "unqualified" {
		t.Fatal("source self-authorized freshness")
	}
	for _, change := range []func(*Intelligence){func(v *Intelligence) { v.ID = strings.Repeat("0", 64) }, func(v *Intelligence) { n := uint64(0); v.Reserved = &n }, func(v *Intelligence) { v.CheckAge = "current" }, func(v *Intelligence) { v.Gaps = append(v.Gaps, "PRIVATE") }} {
		bad := good
		bad.Gaps = append([]string{}, good.Gaps...)
		change(&bad)
		if ValidateIntelligence(bad) == nil {
			t.Fatal("unconfirmed source field admitted", bad)
		}
	}
}
func TestIntelligenceReportAddonPreservesLegacyBuildersAndNoMatching(t *testing.T) {
	plan := Plan{}
	base := BuildReportWithInventory(plan, nil, Summary{}, Resources{}, false, false, nil)
	if base.SchemaVersion != "1.1" || base.Intelligence != nil {
		t.Fatal("legacy report changed")
	}
	missing := UnavailableIntelligence()
	report := BuildReportWithIntelligence(plan, nil, Summary{}, Resources{}, false, false, nil, &missing)
	if report.SchemaVersion != "1.2" || report.ExitCode != 3 {
		t.Fatal("source access granted global completion")
	}
	for _, format := range []string{"terminal", "json", "sarif"} {
		data, e := Render(report, format)
		if e != nil || len(data) == 0 || bytes.Contains(data, []byte("PRIVATE")) {
			t.Fatal("closed intelligence render", format, e)
		}
	}
}
