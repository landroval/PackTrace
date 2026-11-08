package integrityscan

import (
	"strings"
	"testing"

	"packtrace/internal/projectinventory"
)

func TestTerminalLimitsFoldOnlyEquivalentWarnings(t *testing.T) {
	// Presentation-only data: no report authority is created by this helper test.
	r := Report{ExitCode: 3, Privacy: "portable", Inventory: &projectinventory.PublicInventory{
		Complete: false, Gaps: []projectinventory.Gap{{Code: "installed-manifest-unavailable"}},
	}, Intelligence: &Intelligence{State: "available", CheckAge: "expired", ReconciliationAge: "current", Gaps: []string{"source-check-expired", "identity-unqualified", "advisory-originals-lazy", "storage-usage-not-observed"}},
		Advisories: &AdvisoryReport{State: "observed", Summary: AdvisorySummary{Gaps: []string{"inventory-incomplete", "source-stale", "identity-byte-limit", "identity-unqualified", "index-completeness"}}},
		Coverage:   []Coverage{{Check: "inventory", Required: true, Outcome: "incomplete"}, {Check: "native-qualification", Required: true, Outcome: "incomplete"}},
	}
	text := string(renderTerminalSummary(r))
	for _, label := range []string{"Summary", "Packages to review", "Coverage limitations", "installed manifests unavailable: 1 gap records", "advisory read byte limit reached", "exhaustive advisory coverage unverified", "Platform qualification"} {
		if !strings.Contains(text, label) {
			t.Fatal("limitation lost", label, text)
		}
	}
	if strings.Count(text, "advisory source check expired") != 1 || strings.Contains(text, "source stale") || strings.Contains(text, "inventory incomplete") {
		t.Fatal("equivalent warnings still repeated", text)
	}
	if strings.Count(text, "identity unqualified") != 2 {
		t.Fatal("unrelated identity scopes were merged", text)
	}
	if strings.Count(text, "storage usage not measured") != 1 || strings.Contains(text, "originals lazy") {
		t.Fatal("technical scope was repeated or lost", text)
	}
	if !strings.Contains(text, "packtrace intel sync --state-dir DIR") || !strings.Contains(text, "cannot fix unreadable manifests") {
		t.Fatal("no actionable next step")
	}
	if len(r.Advisories.Summary.Gaps) != 5 || len(r.Intelligence.Gaps) != 4 {
		t.Fatal("display changed report evidence")
	}
	// With no specific freshness evidence, the generic marker must remain visible.
	r.Intelligence = nil
	if !strings.Contains(string(renderTerminalSummary(r)), "source stale") {
		t.Fatal("unexplained stale marker silently dropped")
	}
}
