package integrityscan

import (
	"context"
	"testing"

	"packtrace/internal/projectinventory"
)

func TestBunOriginRequiresNewOperationalSchema(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	plan, fixture := bunEligibleFixture(t, info)
	plan.Privacy = "portable"
	var decisions []AdvisoryDecision
	summary, err := MatchInventory(context.Background(), plan, fixture.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error {
		decisions = append(decisions, d)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	advisories := AdvisoryReport{State: "observed", Decisions: decisions, Summary: summary}
	for _, d := range decisions {
		if d.EnforcementEligible {
			advisories.Findings++
		}
	}
	if advisories.Findings != 2 {
		t.Fatal("nonvacuous locked and installed Bun findings required", decisions)
	}
	inventory := projectinventory.PortableMatching(fixture.inv)
	legacy := BuildReportWithAdvisories(plan, nil, Summary{}, Resources{}, false, false, &inventory, &info, &advisories)
	if legacy.Advisories == nil || legacy.Advisories.State != "observed" {
		t.Fatal("test must reach historical rendering with otherwise valid Bun evidence")
	}
	if validRenderedAdvisories(legacy) {
		t.Fatal("new Bun authority marker silently appeared in historical schema")
	}
	current := BuildReportWithPolicy(plan, nil, Summary{}, Resources{}, false, false, &inventory, &info, &advisories, nil, false, matchingNow)
	if current.SchemaVersion != "1.8" {
		t.Fatal("new report contract missing", current.SchemaVersion)
	}
	for _, format := range []string{"json", "terminal", "sarif"} {
		if _, err := Render(current, format); err != nil {
			t.Fatal(format, err)
		}
	}
}
