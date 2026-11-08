package integrityscan

import (
	"context"
	"testing"

	"packtrace/internal/projectinventory"
)

func TestBunCandidatesKeepOriginalTuplesAndOptIn(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	for _, enabled := range []bool{false, true} {
		f := matchingInstalledFixture()
		f.inv.Selection.Family = "bun"
		f.inv.Selection.Profile = "bun@1.3.x"
		f.inv.Selection.File = "bun.lock"
		f.inv.Model.Evidence[0].Location = "bun.lock"
		o := &f.inv.Model.Observations[0]
		o.Kind = "package"
		o.Location = "left-pad"
		o.Origin = ""
		o.Fields = map[string]string{"name-state": "value", "resolution-state": "value", "registry-state": "value", "tuple-key": "left-pad"}
		f.inv.Model.Relations = nil
		plan := matchingPinnedPlan(t, info)
		plan.Manager = "bun@1.3.x"
		plan.Policy.Manager = plan.Manager
		plan.Policy.NPMOrigins = nil
		plan.Policy.AdvisoryCandidates = enabled
		var rows []AdvisoryDecision
		s, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
		if err != nil {
			t.Fatal(err)
		}
		active := 0
		for _, d := range rows {
			if ValidateAdvisoryDecision(plan, projectinventory.PortableMatching(f.inv), info, d) != nil {
				t.Fatal("Bun endpoint rejected", d)
			}
			if d.Candidate {
				active++
			}
			if d.EnforcementEligible || d.Origin != "unqualified" || d.LockedObservation != 0 || d.Rule != 0 || d.Outcome != "indeterminate" {
				t.Fatal("Bun candidate promoted", d)
			}
		}
		if enabled && (active != 2 || s.BytesRead == 0) || !enabled && (active != 0 || s.BytesRead != 0) {
			t.Fatal("candidate opt-in/identity reads", enabled, active, s)
		}
	}
}
