package integrityscan

import (
	"context"
	"testing"

	"packtrace/internal/projectinventory"
)

func TestCandidateWitnessJoinsRejectSameScopeSubstitution(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	plan := matchingPinnedPlan(t, info)
	plan.Policy.AdvisoryCandidates = true
	f := candidateFixture()
	f.inv.Model.Evidence = append(f.inv.Model.Evidence, projectinventory.Evidence{ID: 4, Scope: 1, Location: "node_modules/other", Method: "native-metadata-lease", Complete: true}, projectinventory.Evidence{ID: 5, Scope: 1, Location: "node_modules/other/package.json", Method: "native-input-lease", Complete: true})
	var rows []AdvisoryDecision
	_, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if err != nil {
		t.Fatal(err)
	}
	public := projectinventory.PortableMatching(f.inv)
	if public.Selection.Evidence != 1 || public.Evidence[2].MetadataEvidence != 2 || projectinventory.ValidatePublic(public) != nil {
		t.Fatal("missing independent endpoint joins")
	}
	checked := 0
	for _, d := range rows {
		if d.Advisory == 0 {
			continue
		}
		if ValidateAdvisoryDecision(plan, public, info, d) != nil {
			t.Fatal("valid assessed row", d)
		}
		forged := projectinventory.PortableMatching(f.inv)
		if d.Observation == 1 {
			forged.Observations[0].Source = 3
		} else {
			forged.Observations[1].MetadataEvidence = 4
		}
		if projectinventory.ValidatePublic(forged) == nil && ValidateAdvisoryDecision(plan, forged, info, d) == nil {
			t.Fatal("same-scope witness/source substitution admitted", d.Candidate, d.Observation)
		}
		checked++
	}
	if checked != 6 {
		t.Fatal("active and inactive assessed rows not exercised", checked)
	}
}

func TestCandidateDroppedRequirementsCannotHideLockedAlias(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	plan := matchingPinnedPlan(t, info)
	plan.Policy.AdvisoryCandidates = true
	for _, code := range []string{"requirement-limit", "gap-list-truncated"} {
		f := candidateFixture()
		f.inv.Complete = false
		f.inv.Model.Observations[0].Fields["name-qualification"] = "explicit-claim"
		f.inv.Model.Observations[0].Requirements = nil
		f.inv.Model.Gaps = []projectinventory.Gap{{Scope: 1, Evidence: 1, Code: code}}
		var rows []AdvisoryDecision
		_, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
		if err != nil {
			t.Fatal(err)
		}
		physical := false
		for _, d := range rows {
			if d.Observation == 1 && (d.Advisory != 0 || d.Candidate) {
				t.Fatal("truncated aliases allowed lock lookup", code, d)
			}
			physical = physical || d.Observation == 2 && d.Candidate
			if ValidateAdvisoryDecision(plan, projectinventory.PortableMatching(f.inv), info, d) != nil {
				t.Fatal("partial candidate row rejected", d)
			}
		}
		if !physical {
			t.Fatal("independent own-manifest candidate was lost", code)
		}
	}
}
