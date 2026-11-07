package integrityscan

import (
	"context"
	"testing"

	"packtrace/internal/projectinventory"
)

func TestOldExactOriginPolicyDoesNotImplicitlyGrantInstalledAssociation(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	fixture := matchingInstalledFixture().inv
	plan := matchingPinnedPlan(t, info)
	if plan.Policy.NPMRegistry != "" {
		t.Fatal("this control must use the old locked-only policy")
	}
	var locked AdvisoryDecision
	installed := 0
	_, e := MatchInventory(context.Background(), plan, fixture, snapshot, info, matchingNow, func(d AdvisoryDecision) error {
		if d.Observation == 1 && d.EnforcementEligible {
			locked = d
		}
		if d.Observation == 2 {
			installed++
			if d.Origin != "unqualified" || d.Outcome != "indeterminate" || d.LockedObservation != 0 || d.EnforcementEligible {
				t.Fatal("old exact grant silently gained installed authority", d)
			}
		}
		return nil
	})
	if e != nil || installed != 1 || !locked.EnforcementEligible {
		t.Fatal("legacy locked finding or explicit installed unknown lost", e, installed)
	}
	forged := locked
	forged.Observation, forged.LockedObservation = 2, 1
	if ValidateAdvisoryDecision(plan, projectinventory.PortableMatching(fixture), info, forged) == nil {
		t.Fatal("forged installed authority from old policy accepted")
	}
}
