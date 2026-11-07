package integrityscan

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"packtrace/internal/projectinventory"
)

func matchingInstalledFixture() matchingFixture {
	f := newMatchingFixture()
	f.inv.Model.Evidence = append(f.inv.Model.Evidence,
		projectinventory.Evidence{ID: 2, Scope: 1, Location: "node_modules/left-pad", Method: "native-metadata-lease", Complete: true},
		projectinventory.Evidence{ID: 3, Scope: 1, Location: "node_modules/left-pad/package.json", Method: "native-input-lease", Complete: true})
	f.inv.Model.Observations = append(f.inv.Model.Observations, projectinventory.Observation{ID: 2, Workspace: 1, Source: 3, Class: "installed", Kind: "directory", Status: "complete", Location: "node_modules/left-pad", Name: "left-pad", Version: "1.0.0", Fields: map[string]string{"installation-name": "left-pad", "physical-target": "node_modules/left-pad", "metadata-evidence": "2", "name-state": "value", "version-state": "value"}})
	f.inv.Model.Relations = []projectinventory.Relation{{From: 1, To: 2, Evidence: 3, Kind: "locked-correspondence", Status: "claim-agreement"}}
	return f
}

func TestMatchingInstalledOwnManifestAndCorrespondence(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	for _, tc := range []struct {
		name   string
		change func(*matchingFixture)
	}{
		{"agreement", func(*matchingFixture) {}},
		{"own-version-conflict", func(f *matchingFixture) {
			f.inv.Model.Observations[1].Version = "2.0.0"
			f.inv.Model.Relations[0].Status = "conflict"
		}},
		{"forged-agreement-version", func(f *matchingFixture) { f.inv.Model.Observations[1].Version = "2.0.0" }},
		{"own-name-conflict", func(f *matchingFixture) { f.inv.Model.Observations[1].Name = "other" }},
		{"own-location-conflict", func(f *matchingFixture) { f.inv.Model.Observations[1].Location = "node_modules/other" }},
		{"missing-relation", func(f *matchingFixture) { f.inv.Model.Relations = nil }},
		{"ambiguous-relation", func(f *matchingFixture) {
			f.inv.Model.Relations = append(f.inv.Model.Relations, f.inv.Model.Relations[0])
		}},
		{"wrong-relation-evidence", func(f *matchingFixture) { f.inv.Model.Relations[0].Evidence = 2 }},
		{"candidate-not-agreement", func(f *matchingFixture) { f.inv.Model.Relations[0].Kind = "candidate-correspondence" }},
		{"link", func(f *matchingFixture) { f.inv.Model.Observations[1].Kind = "link" }},
		{"unstable", func(f *matchingFixture) { f.inv.Model.Observations[1].Status = "unstable" }},
		{"manifest-incomplete", func(f *matchingFixture) { f.inv.Model.Evidence[2].Complete = false }},
		{"metadata-incomplete", func(f *matchingFixture) { f.inv.Model.Evidence[1].Complete = false }},
		{"metadata-wrong-method", func(f *matchingFixture) { f.inv.Model.Evidence[1].Method = "native-input-lease" }},
		{"metadata-wrong-location", func(f *matchingFixture) { f.inv.Model.Evidence[1].Location = "node_modules/other" }},
		{"alias", func(f *matchingFixture) { f.inv.Model.Observations[1].Fields["installation-name"] = "alias" }},
		{"unknown-version", func(f *matchingFixture) { f.inv.Model.Observations[1].Fields["version-state"] = "absent" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := matchingInstalledFixture()
			tc.change(&f)
			plan := matchingPinnedPlan(t, info)
			plan.Policy.NPMRegistry = "https://registry.npmjs.org"
			rows := []AdvisoryDecision{}
			s, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
			if err != nil {
				t.Fatal(err)
			}
			var installed []AdvisoryDecision
			for _, d := range rows {
				if d.Observation == 2 {
					installed = append(installed, d)
				}
			}
			if s.Observations != 1 || s.TotalObservations != 1 || s.InstalledObservations != 1 || s.TotalInstalledObservations != 1 {
				t.Fatal("scope", s)
			}
			if tc.name == "agreement" {
				if len(installed) != 3 || installed[0].Outcome != "match" || installed[0].LockedObservation != 1 {
					t.Fatal(installed)
				}
				public := projectinventory.PortableMatching(f.inv)
				if ValidateAdvisorySummary(s, rows, public) != nil {
					t.Fatal("closure")
				}
				for _, d := range rows {
					if ValidateAdvisoryDecision(plan, public, info, d) != nil {
						t.Fatal("decision", d)
					}
				}
			} else if len(installed) != 1 || installed[0].Outcome != "indeterminate" || installed[0].LockedObservation != 0 || installed[0].EnforcementEligible || installed[0].Advisory != 0 {
				t.Fatal("installed claim promoted", installed)
			}
		})
	}
}

func TestMatchingLocalCallbacksAreExplicitAndEquivalent(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	f := matchingInstalledFixture()
	plan := matchingPinnedPlan(t, info)
	plan.Policy.NPMRegistry = "https://registry.npmjs.org"
	var portable, localRows []AdvisoryDecision
	callbackCalls := 0
	ps, err := MatchInventoryWithLocal(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { portable = append(portable, d); return nil }, func(LocalAdvisory) error { callbackCalls++; return errors.New("unsolicited") })
	if err != nil || callbackCalls != 0 {
		t.Fatal(err, callbackCalls)
	}
	plan.Privacy = "local"
	var details []LocalAdvisory
	ls, err := MatchInventoryWithLocal(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { localRows = append(localRows, d); return nil }, func(v LocalAdvisory) error { details = append(details, v); return nil })
	if err != nil || !reflect.DeepEqual(ps, ls) || !reflect.DeepEqual(portable, localRows) || len(details) != 3 {
		t.Fatal("local changed matching", ps, ls, err)
	}
	for i, d := range details {
		if d.Advisory != i+1 || ValidateLocalAdvisory(d) != nil {
			t.Fatal(d)
		}
	}
	stop := errors.New("local-stop")
	if _, err := MatchInventoryWithLocal(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(AdvisoryDecision) error { return nil }, func(LocalAdvisory) error { return stop }); !errors.Is(err, stop) {
		t.Fatal("lost local callback error", err)
	}
	if _, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(AdvisoryDecision) error { return stop }); !errors.Is(err, stop) {
		t.Fatal("lost ordinary callback error", err)
	}
	plan.Policy.RequirePortable = true
	calls := 0
	if _, err := MatchInventoryWithLocal(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(AdvisoryDecision) error { calls++; return nil }, func(LocalAdvisory) error { calls++; return nil }); err == nil || calls != 0 {
		t.Fatal("privacy refusal after content", err, calls)
	}
}

func TestMatchingInstalledParentEndpointForgery(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	f := matchingInstalledFixture()
	plan := matchingPinnedPlan(t, info)
	plan.Policy.NPMRegistry = "https://registry.npmjs.org"
	var row AdvisoryDecision
	_, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error {
		if d.Observation == 2 && d.Outcome == "match" {
			row = d
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	public := projectinventory.PortableMatching(f.inv)
	for _, tc := range []struct {
		name   string
		change func(*AdvisoryDecision, *projectinventory.PublicInventory)
	}{
		{"missing-endpoint", func(d *AdvisoryDecision, _ *projectinventory.PublicInventory) { d.LockedObservation = 0 }},
		{"installed-as-locked", func(d *AdvisoryDecision, _ *projectinventory.PublicInventory) { d.LockedObservation = 2 }},
		{"out-of-range", func(d *AdvisoryDecision, _ *projectinventory.PublicInventory) { d.LockedObservation = 3 }},
		{"locked-row-with-endpoint", func(d *AdvisoryDecision, _ *projectinventory.PublicInventory) { d.Observation = 1 }},
		{"conflict", func(_ *AdvisoryDecision, p *projectinventory.PublicInventory) { p.Relations[0].Status = "conflict" }},
		{"relation-namespace", func(_ *AdvisoryDecision, p *projectinventory.PublicInventory) { p.Relations[0].Kind = "physical-link" }},
		{"incomplete-evidence", func(_ *AdvisoryDecision, p *projectinventory.PublicInventory) { p.Evidence[2].Status = "incomplete" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := row
			p := public
			p.Relations = append([]projectinventory.Relation{}, public.Relations...)
			p.Evidence = append([]projectinventory.PublicEvidence{}, public.Evidence...)
			tc.change(&d, &p)
			if ValidateAdvisoryDecision(plan, p, info, d) == nil {
				t.Fatal("forged endpoint admitted")
			}
		})
	}
}
