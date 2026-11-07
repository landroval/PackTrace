package integrityscan

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"packtrace/internal/projectinventory"
)

func candidateFixture() matchingFixture {
	f := matchingInstalledFixture()
	f.inv.Model.Observations[0].Origin = "https://private.invalid/owner-canary/left-pad.tgz"
	return f
}

func TestCandidateLocalLookupOptInAndSharedCopies(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	f := candidateFixture()
	plan := matchingPinnedPlan(t, info)
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			plan.Policy.AdvisoryCandidates = enabled
			var rows []AdvisoryDecision
			s, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
			if err != nil {
				t.Fatal(err)
			}
			public := projectinventory.PortableMatching(f.inv)
			if ValidateAdvisorySummary(s, rows, public) != nil {
				t.Fatal("summary", s)
			}
			active := 0
			for _, d := range rows {
				if ValidateAdvisoryDecision(plan, public, info, d) != nil {
					t.Fatalf("invalid row %+v", d)
				}
				if d.Candidate {
					active++
				}
				if d.Origin != "unqualified" || d.LockedObservation != 0 || d.Rule != 0 || d.Outcome != "indeterminate" || d.EnforcementEligible || !hasMatchingGap(d.Gaps, "origin-unqualified") {
					t.Fatal("origin promoted", d)
				}
				if d.Candidate && (d.Activity != "not-withdrawn" || d.VersionOutcome != "match") {
					t.Fatal(d)
				}
			}
			if enabled {
				if active != 2 || len(rows) != 6 || s.BytesRead == 0 {
					t.Fatal("missing candidates", active, rows, s)
				}
				for _, d := range rows {
					if d.Activity == "withdrawn" || d.Profile == "unknown" {
						if d.Candidate {
							t.Fatal("withdrawal/correction promoted", d)
						}
					}
				}
			} else if active != 0 || len(rows) != 2 || s.BytesRead != 0 {
				t.Fatal("opt-out read", rows, s)
			}
			encoded, _ := json.Marshal(rows)
			for _, secret := range []string{"left-pad", "private.invalid", "owner-canary", "node_modules", "sha256"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatal("portable leak", secret)
				}
			}
		})
	}
	plan.Policy.AdvisoryCandidates = true
	calls := 0
	plan.TrustedPolicyDigest = ""
	if s, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(AdvisoryDecision) error { calls++; return nil }); err == nil || calls != 0 || s.BytesRead != 0 {
		t.Fatal("missing pin not refused before access", s, err)
	}
}

func TestCandidateRawEndpoints(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	for _, tc := range []struct {
		name              string
		change            func(*matchingFixture)
		locked, installed bool
	}{
		{"private", func(*matchingFixture) {}, true, true},
		{"manager-family-mismatch", func(f *matchingFixture) { f.inv.Selection.Family = "bun" }, false, false},
		{"manager-profile-mismatch", func(f *matchingFixture) { f.inv.Selection.Profile = "npm@11.0.0" }, false, false},
		{"unknown-origin", func(f *matchingFixture) {
			f.inv.Model.Observations[0].Kind = "package"
			f.inv.Model.Observations[0].Origin = ""
			f.inv.Model.Observations[0].Fields["origin-state"] = "absent"
		}, true, true},
		{"no-correspondence", func(f *matchingFixture) { f.inv.Model.Relations = nil }, true, true},
		{"no-selected-lock", func(f *matchingFixture) { f.inv.Selection.State = "absent"; f.inv.Selection.Reason = "no-root-lock" }, false, true},
		{"installed-alias-slot", func(f *matchingFixture) { f.inv.Model.Observations[1].Fields["installation-name"] = "alias" }, true, true},
		{"lock-incomplete", func(f *matchingFixture) { f.inv.Model.Evidence[0].Complete = false }, false, true},
		{"manifest-incomplete", func(f *matchingFixture) { f.inv.Model.Evidence[2].Complete = false }, true, false},
		{"manifest-wrong-path", func(f *matchingFixture) { f.inv.Model.Evidence[2].Location = "other/package.json" }, true, false},
		{"metadata-incomplete", func(f *matchingFixture) { f.inv.Model.Evidence[1].Complete = false }, true, false},
		{"metadata-wrong-path", func(f *matchingFixture) { f.inv.Model.Evidence[1].Location = "node_modules/other" }, true, false},
		{"metadata-wrong-method", func(f *matchingFixture) { f.inv.Model.Evidence[1].Method = "native-metadata" }, true, false},
		{"missing-metadata", func(f *matchingFixture) { delete(f.inv.Model.Observations[1].Fields, "metadata-evidence") }, true, false},
		{"installed-unstable", func(f *matchingFixture) { f.inv.Model.Observations[1].Status = "unstable" }, true, false},
		{"installed-link", func(f *matchingFixture) { f.inv.Model.Observations[1].Kind = "link" }, true, false},
		{"installed-selector", func(f *matchingFixture) { f.inv.Model.Observations[1].Version = "^1.0.0" }, true, false},
		{"lock-alias-resolution", func(f *matchingFixture) { f.inv.Model.Observations[0].Version = "npm:left-pad@1.0.0" }, false, true},
		{"lock-selector", func(f *matchingFixture) { f.inv.Model.Observations[0].Version = "~1.0.0" }, false, true},
		{"lock-file", func(f *matchingFixture) { f.inv.Model.Observations[0].Kind = "file" }, false, true},
		{"lock-git", func(f *matchingFixture) { f.inv.Model.Observations[0].Kind = "git" }, false, true},
		{"lock-workspace", func(f *matchingFixture) { f.inv.Model.Observations[0].Kind = "workspace" }, false, true},
		{"generic-file", func(f *matchingFixture) {
			f.inv.Model.Observations[0].Kind = "package"
			f.inv.Model.Observations[0].Origin = "file:../local"
		}, false, true},
		{"lock-alias-name", func(f *matchingFixture) { f.inv.Model.Observations[0].Fields["installation-name"] = "alias" }, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := candidateFixture()
			tc.change(&f)
			plan := matchingPinnedPlan(t, info)
			plan.Policy.AdvisoryCandidates = true
			var rows []AdvisoryDecision
			_, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
			if err != nil {
				t.Fatal(err)
			}
			active := map[uint32]bool{}
			for _, d := range rows {
				active[d.Observation] = active[d.Observation] || d.Candidate
				if d.Outcome != "indeterminate" || d.EnforcementEligible || d.LockedObservation != 0 {
					t.Fatal(d)
				}
			}
			if active[1] != tc.locked || active[2] != tc.installed {
				t.Fatal("wrong physical endpoint", active, rows)
			}
		})
	}
}

func TestCandidateParentRejectsForgedAssessments(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	f := candidateFixture()
	plan := matchingPinnedPlan(t, info)
	plan.Policy.AdvisoryCandidates = true
	var rows []AdvisoryDecision
	_, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if err != nil {
		t.Fatal(err)
	}
	var candidate, inactive AdvisoryDecision
	for _, d := range rows {
		if d.Observation == 2 {
			if d.Candidate {
				candidate = d
			}
			if d.Activity == "withdrawn" {
				inactive = d
			}
		}
	}
	if !candidate.Candidate || inactive.Advisory == 0 {
		t.Fatal(rows)
	}
	for _, tc := range []struct {
		name   string
		change func(*Plan, *projectinventory.PublicInventory, *AdvisoryDecision)
	}{
		{"opt-out", func(p *Plan, _ *projectinventory.PublicInventory, _ *AdvisoryDecision) {
			p.Policy.AdvisoryCandidates = false
		}},
		{"no-pin", func(p *Plan, _ *projectinventory.PublicInventory, _ *AdvisoryDecision) { p.TrustedPolicyDigest = "" }},
		{"wrong-manager-family", func(_ *Plan, p *projectinventory.PublicInventory, _ *AdvisoryDecision) { p.Selection.Family = "bun" }},
		{"eligible", func(_ *Plan, _ *projectinventory.PublicInventory, d *AdvisoryDecision) { d.EnforcementEligible = true }},
		{"final-match", func(_ *Plan, _ *projectinventory.PublicInventory, d *AdvisoryDecision) { d.Outcome = "match" }},
		{"final-negative", func(_ *Plan, _ *projectinventory.PublicInventory, d *AdvisoryDecision) { d.Outcome = "no-match" }},
		{"lock-attribution", func(_ *Plan, _ *projectinventory.PublicInventory, d *AdvisoryDecision) { d.LockedObservation = 1 }},
		{"withdrawn", func(_ *Plan, _ *projectinventory.PublicInventory, d *AdvisoryDecision) { d.Activity = "withdrawn" }},
		{"unknown-profile", func(_ *Plan, _ *projectinventory.PublicInventory, d *AdvisoryDecision) {
			d.Profile = "unknown"
			d.Category = "unknown"
		}},
		{"missing-support", func(_ *Plan, _ *projectinventory.PublicInventory, d *AdvisoryDecision) {
			d.Support = []AdvisorySupport{}
		}},
		{"missing-witness", func(_ *Plan, p *projectinventory.PublicInventory, _ *AdvisoryDecision) {
			p.Observations[1].MetadataEvidence = 0
		}},
		{"wrong-witness", func(_ *Plan, p *projectinventory.PublicInventory, _ *AdvisoryDecision) {
			p.Observations[1].MetadataEvidence = 1
		}},
		{"incomplete-manifest", func(_ *Plan, p *projectinventory.PublicInventory, _ *AdvisoryDecision) {
			p.Evidence[2].Status = "incomplete"
			p.Complete = false
		}},
		{"incomplete-directory", func(_ *Plan, p *projectinventory.PublicInventory, _ *AdvisoryDecision) {
			p.Evidence[1].Status = "incomplete"
			p.Complete = false
		}},
		{"unstable", func(_ *Plan, p *projectinventory.PublicInventory, _ *AdvisoryDecision) {
			p.Observations[1].Status = "unstable"
		}},
		{"link", func(_ *Plan, p *projectinventory.PublicInventory, _ *AdvisoryDecision) {
			p.Observations[1].Kind = "link"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := plan
			d := candidate
			public := projectinventory.PortableMatching(f.inv)
			tc.change(&p, &public, &d)
			if ValidateAdvisoryDecision(p, public, info, d) == nil {
				t.Fatal("forgery accepted")
			}
		})
	}
	for _, kind := range []string{"file", "git", "link", "workspace", "project"} {
		public := projectinventory.PortableMatching(f.inv)
		public.Observations[0].Kind = kind
		if ValidateAdvisoryDecision(plan, public, info, rows[0]) == nil {
			t.Fatal("literal locked endpoint promoted", kind)
		}
	}
	for _, change := range []func(*projectinventory.PublicInventory){
		func(p *projectinventory.PublicInventory) {
			p.Selection.State = "absent"
			p.Selection.Reason = "no-root-lock"
		},
		func(p *projectinventory.PublicInventory) { p.Evidence[0].Status = "incomplete"; p.Complete = false },
		func(p *projectinventory.PublicInventory) { p.Evidence[0].Method = "native-metadata-lease" },
	} {
		public := projectinventory.PortableMatching(f.inv)
		change(&public)
		if ValidateAdvisoryDecision(plan, public, info, rows[0]) == nil {
			t.Fatal("incomplete/non-native selected lock accepted")
		}
	}
	// Permission/endpoint checks apply even to version-negative, withdrawn or
	// unsupported-profile rows with Candidate=false, not just active candidates.
	for _, optOut := range []bool{false, true} {
		p := plan
		public := projectinventory.PortableMatching(f.inv)
		if optOut {
			p.Policy.AdvisoryCandidates = false
		} else {
			public.Observations[1].MetadataEvidence = 0
		}
		if ValidateAdvisoryDecision(p, public, info, inactive) == nil {
			t.Fatal("inactive assessed row bypassed permission/endpoint")
		}
	}
}

func TestCandidateQualifiedAndAmbiguousShareEvaluationBudget(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	plan := matchingPinnedPlan(t, info)
	plan.Policy.NPMRegistry = "https://registry.npmjs.org"
	plan.Policy.AdvisoryCandidates = true
	one := newMatchingFixture()
	var single []AdvisoryDecision
	s1, err := MatchInventory(context.Background(), plan, one.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { single = append(single, d); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !single[0].EnforcementEligible || single[0].Candidate {
		t.Fatal("qualified finding changed", single)
	}
	f := one
	copy := one.inv.Model.Observations[0]
	copy.ID = 2
	copy.Location = "node_modules/other/node_modules/left-pad"
	copy.Origin = "https://private.invalid/copy.tgz"
	f.inv.Model.Observations = append(f.inv.Model.Observations, copy)
	var rows []AdvisoryDecision
	s2, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if err != nil || s2.BytesRead != s1.BytesRead || s2.Work != s1.Work+len(single) || len(rows) != 2*len(single) {
		t.Fatal("duplicate identity evaluation", s1, s2, err)
	}
	if !rows[0].EnforcementEligible || rows[0].Candidate || !rows[3].Candidate || rows[3].EnforcementEligible {
		t.Fatal(rows)
	}
	if !reflect.DeepEqual(rows[0].Support, rows[3].Support) {
		t.Fatal("template lost support")
	}
	for i := 2; i < 1500; i++ {
		copy.ID = uint32(i + 1)
		copy.Location = fmt.Sprintf("node_modules/copy%d/node_modules/left-pad", i)
		f.inv.Model.Observations = append(f.inv.Model.Observations, copy)
	}
	rows = nil
	s3, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if err != nil || s3.Work != maxMatchingDecisions || s3.BytesRead != s1.BytesRead || !hasMatchingGap(s3.Gaps, "evaluation-limit") || ValidateAdvisorySummary(s3, rows, projectinventory.PortableMatching(f.inv)) != nil {
		t.Fatal("shared cap lost", s3, err)
	}
}

func TestCandidatePartialDiagnosticAndIncompleteInventory(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	f := candidateFixture()
	f.inv.Complete = false
	f.inv.Model.Gaps = []projectinventory.Gap{{Scope: 1, Code: "discovery-incomplete"}}
	plan := matchingPinnedPlan(t, info)
	plan.Policy.AdvisoryCandidates = true
	var rows []AdvisoryDecision
	s, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	public := projectinventory.PortableMatching(f.inv)
	if err != nil || !hasMatchingGap(s.Gaps, "inventory-incomplete") || ValidateAdvisorySummary(s, rows, public) != nil || !rows[0].Candidate {
		t.Fatal("incomplete inventory lost positive or gap", s, err)
	}
	// Parent accepts an original-bound partial version positive with its typed
	// diagnostic, but neither that support nor the diagnostic qualifies origin.
	d := rows[0]
	d.FullyEvaluated = false
	d.FirstVersionProblem = &AdvisoryVersionProblem{"affected", "version-outside-profile", 1, -1, -1}
	d.Gaps = addMatchingGap(d.Gaps, "version-unsupported")
	if ValidateAdvisoryDecision(plan, public, info, d) != nil || !d.Candidate || d.EnforcementEligible || d.Outcome != "indeterminate" {
		t.Fatal("partial diagnostic lost or origin promoted", d)
	}
	copy := d
	copy.FirstVersionProblem = cloneAdvisoryVersionProblem(d.FirstVersionProblem)
	copy.FirstVersionProblem.Version = 2
	if d.FirstVersionProblem.Version != 1 {
		t.Fatal("diagnostic shared across copies")
	}
	d.Candidate = false
	d.VersionOutcome = "indeterminate"
	d.Support = []AdvisorySupport{}
	if ValidateAdvisoryDecision(plan, public, info, d) != nil {
		t.Fatal("partial unknown version was not retained", d)
	}
}

func TestCandidateUnavailableAndNegativeNeverBecomeQualified(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	for _, kind := range []string{"negative", "missing", "unavailable", "failed-read", "unqualified-source"} {
		t.Run(kind, func(t *testing.T) {
			f := candidateFixture()
			plan := matchingPinnedPlan(t, info)
			plan.Policy.AdvisoryCandidates = true
			selected, source := snapshot, info
			switch kind {
			case "negative":
				for i := range f.inv.Model.Observations {
					f.inv.Model.Observations[i].Version = "2.0.0"
				}
			case "missing":
				for i := range f.inv.Model.Observations {
					f.inv.Model.Observations[i].Name = "not-in-the-fixture"
					f.inv.Model.Observations[i].Fields["installation-name"] = "not-in-the-fixture"
				}
			case "unavailable":
				selected = nil
				source = UnavailableIntelligence()
				plan.TrustedSnapshotDigest = ""
			case "failed-read":
				selected, source = matchingSnapshot(t)
				selected.Close()
			case "unqualified-source":
				observed, err := snapshot.Observe(context.Background(), matchingNow, nil)
				if err != nil {
					t.Fatal(err)
				}
				source = SnapshotIntelligence(observed, "current")
				plan.TrustedSnapshotDigest = ""
			}
			var rows []AdvisoryDecision
			s, err := MatchInventory(context.Background(), plan, f.inv, selected, source, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range rows {
				if d.Candidate || d.Outcome != "indeterminate" || d.EnforcementEligible || ValidateAdvisoryDecision(plan, projectinventory.PortableMatching(f.inv), source, d) != nil {
					t.Fatal("negative/unavailable promoted", d)
				}
			}
			if kind == "negative" && (len(rows) != 6 || rows[0].VersionOutcome != "no-match") {
				t.Fatal(rows)
			}
			if kind == "unavailable" && s.BytesRead != 0 {
				t.Fatal("unavailable read")
			}
			if kind == "failed-read" && !hasMatchingGap(rows[0].Gaps, "identity-read-failed") {
				t.Fatal(rows)
			}
		})
	}
}
