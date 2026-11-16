package integrityscan

import (
	"context"
	"encoding/json"
	"testing"

	"packtrace/internal/cli"
	"packtrace/internal/projectinventory"
)

func TestBunDecisionMultiplicity(t *testing.T) {
	locked := AdvisoryDecision{Observation: 1, Rule: 1, Origin: "operator-bun-rule"}
	installed := locked
	installed.Observation, installed.LockedObservation = 2, 1
	if !bunDecisionMultiplicity([]AdvisoryDecision{locked, installed, installed}) {
		t.Fatal("multiple originals confused with multiple endpoints")
	}
	p, _ := bunEligibleFixture(t, UnavailableIntelligence())
	if ValidatePolicyMaterials(p, projectinventory.PublicInventory{}, nil, []AdvisoryDecision{locked, installed}, nil) != nil {
		t.Fatal("baseline parent multiplicity")
	}
	for _, other := range []AdvisoryDecision{
		{Observation: 3, Rule: 1, Origin: "operator-bun-rule"},
		{Observation: 1, Rule: 2, Origin: "operator-bun-rule"},
		{Observation: 3, LockedObservation: 1, Rule: 1, Origin: "operator-bun-rule"},
	} {
		if bunDecisionMultiplicity([]AdvisoryDecision{locked, installed, other}) {
			t.Fatal("multiple endpoints inherited one rule", other)
		}
		if ValidatePolicyMaterials(p, projectinventory.PublicInventory{}, nil, []AdvisoryDecision{locked, installed, other}, nil) == nil {
			t.Fatal("parent multiplicity")
		}
	}
}

func TestBunEligibleOriginalCategoryMatchNonmatchAndCorrection(t *testing.T) {
	for _, bundle := range []string{"full.bundle", "corrected.bundle"} {
		snapshot, info := matchingSnapshotNamed(t, bundle)
		for _, tc := range []struct {
			name, version, category string
			initial, corrected      string
		}{
			{"npmfixture-0002", "1.0.0", "malicious", "match", "match"},
			{"npmfixture-0002", "2.0.0", "malicious", "no-match", "no-match"},
			{"npmfixture-0003", "1.0.0", "vulnerability", "match", "match"},
			{"npmfixture-0003", "2.0.0", "vulnerability", "no-match", "no-match"},
			{"npmfixture-0000", "1.0.0", "malicious", "match", "no-match"},     // withdrawn
			{"npmfixture-0050", "1.0.0", "malicious", "match", "no-match"},     // changed versions
			{"npmfixture-0001", "1.0.0", "vulnerability", "match", "no-match"}, // changed fixed boundary
		} {
			t.Run(bundle+"/"+tc.name+"/"+tc.version, func(t *testing.T) {
				p, f := bunEligibleFixture(t, info)
				p.Checks = cli.ArgumentCheckMalicious | cli.ArgumentCheckVulnerability
				for i := range f.inv.Model.Observations {
					o := &f.inv.Model.Observations[i]
					o.Name, o.Version = tc.name, tc.version
					if o.Class == "locked" {
						o.Location = tc.name
						o.Fields["tuple-key"] = tc.name
					} else {
						o.Location = "node_modules/" + tc.name
						o.Fields["installation-name"] = tc.name
						o.Fields["physical-target"] = o.Location
					}
				}
				f.inv.Model.Evidence[1].Location = "node_modules/" + tc.name
				f.inv.Model.Evidence[2].Location = "node_modules/" + tc.name + "/package.json"
				p.Policy.BunOrigins = []BunOriginRule{{Location: tc.name, Name: tc.name, Version: tc.version, Origin: npmTarballOrigin(tc.name, tc.version)}}
				expected := tc.initial
				if bundle == "corrected.bundle" {
					expected = tc.corrected
				}
				count := 0
				_, err := MatchInventory(context.Background(), p, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error {
					if d.Category == tc.category {
						count++
						if d.Outcome != expected || d.Candidate || d.EnforcementEligible != (expected == "match") {
							t.Fatal("wrong original/category result", d)
						}
						if err := ValidateAdvisoryDecision(p, projectinventory.PortableMatching(f.inv), info, d); err != nil {
							t.Fatal("parent", d, err)
						}
					}
					return nil
				})
				if err != nil || count != 2 {
					t.Fatal("expected one original for each locked/native observation", count, err)
				}
			})
		}
	}
}

func TestBunPolicyMaterialRetainsOriginalWitnessesAndRejectsTamper(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	p, f := bunEligibleFixture(t, info)
	p.Privacy = "local"
	var rows []AdvisoryDecision
	var materials []PolicyMaterial
	_, err := MatchInventoryWithPolicyEvidence(context.Background(), p, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil }, nil, func(m PolicyMaterial) error { materials = append(materials, m); return nil })
	if err != nil || len(materials) != 2 {
		t.Fatal("material emission", materials, err)
	}
	public := projectinventory.PortableMatching(f.inv)
	if err := ValidatePolicyMaterials(p, public, nil, rows, materials); err != nil {
		t.Fatal(err)
	}
	for _, m := range materials {
		if m.BunTupleKey != "left-pad" || m.BunRegistry != "" || m.Scope.Origin != p.Policy.BunOrigins[0].Origin || m.OriginalSHA256 == "" || m.Project.LockSHA256 == "" || m.SourceSHA256 == "" {
			t.Fatal("original witness lost", m)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Plan, *projectinventory.PublicInventory, []AdvisoryDecision, *PolicyMaterial)
	}{
		{"absent-grant", func(p *Plan, _ *projectinventory.PublicInventory, _ []AdvisoryDecision, _ *PolicyMaterial) {
			p.Policy.BunOrigins = nil
		}},
		{"wrong-raw-registry", func(_ *Plan, _ *projectinventory.PublicInventory, _ []AdvisoryDecision, m *PolicyMaterial) {
			m.BunRegistry = m.Scope.Origin
		}},
		{"missing-tuple", func(_ *Plan, _ *projectinventory.PublicInventory, _ []AdvisoryDecision, m *PolicyMaterial) {
			m.BunTupleKey = ""
		}},
		{"alias-tuple", func(_ *Plan, _ *projectinventory.PublicInventory, _ []AdvisoryDecision, m *PolicyMaterial) {
			m.BunTupleKey = "alias"
		}},
		{"wrong-origin", func(_ *Plan, _ *projectinventory.PublicInventory, _ []AdvisoryDecision, m *PolicyMaterial) {
			m.Scope.Origin = "https://private.invalid/p"
		}},
		{"wrong-rule", func(_ *Plan, _ *projectinventory.PublicInventory, ds []AdvisoryDecision, _ *PolicyMaterial) {
			for i := range ds {
				ds[i].Rule = 0
			}
		}},
		{"candidate-decision", func(_ *Plan, _ *projectinventory.PublicInventory, ds []AdvisoryDecision, _ *PolicyMaterial) {
			for i := range ds {
				ds[i].Candidate = true
			}
		}},
		{"wrong-native-target", func(_ *Plan, _ *projectinventory.PublicInventory, _ []AdvisoryDecision, m *PolicyMaterial) {
			m.PhysicalTarget = "node_modules/alias"
		}},
		{"missing-native-metadata", func(_ *Plan, inv *projectinventory.PublicInventory, _ []AdvisoryDecision, _ *PolicyMaterial) {
			inv.Observations[1].MetadataEvidence = 0
		}},
		{"unbound-native-metadata", func(_ *Plan, inv *projectinventory.PublicInventory, _ []AdvisoryDecision, _ *PolicyMaterial) {
			inv.Evidence[2].MetadataEvidence = 0
		}},
		{"wrong-selected-lock", func(_ *Plan, inv *projectinventory.PublicInventory, _ []AdvisoryDecision, _ *PolicyMaterial) {
			inv.Selection.Evidence = 4
		}},
		{"duplicate-relation", func(_ *Plan, inv *projectinventory.PublicInventory, _ []AdvisoryDecision, _ *PolicyMaterial) {
			inv.Relations = append(inv.Relations, inv.Relations[0])
		}},
		{"wrong-relation-original", func(_ *Plan, inv *projectinventory.PublicInventory, _ []AdvisoryDecision, _ *PolicyMaterial) {
			inv.Relations[0].Evidence = 2
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pp Plan
			raw, _ := json.Marshal(p)
			_ = json.Unmarshal(raw, &pp)
			var inv projectinventory.PublicInventory
			raw, _ = json.Marshal(public)
			_ = json.Unmarshal(raw, &inv)
			ds := append([]AdvisoryDecision(nil), rows...)
			m := materials[1]
			tc.mutate(&pp, &inv, ds, &m)
			if ValidatePolicyMaterials(pp, inv, nil, ds, []PolicyMaterial{m}) == nil {
				t.Fatal("tampered Bun material accepted")
			}
		})
	}
	if ValidatePolicyMaterials(p, public, nil, rows, []PolicyMaterial{materials[0], materials[0]}) == nil {
		t.Fatal("duplicate material accepted")
	}
	m := materials[0]
	changed := m
	changed.OriginalSHA256 = hexHash("changed advisory original")
	if AcceptanceFingerprint(m) == AcceptanceFingerprint(changed) {
		t.Fatal("advisory original not acceptance bound")
	}
	changed = m
	changed.SourceSHA256 = hexHash("changed native source")
	changed.LockSourceSHA256 = changed.SourceSHA256
	changed.Project.LockSHA256 = changed.SourceSHA256
	changed.Scope.Project = ProjectFingerprint(changed.Project)
	if AcceptanceFingerprint(m) == AcceptanceFingerprint(changed) {
		t.Fatal("project original not acceptance bound")
	}
	p.Policy.Exceptions = []Exception{{ID: "review", Owner: "owner", Reason: "owned review", ApprovedAt: "2026-10-01T00:00:00Z", ExpiresAt: "2026-10-31T00:00:00Z", Scope: m.Scope, Acceptance: AcceptanceFingerprint(m)}}
	evaluation, err := EvaluatePolicy(p, nil, public, rows, materials, false, matchingNow)
	if err != nil || !evaluation.Findings[0].Accepted {
		t.Fatal("exact original exception", evaluation, err)
	}
	changed = m
	changed.OriginalSHA256 = hexHash("corrected advisory original")
	evaluation, err = EvaluatePolicy(p, nil, public, rows, []PolicyMaterial{changed, materials[1]}, false, matchingNow)
	// All receipts for one advisory must retain one original digest. A mixed
	// original cannot pass; changing every receipt still revokes exact acceptance.
	if err == nil {
		t.Fatal("mixed originals accepted", evaluation)
	}
	changedInstalled := materials[1]
	changedInstalled.OriginalSHA256 = changed.OriginalSHA256
	evaluation, err = EvaluatePolicy(p, nil, public, rows, []PolicyMaterial{changed, changedInstalled}, false, matchingNow)
	if err != nil || evaluation.Findings[0].Accepted {
		t.Fatal("changed original inherited acceptance", evaluation, err)
	}
}
