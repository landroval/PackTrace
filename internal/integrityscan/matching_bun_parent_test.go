package integrityscan

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/projectinventory"
)

// Derived from the independent review's spoof_test.go. Rule 2 is valid,
// but it is not the rule for the acquired endpoint.
func TestBunParentCrossGrant(t *testing.T) {
	snap, info := matchingSnapshot(t)
	p, f := bunEligibleFixture(t, info)
	p.Privacy = "local"
	p.Policy.BunOrigins = append(p.Policy.BunOrigins, BunOriginRule{Location: "other", Name: "other", Version: "1.0.0", Origin: npmTarballOrigin("other", "1.0.0")})
	var ds []AdvisoryDecision
	var ms []PolicyMaterial
	matched, err := MatchInventoryWithPolicyEvidence(context.Background(), p, f.inv, snap, info, matchingNow, func(d AdvisoryDecision) error { ds = append(ds, d); return nil }, nil, func(m PolicyMaterial) error { ms = append(ms, m); return nil })
	if err != nil || len(ms) == 0 {
		t.Fatal(err, len(ms))
	}
	pub := projectinventory.PortableMatching(f.inv)
	t.Run("missing-acquisition", func(t *testing.T) {
		missing := pub
		missing.OriginalClaims = nil
		if ValidateAdvisoryDecision(p, missing, info, ds[0]) == nil || ValidatePolicyMaterials(p, missing, nil, ds, ms) == nil {
			t.Fatal("missing independent acquisition admitted")
		}
	})
	for _, d := range ds {
		if err := ValidateAdvisoryDecision(p, pub, info, d); err != nil {
			t.Fatal("honest decision", err)
		}
	}
	if err := ValidatePolicyMaterials(p, pub, nil, ds, ms); err != nil {
		t.Fatal("honest material", err)
	}
	for _, original := range ms {
		for _, field := range []string{"project-manifest", "project-lock", "source"} {
			t.Run(original.Scope.Class+"/mixed-"+field, func(t *testing.T) {
				m := original
				switch field {
				case "project-manifest":
					m.Project.ManifestSHA256 = strings.Repeat("a", 64)
					m.Scope.Project = ProjectFingerprint(m.Project)
				case "project-lock":
					m.Project.LockSHA256 = strings.Repeat("b", 64)
					m.LockSourceSHA256 = m.Project.LockSHA256
					m.Scope.Project = ProjectFingerprint(m.Project)
				case "source":
					m.SourceSHA256 = strings.Repeat("c", 64)
				}
				if ValidatePolicyMaterials(p, pub, nil, ds, []PolicyMaterial{m}) == nil {
					t.Fatal("mixed original material accepted")
				}
			})
		}
		t.Run(original.Scope.Class, func(t *testing.T) {
			var d AdvisoryDecision
			for _, v := range ds {
				if v.Observation == original.Observation && v.Advisory == original.Advisory && v.Affected == original.Affected {
					d = v
					break
				}
			}
			d.Rule = 2
			m := original
			m.BunTupleKey = "other"
			m.Scope.Package = "other"
			m.Scope.Instance = "other"
			if m.Scope.Class == "installed" {
				m.Scope.Instance = "node_modules/other"
				m.PhysicalTarget = m.Scope.Instance
			}
			m.Scope.Origin = npmTarballOrigin("other", "1.0.0")
			if err := ValidateAdvisoryDecision(p, pub, info, d); err == nil {
				t.Error("accepted unrelated rule against acquired endpoint")
			}
			if err := ValidatePolicyMaterials(p, pub, nil, []AdvisoryDecision{d}, []PolicyMaterial{m}); err == nil {
				t.Error("accepted unrelated material against acquired endpoint")
			}
		})
	}
	for _, mutation := range []string{"manifest-name", "manifest-version", "metadata-location", "tuple-context"} {
		t.Run(mutation, func(t *testing.T) {
			encoded, _ := json.Marshal(f.inv)
			var mixed projectinventory.Result
			if err := json.Unmarshal(encoded, &mixed); err != nil {
				t.Fatal(err)
			}
			for i := range mixed.Model.Observations {
				o := &mixed.Model.Observations[i]
				if o.Class == "installed" {
					if mutation == "manifest-name" {
						o.Name = "other"
					}
					if mutation == "manifest-version" {
						o.Version = "2.0.0"
					}
				}
				if mutation == "tuple-context" && o.Class == "locked" {
					o.Fields["matching-context"] = "unsupported"
				}
			}
			if mutation == "metadata-location" {
				mixed.Model.Evidence[1].Location = "node_modules/other"
			}
			admitted := projectinventory.PortableMatching(mixed)
			for _, d := range ds {
				if mutation != "tuple-context" && d.LockedObservation == 0 {
					continue
				}
				if ValidateAdvisoryDecision(p, admitted, info, d) == nil {
					t.Fatal("mixed original/native endpoint admitted")
				}
			}
		})
	}
	p.Privacy = "portable"
	r := BuildReportWithPolicy(p, nil, Summary{}, Resources{}, false, false, &pub, &info, &AdvisoryReport{State: "observed", Decisions: ds, Summary: matched, Findings: len(ms)}, ms, false, matchingNow)
	if r.Policy == nil || !validRenderedPolicy(r) {
		_, evalErr := EvaluatePolicy(p, nil, *r.Inventory, r.Advisories.Decisions, ms, false, matchingNow)
		t.Fatalf("Bun witness lost from private frozen evaluation: policy=%+v advisories=%+v eval=%v", r.Policy, r.Advisories, evalErr)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"left-pad", "node_modules/", ms[0].Project.LockSHA256, "OriginalClaims", "originalClaims", "TrustedPolicyDigest"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("portable report leaked %q", secret)
		}
	}
	// Mutating live acquisition claims cannot change the sealed parent inputs.
	f.inv.Model.Observations[0].Name = "other"
	if !validRenderedPolicy(r) || !validRenderedAdvisories(r) {
		t.Fatal("live acquisition mutation changed frozen evaluation")
	}
}
