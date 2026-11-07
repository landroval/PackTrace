package integrityscan

import (
	"strings"
	"testing"

	"packtrace/internal/cli"
	"packtrace/internal/integrity"
	"packtrace/internal/projectinventory"
)

func TestEngineIntegrityKindsAndParentJoins(t *testing.T) {
	for _, tc := range []struct {
		name               string
		kind               integrity.DifferenceKind
		expected, observed EvidenceSide
	}{
		{"modified", integrity.DifferenceModified, EvidenceSide{State: "present", Type: "file", Size: 1, SHA256: strings.Repeat("a", 64)}, EvidenceSide{State: "present", Type: "file", Size: 1, SHA256: strings.Repeat("b", 64)}},
		{"missing", integrity.DifferenceMissing, EvidenceSide{State: "present", Type: "file", Size: 1, SHA256: strings.Repeat("a", 64)}, EvidenceSide{State: "absent", Type: "none"}},
		{"added", integrity.DifferenceAdded, EvidenceSide{State: "absent", Type: "none"}, EvidenceSide{State: "present", Type: "file", Size: 0, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
		{"type-changed", integrity.DifferenceTypeChanged, EvidenceSide{State: "present", Type: "file", Size: 1, SHA256: strings.Repeat("a", 64)}, EvidenceSide{State: "present", Type: "link", LinkSHA256: strings.Repeat("b", 64)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := engineMaterial()
			m.Scope.Category = "integrity"
			m.Scope.Rule = "integrity-drift"
			m.Scope.Class = "installed"
			m.Scope.Advisory = ""
			m.Scope.Path = "index.js"
			m.Scope.Change = tc.name
			m.Scope.Package = "pkg"
			m.Scope.Origin = "fixture:private"
			m.Scope.Instance = "node_modules/pkg"
			m.Advisory = 0
			m.OriginalSHA256 = ""
			m.Observation = 2
			m.SourceSHA256 = strings.Repeat("4", 64)
			m.Profile = m.Project.Profile
			m.PhysicalTarget = m.Scope.Instance
			m.DirectoryKind = "directory"
			m.Expected = tc.expected
			m.Observed = tc.observed
			m.ReferenceSRI = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			m.ReferenceObservedSRI = m.ReferenceSRI
			m.ReferenceContext = "none"
			m.Assurance = "independently-anchored"
			m.ReferenceEntryID = "1"
			if tc.kind == integrity.DifferenceAdded {
				m.ReferenceEntryID = ""
			}
			m.ObservedEntryID = instanceID(0) + ":observed:1"
			if tc.kind == integrity.DifferenceMissing {
				m.ObservedEntryID = instanceID(0) + ":scope"
			}
			p, _ := ParsePolicy([]byte(policyJSON))
			p.FailOn = []string{"integrity"}
			p.Exceptions = []Exception{engineException(m)}
			plan, e := Configure(cli.ScanArgumentRequest{Manager: "auto", PolicyPath: "policy.json", Privacy: "local", Checks: cli.ArgumentCheckIntegrity, Output: "-", TrustedPolicyDigest: m.ReferenceSRI}, p)
			if e != nil {
				t.Fatal(e)
			}
			f := newMatchingFixture().inv
			f.Model.Evidence = append(f.Model.Evidence,
				projectinventory.Evidence{ID: 2, Scope: 1, Location: "package.json", Method: "native-input-lease", Complete: true},
				projectinventory.Evidence{ID: 3, Scope: 1, Location: "node_modules/pkg", Method: "native-metadata-lease", Complete: true},
				projectinventory.Evidence{ID: 4, Scope: 1, Location: "node_modules/pkg/package.json", Method: "native-input-lease", Complete: true})
			f.Model.Observations = append(f.Model.Observations, projectinventory.Observation{ID: 2, Workspace: 1, Source: 4, Class: "installed", Kind: "directory", Status: "complete", Location: "node_modules/pkg", Fields: map[string]string{"metadata-evidence": "3"}})
			f.Model.Evidence = append(f.Model.Evidence,
				projectinventory.Evidence{ID: 5, Scope: 1, Location: "node_modules/other", Method: "native-metadata-lease", Complete: true},
				projectinventory.Evidence{ID: 6, Scope: 1, Location: "node_modules/other/package.json", Method: "native-input-lease", Complete: true})
			f.Model.Observations = append(f.Model.Observations, projectinventory.Observation{ID: 3, Workspace: 1, Source: 6, Class: "installed", Kind: "directory", Status: "complete", Location: "node_modules/other", Fields: map[string]string{"metadata-evidence": "5"}})
			inv := projectinventory.PortableMatching(f)
			ref := p.References[0]
			records := []Record{{Index: 0, ObservedEntries: 2, Lock: integrity.BindingClaim{PackageID: ref.Name, Version: ref.Version, Origin: ref.Origin, ExpectedSRI: ref.ExpectedSRI, SourceLocator: m.Project.LockFile, SourceHash: hexSRI(m.LockSourceSHA256), EvidenceID: "locked:" + ref.Location}, Assessment: integrity.InstanceAssessment{InstanceID: instanceID(0), Assurance: integrity.AssuranceIndependent, SuppliedComparisonComplete: true, Differences: []integrity.Difference{{InstanceID: instanceID(0), Kind: tc.kind, EntryID: m.ReferenceEntryID, EvidenceID: m.ObservedEntryID}}}}}
			records[0].PolicyObservation = m.Observation
			records[0].PolicyWitnesses = []PolicyDifferenceWitness{{Difference: 0, EntryID: m.ReferenceEntryID, EvidenceID: m.ObservedEntryID, Fingerprint: PolicyDifferenceFingerprint(m)}}
			if err := ValidateRecord(plan, records[0], sourceSRI([]byte("authored pinned policy"))); err != nil {
				t.Fatal("invalid original record fixture", err)
			}
			if err := ValidatePolicyMaterial(plan, inv, records, nil, m); err != nil {
				t.Fatal("valid receipt refused", err)
			}
			t.Run("manifest must join specific metadata witness", func(t *testing.T) {
				disconnected := inv
				disconnected.Evidence = append([]projectinventory.PublicEvidence{}, inv.Evidence...)
				disconnected.Evidence[3].MetadataEvidence = 0
				if projectinventory.ValidatePublic(disconnected) != nil {
					t.Fatal("disconnected inventory must remain otherwise admissible")
				}
				if ValidatePolicyMaterial(plan, disconnected, records, nil, m) == nil {
					t.Fatal("installed input missing specific metadata source join admitted")
				}
			})
			out, err := EvaluatePolicy(plan, records, inv, nil, []PolicyMaterial{m}, false, matchingNow)
			if err != nil || len(out.Findings) != 1 || !out.Findings[0].Accepted || out.EnforcedUnaccepted != 0 {
				t.Fatal(out, err)
			}
			t.Run("exact private uppercase identity", func(t *testing.T) {
				private := m
				private.Scope.Package = "PRIVATE-pkg"
				private.Scope.Version = "owned-reference-revision"
				q := plan
				q.Policy.References = append([]Reference{}, plan.Policy.References...)
				q.Policy.References[0].Name = private.Scope.Package
				q.Policy.References[0].Version = private.Scope.Version
				q.Policy.Exceptions = []Exception{engineException(private)}
				r := records[0]
				r.Lock.PackageID = private.Scope.Package
				r.Lock.Version = private.Scope.Version
				r.PolicyWitnesses = []PolicyDifferenceWitness{{Difference: 0, EntryID: private.ReferenceEntryID, EvidenceID: private.ObservedEntryID, Fingerprint: PolicyDifferenceFingerprint(private)}}
				if ValidateRecord(q, r, sourceSRI([]byte("authored private pinned policy"))) != nil {
					t.Fatal("private original record refused")
				}
				out, err := EvaluatePolicy(q, []Record{r}, inv, nil, []PolicyMaterial{private}, false, matchingNow)
				if err != nil || len(out.Findings) != 1 || !out.Findings[0].Accepted {
					t.Fatal("exact private identity failed", out, err)
				}
				private.Scope.Package = strings.ToLower(private.Scope.Package)
				if ValidatePolicyMaterial(q, inv, []Record{r}, nil, private) == nil {
					t.Fatal("private package identity case-folded")
				}
			})
			for name, mutate := range map[string]func(*PolicyMaterial){
				"path": func(m *PolicyMaterial) { m.Scope.Path = "unrelated.js" },
				"sides": func(m *PolicyMaterial) {
					if m.Expected.State == "present" {
						m.Expected.Size++
					} else {
						m.Observed.Size++
					}
				},
				"installed endpoint":    func(m *PolicyMaterial) { m.Observation = 3 },
				"entry substitution":    func(m *PolicyMaterial) { m.ReferenceEntryID = "2" },
				"evidence substitution": func(m *PolicyMaterial) { m.ObservedEntryID = instanceID(0) + ":observed:2" },
			} {
				t.Run(name, func(t *testing.T) {
					bad := m
					mutate(&bad)
					if ValidatePolicyMaterialShape(bad) != nil {
						t.Fatal("attack fixture is not shape-valid")
					}
					for _, receipt := range []PolicyMaterial{m, bad} {
						q := plan
						q.Policy.Exceptions = []Exception{engineException(receipt)}
						if _, err := EvaluatePolicy(q, records, inv, nil, []PolicyMaterial{bad}, false, matchingNow); err == nil {
							t.Fatal("substitution admitted against unchanged original witness")
						}
					}
				})
			}
			for _, mutate := range []func(*PolicyMaterial){
				func(m *PolicyMaterial) {
					m.Observed.SHA256 = ""
					m.Observed.LinkSHA256 = ""
					m.Observed.Type = "file"
					m.Observed.State = "present"
				},
				func(m *PolicyMaterial) { m.Record = 1 },
				func(m *PolicyMaterial) { m.Difference = 1 },
				func(m *PolicyMaterial) { m.ReferenceSRI = "sha256-ERERERERERERERERERERERERERERERERERERERERERE=" },
				func(m *PolicyMaterial) { m.Assurance = "lockfile-consistent" },
				func(m *PolicyMaterial) { m.Observation = 1 },
			} {
				bad := m
				mutate(&bad)
				if ValidatePolicyMaterial(plan, inv, records, nil, bad) == nil {
					t.Fatal("malformed or orphan integrity receipt admitted")
				}
			}
			for name, mutate := range map[string]func(*Record){
				"missing witness":     func(r *Record) { r.PolicyWitnesses = nil },
				"duplicate witness":   func(r *Record) { r.PolicyWitnesses = append(r.PolicyWitnesses, r.PolicyWitnesses[0]) },
				"orphan witness":      func(r *Record) { r.PolicyWitnesses[0].Difference = 1 },
				"negative difference": func(r *Record) { r.PolicyWitnesses[0].Difference = -1 },
				"entry mismatch":      func(r *Record) { r.PolicyWitnesses[0].EntryID = "2" },
				"evidence mismatch":   func(r *Record) { r.PolicyWitnesses[0].EvidenceID = instanceID(0) + ":observed:2" },
				"bad fingerprint":     func(r *Record) { r.PolicyWitnesses[0].Fingerprint = "sha256-invalid" },
				"noncanonical fingerprint": func(r *Record) {
					r.PolicyWitnesses[0].Fingerprint = strings.TrimSuffix(r.PolicyWitnesses[0].Fingerprint, "=")
				},
				"missing observation": func(r *Record) { r.PolicyObservation = 0 },
				"count limit":         func(r *Record) { r.PolicyWitnesses = make([]PolicyDifferenceWitness, 4097) },
			} {
				t.Run(name, func(t *testing.T) {
					r := records[0]
					r.PolicyWitnesses = append([]PolicyDifferenceWitness{}, r.PolicyWitnesses...)
					mutate(&r)
					if name != "missing witness" && ValidateRecord(plan, r, sourceSRI([]byte("authored pinned policy"))) == nil {
						t.Fatal("malformed witness table admitted with original record")
					}
					if ValidatePolicyMaterial(plan, inv, []Record{r}, nil, m) == nil {
						t.Fatal("material admitted without matching original witness")
					}
				})
			}
			legacy := records[0]
			legacy.PolicyObservation = 0
			legacy.PolicyWitnesses = nil
			if ValidateRecord(plan, legacy, sourceSRI([]byte("authored pinned policy"))) != nil {
				t.Fatal("historical record rejected")
			}
			renumber := m
			renumber.ReferenceEntryID = "99"
			renumber.ObservedEntryID = "other:observed:9"
			renumber.Observation = 99
			if AcceptanceFingerprint(renumber) != AcceptanceFingerprint(m) || PolicyDifferenceFingerprint(renumber) == PolicyDifferenceFingerprint(m) {
				t.Fatal("stable acceptance/private commitment domains conflated")
			}
			// Another honest difference's material cannot be paired with the first
			// difference, even when both are the same kind and both IDs exist.
			second := m
			second.Difference = 1
			second.Scope.Path = "second.js"
			second.ReferenceEntryID = "2"
			if tc.kind == integrity.DifferenceAdded {
				second.ReferenceEntryID = ""
			}
			second.ObservedEntryID = instanceID(0) + ":observed:2"
			if tc.kind == integrity.DifferenceMissing {
				second.ObservedEntryID = instanceID(0) + ":scope"
			}
			pair := records[0]
			pair.Assessment.Differences = append([]integrity.Difference{}, pair.Assessment.Differences...)
			pair.Assessment.Differences = append(pair.Assessment.Differences, integrity.Difference{InstanceID: instanceID(0), Kind: tc.kind, EntryID: second.ReferenceEntryID, EvidenceID: second.ObservedEntryID})
			pair.PolicyWitnesses = append([]PolicyDifferenceWitness{}, pair.PolicyWitnesses...)
			pair.PolicyWitnesses = append(pair.PolicyWitnesses, PolicyDifferenceWitness{Difference: 1, EntryID: second.ReferenceEntryID, EvidenceID: second.ObservedEntryID, Fingerprint: PolicyDifferenceFingerprint(second)})
			if ValidateRecord(plan, pair, sourceSRI([]byte("authored pinned policy"))) != nil || ValidatePolicyMaterial(plan, inv, []Record{pair}, nil, second) != nil {
				t.Fatal("honest second difference fixture refused")
			}
			second.Difference = 0
			if ValidatePolicyMaterial(plan, inv, []Record{pair}, nil, second) == nil {
				t.Fatal("cross-paired same-kind difference admitted")
			}
			changed := m
			changed.SourceSHA256 = strings.Repeat("5", 64)
			if AcceptanceFingerprint(changed) == AcceptanceFingerprint(m) {
				t.Fatal("installed manifest not bound")
			}
			changed = m
			changed.PhysicalTarget = "node_modules/other"
			if AcceptanceFingerprint(changed) == AcceptanceFingerprint(m) {
				t.Fatal("physical target not bound")
			}
		})
	}
}
