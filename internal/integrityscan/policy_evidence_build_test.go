package integrityscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"packtrace/internal/integrity"
	"packtrace/internal/projectinventory"
)

func policyEvidenceFixture() projectinventory.Result {
	return projectinventory.Result{
		Selection: projectinventory.Selection{Profile: "npm@11.6.2", Family: "npm", File: "package-lock.json", State: "usable"},
		Model: projectinventory.Model{
			Scopes: []projectinventory.Scope{{ID: 1, Kind: "project", Status: "complete"}},
			Evidence: []projectinventory.Evidence{
				{ID: 1, Scope: 1, Location: "package.json", Method: "native-input-lease", Complete: true, SHA256: sha256.Sum256([]byte(`{"name":"root"}`))},
				{ID: 2, Scope: 1, Location: "package-lock.json", Method: "native-input-lease", Complete: true, SHA256: sha256.Sum256([]byte("whole lock"))},
				{ID: 3, Scope: 1, Location: "node_modules/p/package.json", Method: "native-input-lease", Complete: true, SHA256: sha256.Sum256([]byte(`{"name":"p","version":"1.0.0"}`))},
				{ID: 4, Scope: 1, Location: "node_modules/p", Method: "native-metadata-lease", Complete: true},
			},
			Observations: []projectinventory.Observation{
				{ID: 1, Workspace: 1, Source: 2, Class: "locked", Kind: "url", Status: "complete", Location: "node_modules/p", Name: "p", Version: "1.0.0", Origin: "https://registry.npmjs.org/p/-/p-1.0.0.tgz"},
				{ID: 2, Workspace: 1, Source: 3, Class: "installed", Kind: "directory", Status: "complete", Location: "node_modules/p", Name: "p", Version: "1.0.0", Fields: map[string]string{"metadata-evidence": "4", "physical-target": "node_modules/p"}},
			}},
	}
}
func TestPolicyEvidenceProjectQualifiedOriginalBytes(t *testing.T) {
	inv := policyEvidenceFixture()
	p, ok := BuildProjectEvidence(inv)
	if !ok || ProjectFingerprint(p) == "" {
		t.Fatal("missing qualified project")
	}
	inv.Model.Evidence[1].SHA256 = sha256.Sum256([]byte("whole lock with unrelated change"))
	changed, ok := BuildProjectEvidence(inv)
	if !ok || ProjectFingerprint(p) == ProjectFingerprint(changed) {
		t.Fatal("whole-lock change ignored")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*projectinventory.Result)
	}{
		{"unqualified", func(r *projectinventory.Result) { r.Selection.Profile = "npm" }},
		{"family-mismatch", func(r *projectinventory.Result) { r.Selection.Family = "bun" }},
		{"file-mismatch", func(r *projectinventory.Result) { r.Selection.File = "bun.lock" }},
		{"missing-root", func(r *projectinventory.Result) { r.Model.Scopes = nil }},
		{"zero-hash", func(r *projectinventory.Result) { r.Model.Evidence[0].SHA256 = [32]byte{} }},
		{"selection", func(r *projectinventory.Result) { r.Selection.State = "indeterminate" }},
		{"incomplete", func(r *projectinventory.Result) { r.Model.Evidence[0].Complete = false }},
		{"invalid-root", func(r *projectinventory.Result) {
			r.Model.Gaps = []projectinventory.Gap{{Scope: 1, Evidence: 1, Code: "manifest-invalid"}}
		}},
		{"invalid-lock", func(r *projectinventory.Result) {
			r.Model.Gaps = []projectinventory.Gap{{Scope: 1, Evidence: 2, Code: "lock-invalid"}}
		}},
		{"duplicate", func(r *projectinventory.Result) { r.Model.Evidence = append(r.Model.Evidence, r.Model.Evidence[0]) }},
		{"conflict", func(r *projectinventory.Result) {
			r.Model.Gaps = []projectinventory.Gap{{Scope: 1, Code: "selection-indeterminate"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := policyEvidenceFixture()
			tc.mutate(&r)
			if _, ok := BuildProjectEvidence(r); ok {
				t.Fatal("unqualified project accepted")
			}
		})
	}
	inv = policyEvidenceFixture()
	inv.Model.Gaps = []projectinventory.Gap{{Scope: 1, Evidence: 3, Code: "installed-incomplete"}}
	if _, ok := BuildProjectEvidence(inv); !ok {
		t.Fatal("unrelated installed gap erased project bytes")
	}
}
func TestPolicyEvidenceAdvisoryPrivacyIndependent(t *testing.T) {
	inv := policyEvidenceFixture()
	p, _ := BuildProjectEvidence(inv)
	idx := indexPolicyInventory(inv)
	original := LocalAdvisory{Advisory: 1, ID: "MAL-2026-1", SHA256: hexHash("original")}
	d := AdvisoryDecision{Observation: 2, LockedObservation: 1, Advisory: 1, Affected: 0, Category: "malicious", Profile: "openssf-malicious-v1", EnforcementEligible: true}
	m, ok := buildAdvisoryPolicyEvidence(p, idx, inv.Model.Observations[1], d, original)
	if !ok || m.SourceSHA256 == m.LockSourceSHA256 || m.DirectoryKind != "directory" || m.LinkSHA256 != "" || m.OriginalSHA256 != original.SHA256 || m.Scope.Origin != inv.Model.Observations[0].Origin {
		t.Fatalf("bad installed receipt: %+v", m)
	}
	if AcceptanceFingerprint(m) == "" {
		t.Fatal("receipt not accepted by shape validator")
	}
	again, _ := buildAdvisoryPolicyEvidence(p, idx, inv.Model.Observations[1], d, original)
	if !reflect.DeepEqual(m, again) {
		t.Fatal("unchanged original receipt changed")
	}
	original.SHA256 = hexHash("corrected original")
	changed, _ := buildAdvisoryPolicyEvidence(p, idx, inv.Model.Observations[1], d, original)
	if AcceptanceFingerprint(m) == AcceptanceFingerprint(changed) {
		t.Fatal("original bytes omitted")
	}
	inv.Model.Evidence[2].SHA256 = sha256.Sum256([]byte("changed own manifest"))
	changed, _ = buildAdvisoryPolicyEvidence(p, indexPolicyInventory(inv), inv.Model.Observations[1], d, LocalAdvisory{Advisory: 1, ID: "MAL-2026-1", SHA256: m.OriginalSHA256})
	if AcceptanceFingerprint(m) == AcceptanceFingerprint(changed) {
		t.Fatal("own manifest omitted")
	}
	d.Candidate = true
	if _, ok := buildAdvisoryPolicyEvidence(p, idx, inv.Model.Observations[1], d, original); ok {
		t.Fatal("candidate accepted")
	}
	d.Candidate = false
	inv.Model.Evidence[3].Complete = false
	if _, ok := buildAdvisoryPolicyEvidence(p, indexPolicyInventory(inv), inv.Model.Observations[1], d, original); ok {
		t.Fatal("missing physical witness accepted")
	}
	if policyEvidenceNeeded(Plan{Privacy: "portable"}) || !policyEvidenceNeeded(Plan{Privacy: "local"}) || !policyEvidenceNeeded(Plan{Privacy: "portable", Policy: Policy{Exceptions: []Exception{{}}}}) {
		t.Fatal("privacy changed exception acquisition")
	}
}
func hexHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func policyEvidenceCatalog(t *testing.T) (integrity.ReferenceCatalog, integrity.ReferenceBinding, string) {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "package/a", Typeflag: tar.TypeReg, Size: 1, Mode: 0644, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(out.Bytes())
	sri := "sha256-" + base64.StdEncoding.EncodeToString(h[:])
	other := sha256.Sum256([]byte("another allowed compressed artifact"))
	allowed := sri + " sha256-" + base64.StdEncoding.EncodeToString(other[:])
	binding, gaps := integrity.ResolveReferenceBinding(integrity.BindingInput{InstanceID: instanceID(0), Lockfile: integrity.BindingClaim{PackageID: "p", Version: "1.0.0", Origin: "o", ExpectedSRI: allowed, SourceLocator: "lock", SourceHash: sri, EvidenceID: "lock"}, SelectedBaseline: integrity.BaselineLockfile, SelectionReason: "selected", RequiredAssurance: integrity.AssuranceLockfile, Qualification: integrity.QualificationEvidence{ControllerEvidenceID: "controller", Basis: "supplied test evidence"}})
	if len(gaps) != 0 {
		t.Fatal(gaps)
	}
	catalog, err := integrity.InspectReferenceArchive(context.Background(), binding, bytes.NewReader(out.Bytes()), integrity.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if catalog.ObservedSRI() != sri || (integrity.ReferenceCatalog{}).ObservedSRI() != "" {
		t.Fatal("actual compressed artifact digest unavailable")
	}
	invalid, err := integrity.InspectReferenceArchive(context.Background(), binding, bytes.NewReader([]byte("invalid")), integrity.Limits{})
	if err == nil || invalid.ObservedSRI() != "" {
		t.Fatal("invalid catalog exposed digest")
	}
	return catalog, binding, sri
}
func TestPolicyEvidenceIntegrityDifferenceSides(t *testing.T) {
	catalog, binding, sri := policyEvidenceCatalog(t)
	inv := policyEvidenceFixture()
	p, _ := BuildProjectEvidence(inv)
	plan := Plan{Policy: Policy{References: []Reference{{Name: "p", Version: "1.0.0", Origin: "o", Location: "node_modules/p", ExpectedSRI: sri, Context: "none"}}}}
	for _, tc := range []struct {
		name     string
		entries  []integrity.InstalledEntry
		change   string
		observed string
	}{
		{"modified", []integrity.InstalledEntry{{Name: "a", Type: integrity.EntryFile, Size: 1, SHA256: sha256.Sum256([]byte("y"))}}, "modified", "file"},
		{"missing", nil, "missing", "none"},
		{"added", []integrity.InstalledEntry{{Name: "a", Type: integrity.EntryFile, Size: 1, SHA256: sha256.Sum256([]byte("x"))}, {Name: "b", Type: integrity.EntryFile, Size: 0, SHA256: sha256.Sum256(nil)}}, "added", "file"},
		{"directory", []integrity.InstalledEntry{{Name: "a", Type: integrity.EntryDirectory, Size: 4096}}, "type-changed", "directory"},
		{"link", []integrity.InstalledEntry{{Name: "a", Type: integrity.EntryLink, LinkTarget: "../target", Size: 9}}, "type-changed", "link"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := integrity.InstalledSnapshot{Entries: tc.entries, Scopes: []integrity.InstalledScope{{InstanceID: instanceID(0), OwnerInstanceID: instanceID(0), EvidenceID: instanceID(0) + ":scope", Enumerated: true, OwnershipKnown: true, Status: integrity.ObservationComplete}}}
			for i := range snapshot.Entries {
				snapshot.Entries[i].InstanceID = instanceID(0)
				snapshot.Entries[i].OwnerInstanceID = instanceID(0)
				snapshot.Entries[i].EvidenceID = instanceID(0) + ":observed:" + strconv.Itoa(i+1)
				snapshot.Entries[i].Status = integrity.ObservationComplete
			}
			assessment, err := integrity.CompareReferenceCatalog(binding, catalog, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			var rows []PolicyMaterial
			record := Record{Assessment: assessment}
			if err := emitIntegrityPolicyEvidence(p, plan, &record, indexPolicyInventory(inv), catalog, snapshot, func(m PolicyMaterial) error { rows = append(rows, m); return nil }); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].Scope.Change != tc.change || rows[0].Observed.Type != tc.observed || rows[0].ReferenceObservedSRI != sri || rows[0].SourceSHA256 == rows[0].LockSourceSHA256 {
				t.Fatalf("bad receipts: %+v", rows)
			}
			if err := ValidatePolicyMaterialShape(rows[0]); err != nil {
				t.Fatalf("producer/engine shape mismatch: %v: %+v", err, rows[0])
			}
			if record.PolicyObservation != rows[0].Observation || len(record.PolicyWitnesses) != len(rows) {
				t.Fatal("original record lost actual endpoint or witnesses")
			}
			for _, m := range rows {
				w := record.PolicyWitnesses[0]
				d := record.Assessment.Differences[m.Difference]
				if w.Difference != m.Difference || w.EntryID != d.EntryID || w.EvidenceID != d.EvidenceID || m.ReferenceEntryID != d.EntryID || m.ObservedEntryID != d.EvidenceID || w.Fingerprint != PolicyDifferenceFingerprint(m) {
					t.Fatal("producer cross-wired original difference", w, d, m)
				}
			}
			if tc.observed == "directory" && (rows[0].Observed.Size != 0 || rows[0].Observed.SHA256 != "") {
				t.Fatal("directory bound incidental size/hash")
			}
			if tc.observed == "link" && (rows[0].Observed.LinkSHA256 == "" || len(assessment.Gaps) == 0) {
				t.Fatal("link receipt erased unsupported gap")
			}
			sentinel := errors.New("stop")
			if err := emitIntegrityPolicyEvidence(p, plan, &record, indexPolicyInventory(inv), catalog, snapshot, func(PolicyMaterial) error { return sentinel }); !errors.Is(err, sentinel) {
				t.Fatal("callback error swallowed")
			}
		})
	}
}
