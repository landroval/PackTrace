package integrityscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"packtrace/internal/integrity"
)

func acquireContentProfile(t *testing.T, root, policy string, p Policy, verify bool) ([]Record, Plan, string) {
	t.Helper()
	p.MinimumAssurance = "independently-anchored"
	plan, hash := fixturePlan(t, policy, p)
	plan.TrustedPolicyDigest = hash
	if verify {
		plan.IntegrityProfile = VerifyNPMProfile
	}
	if e := ValidatePlanPolicy(plan); e != nil {
		t.Fatal(e)
	}
	var records []Record
	_, e := Acquire(context.Background(), root, filepath.Dir(policy), hash, plan, func(r Record) error { records = append(records, r); return nil })
	if e != nil || len(records) != len(p.References) {
		t.Fatal(e, records)
	}
	for _, r := range records {
		if e := ValidateRecord(plan, r, hash); e != nil {
			t.Fatal(e, r)
		}
	}
	return records, plan, hash
}

func contentFixture(t *testing.T) (string, string, Policy) {
	t.Helper()
	root, policy, p := bundledFixture(t, false)
	lockPath := filepath.Join(root, "package-lock.json")
	data, e := os.ReadFile(lockPath)
	if e != nil {
		t.Fatal(e)
	}
	var lock map[string]any
	if json.Unmarshal(data, &lock) != nil {
		t.Fatal("lock")
	}
	delete(lock["packages"].(map[string]any), "node_modules/pkg/"+ownedBundle)
	data, _ = json.Marshal(lock)
	if e := os.WriteFile(lockPath, data, 0600); e != nil {
		t.Fatal(e)
	}
	return root, policy, p
}

func TestPublishedContentProfileNativeComparison(t *testing.T) {
	root, policy, p := contentFixture(t)
	legacy, _, _ := acquireContentProfile(t, root, policy, p, false)
	if legacy[0].Assessment.SuppliedComparisonComplete {
		t.Fatal("legacy ownership widened")
	}
	records, _, _ := acquireContentProfile(t, root, policy, p, true)
	a := records[0].Assessment
	want := map[string]integrity.DifferenceKind{"1": integrity.DifferenceModified, "2": integrity.DifferenceMissing, "3": integrity.DifferenceTypeChanged}
	added := 0
	for _, d := range a.Differences {
		if want[d.EntryID] == d.Kind {
			delete(want, d.EntryID)
		}
		if d.Kind == integrity.DifferenceAdded {
			added++
		}
	}
	if a.SuppliedComparisonComplete || len(a.Gaps) != 1 || a.Gaps[0].Code != integrity.GapOwnership || len(want) != 0 || added != 1 {
		t.Fatal("ambiguous subtree closed or unrelated native drift lost", a, want)
	}
}

func TestPublishedContentExactBoundaries(t *testing.T) {
	for _, manifest := range []bool{false, true} {
		for _, rel := range []string{"node_modules/foreign", ownedBundle + "/node_modules/deeper"} {
			root, policy, p := contentFixture(t)
			dir := filepath.Join(root, "node_modules/pkg", filepath.FromSlash(rel))
			if e := os.MkdirAll(dir, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(dir, "payload.js"), []byte("inert extra"), 0600); e != nil {
				t.Fatal(e)
			}
			if manifest {
				if e := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"foreign","version":"1.0.0"}`), 0600); e != nil {
					t.Fatal(e)
				}
			}
			records, _, _ := acquireContentProfile(t, root, policy, p, true)
			a := records[0].Assessment
			ownership := false
			for _, g := range a.Gaps {
				ownership = ownership || g.Code == integrity.GapOwnership
			}
			if a.SuppliedComparisonComplete || !ownership {
				t.Fatal("unknown scope swallowed", rel, manifest, a)
			}
		}
	}
}

// Matching authenticated bytes do not distinguish parent fixtures from an
// unrecorded separate package without a manifest. Neither profile may complete.
func TestPublishedContentIdenticalManifestlessOwnerRemainsAmbiguous(t *testing.T) {
	root, policy, p := contentFixture(t)
	dir := filepath.Join(root, "node_modules/pkg", ownedBundle)
	for _, name := range []string{"added.js", "type.js"} {
		if e := os.Remove(filepath.Join(dir, name)); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"index.js", "gone.js", "type.js"} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte("original"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, verify := range []bool{false, true} {
		records, _, _ := acquireContentProfile(t, root, policy, p, verify)
		a := records[0].Assessment
		if a.SuppliedComparisonComplete || len(a.Gaps) != 1 || a.Gaps[0].Code != integrity.GapOwnership {
			t.Fatal("identical bytes granted ownership", verify, a)
		}
		for _, d := range a.Differences {
			if d.EntryID == "4" || d.EntryID == "5" || d.EntryID == "6" {
				t.Fatal("ambiguous owner compared as parent", verify, d)
			}
		}
	}
}

func TestPublishedContentManifestIsSeparateOwner(t *testing.T) {
	root, policy, p := contentFixture(t)
	name := filepath.Join(root, "node_modules/pkg", ownedBundle, "package.json")
	if e := os.WriteFile(name, []byte(`{"name":"@scope/bundled","version":"1.0.0"}`), 0600); e != nil {
		t.Fatal(e)
	}
	records, _, _ := acquireContentProfile(t, root, policy, p, true)
	if records[0].Assessment.SuppliedComparisonComplete {
		t.Fatal("installed manifest owner absorbed")
	}
}

func TestPublishedEmptyDirectoryDoesNotGrantScope(t *testing.T) {
	root, policy, p := contentFixture(t)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if e := tw.WriteHeader(&tar.Header{Name: "package/" + ownedBundle + "/", Typeflag: tar.TypeDir, Mode: 0700, Format: tar.FormatUSTAR}); e != nil {
		t.Fatal(e)
	}
	if tw.Close() != nil || gz.Close() != nil {
		t.Fatal("archive")
	}
	p.References[0].ExpectedSRI = sourceSRI(buf.Bytes())
	if e := os.WriteFile(filepath.Join(filepath.Dir(policy), "pkg.tgz"), buf.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	lockPath := filepath.Join(root, "package-lock.json")
	data, e := os.ReadFile(lockPath)
	if e != nil {
		t.Fatal(e)
	}
	var lock map[string]any
	if json.Unmarshal(data, &lock) != nil {
		t.Fatal("lock")
	}
	lock["packages"].(map[string]any)["node_modules/pkg"].(map[string]any)["integrity"] = p.References[0].ExpectedSRI
	data, _ = json.Marshal(lock)
	if e := os.WriteFile(lockPath, data, 0600); e != nil {
		t.Fatal(e)
	}
	records, _, _ := acquireContentProfile(t, root, policy, p, true)
	ownership := false
	for _, g := range records[0].Assessment.Gaps {
		ownership = ownership || g.Code == integrity.GapOwnership
	}
	if !ownership || records[0].Assessment.SuppliedComparisonComplete {
		t.Fatal("empty directory granted scope", records)
	}
}

func TestPublishedContentMappedOwnerWins(t *testing.T) {
	root, policy, p := mappedBundleFixture(t)
	records, _, _ := acquireContentProfile(t, root, policy, p, true)
	if records[0].Assessment.SuppliedComparisonComplete {
		t.Fatal("mapped owner swallowed")
	}
	for _, d := range records[0].Assessment.Differences {
		if d.EntryID == "4" || d.EntryID == "5" || d.EntryID == "6" {
			t.Fatal("parent consumed mapped evidence")
		}
	}
}

func TestDistinctUnknownBoundaryEvidenceSurvivesValidation(t *testing.T) {
	root, policy, p := contentFixture(t)
	for _, rel := range []string{"node_modules/a", "node_modules/b"} {
		if e := os.MkdirAll(filepath.Join(root, "node_modules/pkg", rel), 0700); e != nil {
			t.Fatal(e)
		}
	}
	records, _, _ := acquireContentProfile(t, root, policy, p, true)
	seen := map[string]bool{}
	for _, g := range records[0].Assessment.Gaps {
		if g.Code == integrity.GapOwnership {
			if seen[g.EvidenceID] {
				t.Fatal("collapsed boundaries", g)
			}
			seen[g.EvidenceID] = true
		}
	}
	if len(seen) != 3 {
		t.Fatal("missing boundaries", records)
	}
	portable := integrity.BuildPortableIntegrity(integrity.Assessment{Instances: []integrity.InstanceAssessment{records[0].Assessment}})
	positions := map[int]bool{}
	for _, g := range portable.Gaps {
		if g.Code == integrity.GapOwnership {
			if g.Evidence == 0 || positions[g.Evidence] {
				t.Fatal("portable boundary collapse", portable)
			}
			positions[g.Evidence] = true
		}
	}
	if len(positions) != 3 {
		t.Fatal("portable boundaries missing", portable)
	}
}

func TestPublishedContentNeverAbsorbsSeparateLockedOwner(t *testing.T) {
	root, policy, p := bundledFixture(t, false)
	records, _, _ := acquireContentProfile(t, root, policy, p, true)
	if records[0].Assessment.SuppliedComparisonComplete {
		t.Fatal("separate locked owner absorbed")
	}
	for _, d := range records[0].Assessment.Differences {
		if d.EntryID == "4" || d.EntryID == "5" || d.EntryID == "6" {
			t.Fatal("separate locked content compared by parent")
		}
	}
}

func TestPublishedContentLinkRemainsNegative(t *testing.T) {
	root, policy, p := contentFixture(t)
	name := filepath.Join(root, "node_modules/pkg", ownedBundle, "index.js")
	if e := os.Remove(name); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("../index.js", name); e != nil {
		t.Skip(e)
	}
	records, _, _ := acquireContentProfile(t, root, policy, p, true)
	if records[0].Assessment.SuppliedComparisonComplete || len(records[0].Assessment.Gaps) == 0 {
		t.Fatal("published link admitted")
	}
}

func TestIntegrityProfileAdmission(t *testing.T) {
	_, policy, p := ownedFixture(t)
	p.MinimumAssurance = "independently-anchored"
	plan, hash := fixturePlan(t, policy, p)
	plan.TrustedPolicyDigest = hash
	plan.IntegrityProfile = VerifyNPMProfile
	if ValidatePlanPolicy(plan) != nil {
		t.Fatal("valid profile rejected")
	}
	for _, mutate := range []func(*Plan){
		func(p *Plan) { p.IntegrityProfile = "arbitrary" },
		func(p *Plan) { p.TrustedPolicyDigest = "" },
		func(p *Plan) { p.Policy.MinimumAssurance = "lockfile-consistent" },
		func(p *Plan) { p.Builtin = true },
		func(p *Plan) { p.Checks |= 1 },
	} {
		v := plan
		mutate(&v)
		if ValidatePlanPolicy(v) == nil {
			t.Fatal("profile escaped", v)
		}
	}
}
