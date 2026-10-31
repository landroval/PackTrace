package integrityscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"packtrace/internal/integrity"
)

func ownedFixture(t *testing.T) (string, string, Policy) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "target")
	external := filepath.Join(base, "prepared")
	for _, dir := range []string{filepath.Join(root, "node_modules", "pkg"), external} {
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, file := range []struct{ name, body string }{{"index.js", "original"}, {"gone.js", "gone"}, {"type.js", "ordinary"}} {
		body := []byte(file.body)
		if e := tw.WriteHeader(&tar.Header{Name: "package/" + file.name, Size: int64(len(body)), Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); e != nil {
			t.Fatal(e)
		}
		if _, e := tw.Write(body); e != nil {
			t.Fatal(e)
		}
	}
	if tw.Close() != nil || gz.Close() != nil {
		t.Fatal("archive")
	}
	sum := sha256.Sum256(archive.Bytes())
	sri := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	var p Policy
	if json.Unmarshal([]byte(policyJSON), &p) != nil {
		t.Fatal("policy")
	}
	p.References[0].ExpectedSRI = sri
	lock := `{"lockfileVersion":3,"packages":{"":{},"node_modules/pkg":{"name":"pkg","version":"1.0.0","resolved":"fixture:private","integrity":"` + sri + `"}}}`
	for name, body := range map[string][]byte{"package-lock.json": []byte(lock), "package.json": []byte(`{"name":"fixture"}`), "node_modules/pkg/index.js": []byte("modified"), "node_modules/pkg/added.js": []byte("extra")} {
		if e := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), body, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Mkdir(filepath.Join(root, "node_modules/pkg/type.js"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(external, "pkg.tgz"), archive.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(p)
	policy := filepath.Join(external, "policy.json")
	if e := os.WriteFile(policy, data, 0600); e != nil {
		t.Fatal(e)
	}
	return root, policy, p
}

// Bind direct unit callers to the same actual external policy source required
// by the supervised flow. Assertions remain unchanged; no hash-only admission.
func fixturePlan(t *testing.T, policy string, p Policy) (Plan, string) {
	t.Helper()
	data, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(policy, data, 0600); e != nil {
		t.Fatal(e)
	}
	return Plan{PolicyFile: filepath.Base(policy), Manager: p.Manager, Policy: p, Checks: 4}, sourceSRI(data)
}

func TestOwnedNativeAcquisitionProducesRealDrift(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned local Linux unit case, not native qualification")
	}
	root, policy, p := ownedFixture(t)
	got, e := AcquirePolicy(context.Background(), policy, root)
	if e != nil {
		t.Fatal(e)
	}
	if got.Policy.Reason != p.Reason || got.SourceHash == "" {
		t.Fatal("policy was not acquired")
	}
	plan := Plan{PolicyFile: filepath.Base(policy), Manager: p.Manager, Policy: p, Checks: 4}
	var records []Record
	summary, e := Acquire(context.Background(), root, filepath.Dir(policy), got.SourceHash, plan, func(r Record) error { records = append(records, r); return nil })
	if e != nil || len(records) != 1 {
		t.Fatalf("real acquisition %+v %v %+v", summary, e, records)
	}
	kinds := map[integrity.DifferenceKind]bool{}
	for _, d := range records[0].Assessment.Differences {
		kinds[d.Kind] = true
	}
	for _, kind := range []integrity.DifferenceKind{integrity.DifferenceModified, integrity.DifferenceMissing, integrity.DifferenceAdded, integrity.DifferenceTypeChanged} {
		if !kinds[kind] {
			t.Fatalf("lost actual drift %v: %+v", kind, records)
		}
	}
	if summary.Qualified || summary.AuthorityComplete {
		t.Fatal("candidate promoted itself to qualified")
	}
}

func TestPolicyAndReferenceAdmissionIsFailClosed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned local Linux unit")
	}
	root, policy, p := ownedFixture(t)
	if _, e := AcquirePolicy(context.Background(), filepath.Join(root, "policy.json"), root); e == nil {
		t.Fatal("lexically contained policy accepted")
	}
	p.MinimumAssurance = "independently-anchored"
	var record Record
	plan, hash := fixturePlan(t, policy, p)
	_, e := Acquire(context.Background(), root, filepath.Dir(policy), hash, plan, func(r Record) error { record = r; return nil })
	if e != nil || len(record.Assessment.Differences) != 0 || len(record.Assessment.Gaps) == 0 {
		t.Fatalf("unproved independence admitted: %+v %v", record, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Acquire(ctx, root, filepath.Dir(policy), "", Plan{Policy: p}, func(Record) error { t.Fatal("canceled emitted record"); return nil }); e == nil {
		t.Fatal("canceled acquisition accepted")
	}
}
