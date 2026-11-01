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

const ownedBundle = "node_modules/@scope/bundled"

// All bytes and paths are owned synthetic inputs. These are actual native lease
// comparisons, not producer compatibility or global release qualification.
func bundledFixture(t *testing.T, marker any) (string, string, Policy) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("supported Linux/Windows owned fixture")
	}
	root, policy, p := ownedFixture(t)
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"index.js", "gone.js", "type.js", ownedBundle + "/index.js", ownedBundle + "/gone.js", ownedBundle + "/type.js"} {
		body := []byte("original")
		if e := tw.WriteHeader(&tar.Header{Name: "package/" + name, Size: int64(len(body)), Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); e != nil {
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
	p.References[0].ExpectedSRI = "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	if e := os.WriteFile(filepath.Join(filepath.Dir(policy), "pkg.tgz"), archive.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	bundle := filepath.Join(root, "node_modules/pkg", filepath.FromSlash(ownedBundle))
	if e := os.MkdirAll(filepath.Join(bundle, "type.js"), 0700); e != nil {
		t.Fatal(e)
	}
	for name, body := range map[string]string{"index.js": "modified bundle", "added.js": "added bundle"} {
		if e := os.WriteFile(filepath.Join(bundle, name), []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	lock := map[string]any{"lockfileVersion": 3, "packages": map[string]any{"": map[string]any{}, "node_modules/pkg": map[string]any{"name": "pkg", "version": "1.0.0", "resolved": "fixture:private", "integrity": p.References[0].ExpectedSRI}, "node_modules/pkg/" + ownedBundle: map[string]any{"version": "1.0.0", "inBundle": marker}}}
	data, _ := json.Marshal(lock)
	if e := os.WriteFile(filepath.Join(root, "package-lock.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	return root, policy, p
}

func acquireOwned(t *testing.T, root, policy string, p Policy) ([]Record, Summary) {
	t.Helper()
	plan, hash := fixturePlan(t, policy, p)
	var records []Record
	summary, e := Acquire(context.Background(), root, filepath.Dir(policy), hash, plan, func(r Record) error { records = append(records, r); return nil })
	if e != nil || len(records) != len(p.References) {
		t.Fatalf("acquisition: %+v %v", records, e)
	}
	for _, r := range records {
		if e := ValidateRecord(plan, r, hash); e != nil {
			t.Fatal("parent rejected actual record", e)
		}
	}
	if summary.Qualified {
		t.Fatal("scope promoted global qualification")
	}
	return records, summary
}

func TestPublishedBundledContentIsCompared(t *testing.T) {
	root, policy, p := bundledFixture(t, true)
	records, _ := acquireOwned(t, root, policy, p)
	a := records[0].Assessment
	want := map[string]integrity.DifferenceKind{"4": integrity.DifferenceModified, "5": integrity.DifferenceMissing, "6": integrity.DifferenceTypeChanged}
	added := 0
	for _, d := range a.Differences {
		if k, ok := want[d.EntryID]; ok && k == d.Kind {
			delete(want, d.EntryID)
		}
		if d.Kind == integrity.DifferenceAdded {
			added++
		}
	}
	if added != 2 {
		t.Fatalf("published implicit directories misclassified as additions: got=%d want=2", added)
	}
	if len(want) != 0 || !a.SuppliedComparisonComplete || len(a.Gaps) != 0 {
		t.Fatalf("published bundled drift excluded: missing=%v assessment=%+v", want, a)
	}
}

func TestBundleFlagRequiresLiteralTrue(t *testing.T) {
	for _, marker := range []any{nil, false, "true", 1, []any{true}} {
		t.Run(stringMustJSON(marker), func(t *testing.T) {
			root, policy, p := bundledFixture(t, marker)
			records, _ := acquireOwned(t, root, policy, p)
			a := records[0].Assessment
			if a.SuppliedComparisonComplete || len(a.Gaps) == 0 {
				t.Fatal("unqualified bundle admitted", a)
			}
			for _, d := range a.Differences {
				if d.EntryID == "4" || d.EntryID == "5" || d.EntryID == "6" {
					t.Fatal("unqualified bundle compared", a)
				}
			}
		})
	}
}
func stringMustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestGeneratedAndPatchContextNeverSuppressDrift(t *testing.T) {
	for _, kind := range []string{"patch", "generated"} {
		t.Run(kind, func(t *testing.T) {
			root, policy, p := bundledFixture(t, true)
			p.References[0].Context = kind
			records, _ := acquireOwned(t, root, policy, p)
			a := records[0].Assessment
			want := integrity.ContextPatch
			if kind == "generated" {
				want = integrity.ContextGenerated
			}
			if len(a.Contexts) != 1 || a.Contexts[0].Kind != want {
				t.Fatal("context missing", a)
			}
			modified := 0
			for _, d := range a.Differences {
				if d.Kind == integrity.DifferenceModified {
					modified++
				}
			}
			if modified != 2 || !a.SuppliedComparisonComplete {
				t.Fatal("context suppressed real parent/bundle drift", a)
			}
		})
	}
}
