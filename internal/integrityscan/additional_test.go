package integrityscan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"packtrace/internal/integrity"
)

func TestPartialNativeSnapshotRetainsKnownDrift(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local Linux owned unit")
	}
	root, policy, p := ownedFixture(t)
	// A safe escaping link is observed but not followed. The known ordinary
	// file modification must survive this separate snapshot-coverage failure.
	if e := os.Symlink("../../outside-canary", filepath.Join(root, "node_modules/pkg/escaping")); e != nil {
		t.Fatal(e)
	}
	var records []Record
	plan, hash := fixturePlan(t, policy, p)
	summary, e := Acquire(context.Background(), root, filepath.Dir(policy), hash, plan, func(r Record) error { records = append(records, r); return nil })
	if e != nil || len(records) != 1 || summary.SnapshotComplete {
		t.Fatalf("partial observation discarded: %+v %+v %v", summary, records, e)
	}
	modified := false
	for _, d := range records[0].Assessment.Differences {
		modified = modified || d.Kind == integrity.DifferenceModified
	}
	if !modified || records[0].Assessment.SuppliedComparisonComplete {
		t.Fatalf("known drift erased or incomplete scan verified: %+v", records)
	}
}

func TestPreparedReferenceFailuresNeverProduceDifferences(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local Linux owned unit")
	}
	for _, mode := range []string{"missing", "truncated", "wrong-digest", "mismatched-lock-identity", "independent"} {
		t.Run(mode, func(t *testing.T) {
			root, policy, p := ownedFixture(t)
			switch mode {
			case "missing":
				p.References[0].Archive = "absent.tgz"
			case "truncated":
				if e := os.WriteFile(filepath.Join(filepath.Dir(policy), "pkg.tgz"), []byte("not-an-archive"), 0600); e != nil {
					t.Fatal(e)
				}
			case "wrong-digest":
				p.References[0].ExpectedSRI = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			case "mismatched-lock-identity":
				p.References[0].Name = "other"
			case "independent":
				p.MinimumAssurance = "independently-anchored"
			}
			var record Record
			plan, hash := fixturePlan(t, policy, p)
			_, e := Acquire(context.Background(), root, filepath.Dir(policy), hash, plan, func(r Record) error { record = r; return nil })
			if e != nil || len(record.Assessment.Differences) != 0 || len(record.Assessment.Gaps) == 0 {
				t.Fatalf("bad reference verified: %+v %v", record, e)
			}
		})
	}
}

func TestMultipleAndNestedInstancesKeepPhysicalOwnership(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local Linux owned unit")
	}
	root, policy, p := ownedFixture(t)
	nested := "node_modules/pkg/node_modules/pkg"
	if e := os.MkdirAll(filepath.Join(root, filepath.FromSlash(nested)), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, filepath.FromSlash(nested), "index.js"), []byte("nested-modification"), 0600); e != nil {
		t.Fatal(e)
	}
	child := p.References[0]
	child.Location = nested
	child.LockKey = nested
	p.References = append(p.References, child)
	data, e := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if e != nil {
		t.Fatal(e)
	}
	var lock map[string]any
	if json.Unmarshal(data, &lock) != nil {
		t.Fatal("lock")
	}
	packages := lock["packages"].(map[string]any)
	packages[nested] = packages["node_modules/pkg"]
	data, _ = json.Marshal(lock)
	if e := os.WriteFile(filepath.Join(root, "package-lock.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	var records []Record
	plan, hash := fixturePlan(t, policy, p)
	_, e = Acquire(context.Background(), root, filepath.Dir(policy), hash, plan, func(r Record) error { records = append(records, r); return nil })
	if e != nil || len(records) != 2 {
		t.Fatal(records, e)
	}
	if records[0].Assessment.InstanceID == records[1].Assessment.InstanceID || records[0].Assessment.SuppliedComparisonComplete {
		t.Fatal("nested ownership collapsed/blanket-excluded", records)
	}
	for _, record := range records {
		modified := false
		for _, d := range record.Assessment.Differences {
			if d.InstanceID != record.Assessment.InstanceID {
				t.Fatal("cross-instance evidence")
			}
			modified = modified || d.Kind == integrity.DifferenceModified
		}
		if !modified {
			t.Fatalf("physical instance modification lost %+v", record)
		}
	}
}
