package integrityscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"packtrace/internal/integrity"
)

// Also runnable unchanged against local base 8d60af6. The opt-in report retains
// decision, gaps, differences and portable representation for a differential
// probe without executing any installed package or acquiring source/artifacts.
func TestLegacyBoundaryPublicContract(t *testing.T) {
	root, policy, p := mappedBundleFixture(t)
	for _, rel := range []string{"node_modules/unknown-a", "node_modules/unknown-b"} {
		if e := os.MkdirAll(filepath.Join(root, "node_modules/pkg", rel), 0700); e != nil {
			t.Fatal(e)
		}
	}
	records, _ := acquireOwned(t, root, policy, p)
	var assessments []integrity.InstanceAssessment
	for _, r := range records {
		assessments = append(assessments, r.Assessment)
	}
	parent := assessments[0]
	if parent.SuppliedComparisonComplete || len(parent.Gaps) != 3 {
		t.Fatal("legacy decision or boundary gaps changed", parent)
	}
	for _, g := range parent.Gaps {
		if g.Code != integrity.GapOwnership {
			t.Fatal("unexpected gap", g)
		}
	}
	for _, d := range parent.Differences {
		if d.EntryID == "4" || d.EntryID == "5" || d.EntryID == "6" {
			t.Fatal("parent consumed nested owner", d)
		}
	}
	portable := integrity.BuildPortableIntegrity(integrity.Assessment{Instances: assessments})
	if file := os.Getenv("PACKTRACE_BOUNDARY_REPORT"); file != "" {
		data, e := json.MarshalIndent(struct {
			Assessments []integrity.InstanceAssessment
			Portable    any
		}{assessments, portable}, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(file, append(data, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
}
