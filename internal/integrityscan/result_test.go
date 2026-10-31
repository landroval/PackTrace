package integrityscan

import (
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/integrity"
)

func TestSupervisorRejectsChildAuthorityAndInvalidReferences(t *testing.T) {
	p, e := ParsePolicy([]byte(policyJSON))
	if e != nil {
		t.Fatal(e)
	}
	plan := Plan{Manager: p.Manager, Policy: p, Checks: 4}
	record := badRecord(0, integrity.BindingClaim{}, integrity.GapBinding)
	if ValidateRecord(plan, record, "policy") != nil {
		t.Fatal("valid gap rejected")
	}
	for _, mutate := range []func(*Record){
		func(r *Record) { r.Assessment.InstanceID = "other" },
		func(r *Record) { r.Index = 1 },
		func(r *Record) { r.Assessment.SuppliedComparisonComplete = true },
		func(r *Record) { r.Assessment.Assurance = integrity.AssuranceIndependent },
		func(r *Record) { r.Assessment.Gaps[0].EvidenceID = "PRIVATE" },
		func(r *Record) {
			r.Assessment.Differences = []integrity.Difference{{Kind: integrity.DifferenceModified, InstanceID: "instance-1", EntryID: "1", EvidenceID: "nonexistent"}}
		},
	} {
		copy := record
		copy.Assessment.Gaps = append([]integrity.Gap{}, record.Assessment.Gaps...)
		mutate(&copy)
		if ValidateRecord(plan, copy, "policy") == nil {
			t.Fatalf("forgery accepted %+v", copy)
		}
	}
}

func TestCandidateReportsNeverPromoteEngineCompletionOrLeak(t *testing.T) {
	p, e := ParsePolicy([]byte(policyJSON))
	if e != nil {
		t.Fatal(e)
	}
	p.Reason = "PRIVATE-POLICY"
	p.References[0].Name = "PRIVATE-PACKAGE"
	plan := Plan{Manager: p.Manager, Policy: p, Checks: 7, FailOn: 4}
	record := badRecord(0, integrity.BindingClaim{}, integrity.GapBinding)
	report := BuildReport(plan, []Record{record}, Summary{Records: 1, InventoryComplete: true, SnapshotComplete: true}, Resources{}, false, false)
	if report.ExitCode != 3 || report.Coverage[0].Outcome == "completed" {
		t.Fatalf("false completion %+v", report)
	}
	for _, format := range []string{"terminal", "json", "sarif"} {
		data, e := Render(report, format)
		if e != nil || strings.Contains(string(data), "PRIVATE") || strings.Contains(string(data), "sha256-") {
			t.Fatalf("privacy %s %s %v", format, data, e)
		}
		if format != "terminal" {
			var decoded map[string]any
			if json.Unmarshal(data, &decoded) != nil {
				t.Fatal("invalid JSON")
			}
		}
	}
	interrupted := BuildReport(plan, nil, Summary{}, Resources{}, true, false)
	if interrupted.ExitCode != 130 {
		t.Fatal("interruption precedence")
	}
}
