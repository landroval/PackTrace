package integrityscan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/projectinventory"
)

func coverageRow(t *testing.T, r Report, check string) Coverage {
	t.Helper()
	for _, c := range r.Coverage {
		if c.Check == check {
			return c
		}
	}
	t.Fatalf("missing coverage %s", check)
	return Coverage{}
}

// Ordinary owned native fixtures establish receipt behavior, not qualification.
func TestOperationalReferenceComparisonCoverage(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned Linux fixture, not qualification")
	}
	root, policy, p := ownedFixture(t)
	if err := os.WriteFile(filepath.Join(root, "node_modules/pkg/package.json"), []byte(`{"name":"pkg","version":"1.0.0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	plan, hash := fixturePlan(t, policy, p)
	plan.TrustedPolicyDigest = hash
	var records []Record
	var inventory projectinventory.PublicInventory
	summary, err := AcquireWithInventory(context.Background(), root, filepath.Dir(policy), hash, plan, func(r Record) error { records = append(records, r); return nil }, func(r projectinventory.Result) error { inventory = projectinventory.PortableMatching(r); return nil })
	if err != nil || !inventory.Complete {
		t.Fatalf("fixture: %v %+v", err, inventory)
	}
	build := func(records []Record, resources Resources, abnormal bool) Report {
		return BuildReportWithPolicy(plan, records, summary, resources, false, abnormal, &inventory, nil, nil, nil, false, time.Now().UTC())
	}
	r := build(records, Resources{}, false)
	if coverageRow(t, r, "reference-comparison").Outcome != "completed" {
		t.Fatal("actual selected-reference comparison lost")
	}
	if coverageRow(t, r, "inventory").Outcome != "completed" || coverageRow(t, r, "integrity").Outcome != "completed" || coverageRow(t, r, "native-qualification").Outcome != "incomplete" || coverageRow(t, r, "resident-observation").Outcome != "incomplete" || r.ExitCode != 3 {
		t.Fatalf("scope promoted qualification: %+v", r.Coverage)
	}
	for _, format := range []string{"terminal", "json", "sarif"} {
		if _, err := Render(r, format); err != nil {
			t.Fatal(format, err)
		}
	}
	for name, mutate := range map[string]func(*Record){
		"boolean-only":   func(r *Record) { r.Assessment.Differences = nil; r.ObservedEntries = 0 },
		"gap":            func(r *Record) { r.Assessment.SuppliedComparisonComplete = false },
		"wrong-index":    func(r *Record) { r.Index++ },
		"wrong-binding":  func(r *Record) { r.Lock.Version = "2.0.0" },
		"missing-source": func(r *Record) { r.Lock.SourceHash = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := append([]Record(nil), records...)
			mutate(&changed[0])
			if coverageRow(t, build(changed, Resources{}, false), "reference-comparison").Outcome != "incomplete" {
				t.Fatal("forged receipt completed")
			}
		})
	}
	for _, resources := range []Resources{{QueryFailed: true}, {Stale: true}, {Stopped: true}} {
		if coverageRow(t, build(records, resources, false), "reference-comparison").Outcome != "incomplete" {
			t.Fatal("resource gap completed")
		}
	}
	if coverageRow(t, build(records, Resources{}, true), "reference-comparison").Outcome != "incomplete" || coverageRow(t, build(nil, Resources{}, false), "reference-comparison").Outcome != "incomplete" {
		t.Fatal("absent/incomplete execution completed")
	}
	legacy := BuildReportWithInventory(plan, records, summary, Resources{}, false, false, &inventory)
	for _, c := range legacy.Coverage {
		if c.Check == "reference-comparison" {
			t.Fatal("historical contract changed")
		}
	}
	// A summary cannot grant (or substitute for) concrete closed evidence.
	withoutSummary := BuildReportWithPolicy(plan, records, Summary{}, Resources{}, false, false, &inventory, nil, nil, nil, false, time.Now().UTC())
	if coverageRow(t, withoutSummary, "inventory").Outcome != "completed" || coverageRow(t, withoutSummary, "reference-authority").Outcome != "completed" {
		t.Fatal("concrete inventory/binding completion depended on a child summary bit")
	}
	badBinding := append([]Record(nil), records...)
	badBinding[0].Lock.Version = "2.0.0"
	if coverageRow(t, build(badBinding, Resources{}, false), "reference-authority").Outcome != "incomplete" {
		t.Fatal("summary/assurance bit granted incoherent binding authority")
	}
	unpinned := plan
	unpinned.TrustedPolicyDigest = ""
	untrusted := BuildReportWithPolicy(unpinned, records, summary, Resources{}, false, false, &inventory, nil, nil, nil, false, time.Now().UTC())
	if coverageRow(t, untrusted, "reference-authority").Outcome != "incomplete" {
		t.Fatal("missing parent pin granted authority")
	}
	for name, mutate := range map[string]func(*projectinventory.PublicInventory){
		"selected-original": func(p *projectinventory.PublicInventory) { p.Selection.Evidence = 0 },
		"enumeration": func(p *projectinventory.PublicInventory) {
			for i := range p.Evidence {
				if p.Evidence[i].Method == "native-metadata" {
					p.Evidence[i].Method = "native-input-lease"
				}
			}
		},
		"installed-witness": func(p *projectinventory.PublicInventory) {
			for i := range p.Observations {
				if p.Observations[i].Class == "installed" {
					p.Observations[i].MetadataEvidence = 0
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			data, _ := json.Marshal(inventory)
			var changed projectinventory.PublicInventory
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if projectinventory.ValidatePublic(changed) != nil {
				t.Fatal("expected historically valid projection")
			}
			r := BuildReportWithPolicy(plan, records, summary, Resources{}, false, false, &changed, nil, nil, nil, false, time.Now().UTC())
			if coverageRow(t, r, "inventory").Outcome != "incomplete" {
				t.Fatal("omitted native witness completed inventory")
			}
		})
	}
	forged := BuildReportWithPolicy(plan, nil, Summary{Qualified: true, AuthorityComplete: true, InventoryComplete: true, SnapshotComplete: true}, Resources{WorkerSamples: 100, SupervisorSamples: 100}, false, false, nil, nil, nil, nil, false, time.Now().UTC())
	for _, check := range []string{"inventory", "reference-comparison", "reference-authority", "native-qualification", "resident-observation"} {
		if coverageRow(t, forged, check).Outcome != "incomplete" {
			t.Fatal("child summary/samples granted", check)
		}
	}
}

func TestOperationalFreshnessAndFrozenConditions(t *testing.T) {
	plan, inventory, info, a := candidateReportFixture(t, "portable")
	plan.Checks |= cli.ArgumentCheckVulnerability
	build := func(resources Resources, abnormal bool) Report {
		return BuildReportWithPolicy(plan, nil, Summary{}, resources, false, abnormal, &inventory, &info, &a, nil, false, time.Now().UTC())
	}
	if coverageRow(t, build(Resources{}, false), "intelligence-freshness").Outcome != "completed" {
		t.Fatal("independent current source freshness lost")
	}
	for _, resources := range []Resources{{QueryFailed: true}, {Stale: true}, {Stopped: true}} {
		if coverageRow(t, build(resources, false), "intelligence-freshness").Outcome != "incomplete" {
			t.Fatal("resource gap completed freshness")
		}
	}
	if coverageRow(t, build(Resources{}, true), "intelligence-freshness").Outcome != "incomplete" {
		t.Fatal("abnormal source lifetime completed freshness")
	}
	r := build(Resources{}, false)
	for _, category := range []string{"malicious", "vulnerability"} {
		// A selected category cannot borrow the other category's rows or omit the index gap.
		if coverageRow(t, r, category).Required && !strings.Contains(coverageRow(t, r, category).Reason, "index-completeness") {
			t.Fatal("source/index incompleteness not explicit", r.Coverage)
		}
	}
	for name, mutate := range map[string]func(*Report){
		"coverage-removed": func(r *Report) { r.Coverage = nil },
		"all-completed": func(r *Report) {
			r.Coverage = append([]Coverage(nil), r.Coverage...)
			for i := range r.Coverage {
				r.Coverage[i].Outcome = "completed"
			}
		},
		"exit":      func(r *Report) { r.ExitCode = 0 },
		"downgrade": func(r *Report) { r.SchemaVersion = "1.6" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			mutate(&changed)
			if !ReportConditions(changed).ReportPreventingError {
				t.Fatal("unsealed comparison accepted by final adjudication")
			}
		})
	}
	interrupted := BuildReportWithPolicy(plan, nil, Summary{}, Resources{}, true, false, &inventory, &info, &a, nil, false, time.Now().UTC())
	interrupted.ExitCode = 0
	conditions := ReportConditions(interrupted)
	if !conditions.Interrupted || !conditions.ReportPreventingError || cli.SelectScanExit(conditions) != 130 {
		t.Fatal("tampering overrode frozen interruption", conditions)
	}
	data, _ := json.Marshal(r)
	var decoded Report
	if json.Unmarshal(data, &decoded) != nil || !ReportConditions(decoded).ReportPreventingError {
		t.Fatal("public JSON recreated comparison authority")
	}
}

func TestOperationalAdvisoryCompletionRequiresSourceAndFullScope(t *testing.T) {
	plan, _, info, _ := candidateReportFixture(t, "portable")
	plan.Checks |= cli.ArgumentCheckVulnerability
	inventory := projectinventory.PortableMatching(newMatchingFixture().inv)
	d := AdvisoryDecision{Observation: 1, Advisory: 1, Affected: 0, Rule: 1, VersionOutcome: "match", Outcome: "match", Category: "malicious", Profile: "openssf-malicious-v1", Activity: "not-withdrawn", Origin: "operator-npm-rule", Source: "qualified", FullyEvaluated: true, EnforcementEligible: true, Support: []AdvisorySupport{{Version: 0, Range: -1}}, Gaps: []string{}}
	v := d
	v.Sequence, v.Advisory, v.Category, v.Profile = 1, 2, "vulnerability", "osv-github-reviewed-v1"
	a := AdvisoryReport{State: "observed", Decisions: []AdvisoryDecision{d, v}, Findings: 2, Summary: AdvisorySummary{Decisions: 2, Observations: 1, TotalObservations: 1, Work: 4, BytesRead: 2, Gaps: []string{"declared-unassessed", "index-completeness"}}}
	build := func() Report {
		return BuildReportWithPolicy(plan, nil, Summary{}, Resources{}, false, false, &inventory, &info, &a, nil, false, time.Now().UTC())
	}
	r := build()
	if r.Advisories.State != "observed" || r.Advisories.Findings != 2 {
		t.Fatal("qualified fixture rejected")
	}
	for _, category := range []string{"malicious", "vulnerability"} {
		if coverageRow(t, r, category).Outcome != "incomplete" {
			t.Fatal("perfect finding rows erased index gap", category)
		}
	}
	// Removing the gap is a forged historical source contract, not completion.
	a.Summary.Gaps = []string{"declared-unassessed"}
	if build().Advisories.State != "unavailable" {
		t.Fatal("forged source/index completeness admitted")
	}
	// Even a structurally valid empty observation set has no complete-index proof.
	inventory.Observations = []projectinventory.PublicObservation{}
	inventory.Counts.Locked = 0
	a = AdvisoryReport{State: "observed", Decisions: []AdvisoryDecision{}, Summary: AdvisorySummary{Gaps: []string{"declared-unassessed", "index-completeness"}}}
	r = build()
	if r.Advisories.State != "observed" {
		t.Fatal("empty fixture rejected")
	}
	for _, category := range []string{"malicious", "vulnerability"} {
		if coverageRow(t, r, category).Outcome != "incomplete" {
			t.Fatal("empty decisions became complete", category)
		}
	}
}
