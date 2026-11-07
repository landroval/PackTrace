package integrityscan

import (
	"bytes"
	"testing"

	"packtrace/internal/cli"
	"packtrace/internal/projectinventory"
)

func TestAdvisoryReportRetainsIndependentGapsAndRejectsForgedRendering(t *testing.T) {
	plan := Plan{Manager: "npm@10.9.4", Checks: cli.ArgumentCheckMalicious, Policy: Policy{Version: 1, Designation: "user-designated", Reason: "PRIVATE-reason", Provenance: "PRIVATE-provenance", Manager: "npm@10.9.4", RequiredChecks: []string{"malicious"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []Reference{}}}
	inventory := projectinventory.PublicInventory{
		Scopes:       []projectinventory.PublicScope{{ID: 1, Kind: "project", Status: "incomplete"}},
		Evidence:     []projectinventory.PublicEvidence{{ID: 1, Scope: 1, Method: "native-metadata", Status: "incomplete"}},
		Observations: []projectinventory.PublicObservation{{ID: 1, Workspace: 1, Source: 1, Class: "locked", Kind: "url", Status: "complete"}},
		Relations:    []projectinventory.Relation{}, Gaps: []projectinventory.Gap{{Scope: 1, Evidence: 1, Code: "discovery-incomplete"}},
		Selection: projectinventory.PublicSelection{Family: "npm", State: "unusable", Reason: "candidate-unusable"},
		Counts:    projectinventory.Counters{Scopes: 1, Evidence: 1, Locked: 1, Gaps: 1},
	}
	info := UnavailableIntelligence()
	a := AdvisoryReport{State: "observed", Decisions: []AdvisoryDecision{{Observation: 1, Affected: -1, VersionOutcome: "indeterminate", Outcome: "indeterminate", Category: "unknown", Profile: "unknown", Activity: "unknown", Origin: "unqualified", Source: "unqualified", Support: []AdvisorySupport{}, Gaps: []string{"origin-unqualified", "source-unqualified", "intelligence-unavailable"}}}, Summary: AdvisorySummary{Decisions: 1, Observations: 1, TotalObservations: 1, Work: 1, Gaps: []string{"declared-unassessed", "index-completeness", "inventory-incomplete"}}}
	r := BuildReportWithAdvisories(plan, nil, Summary{}, Resources{}, false, false, &inventory, &info, &a)
	a.Decisions[0].Gaps[0] = "PRIVATE-mutated"
	a.Summary.Gaps[0] = "PRIVATE-mutated"
	if r.SchemaVersion != "1.4" || r.ExitCode != 3 || r.Findings != 0 || r.Advisories == nil || r.Advisories.State != "observed" {
		t.Fatal("matching silently disappeared or changed global coverage", r)
	}
	for _, format := range []string{"json", "terminal", "sarif"} {
		data, e := Render(r, format)
		if e != nil || bytes.Contains(data, []byte("PRIVATE")) {
			t.Fatal("report is not an independent portable copy", format, e)
		}
	}
	for _, corrupt := range []func(*Report){
		func(r *Report) { r.Advisories.Decisions[0].Gaps = []string{"PRIVATE-terminal\x1b[31m"} },
		func(r *Report) { r.Advisories.Decisions[0].EnforcementEligible = true },
		func(r *Report) { r.Advisories.Findings = 1 },
		func(r *Report) { r.SchemaVersion = "1.2" },
		func(r *Report) { r.advisoryPlan = nil },
	} {
		copy := r
		a := *r.Advisories
		a.Decisions = append([]AdvisoryDecision{}, r.Advisories.Decisions...)
		copy.Advisories = &a
		corrupt(&copy)
		for _, format := range []string{"json", "terminal", "sarif"} {
			if _, e := Render(copy, format); e == nil {
				t.Fatal("forged advisory report rendered", format)
			}
		}
	}
}

func TestAdvisoryReportBeforeInventoryIsUnavailableNotSuccessfulZero(t *testing.T) {
	plan := Plan{Checks: cli.ArgumentCheckMalicious}
	r := BuildReportWithAdvisories(plan, nil, Summary{}, Resources{}, false, true, nil, nil, nil)
	if r.Advisories == nil || r.Advisories.State != "unavailable" || r.ExitCode != 3 {
		t.Fatal("missing matching promoted to success", r)
	}
	for _, format := range []string{"json", "terminal", "sarif"} {
		if _, e := Render(r, format); e != nil {
			t.Fatal("partial report unnecessarily prevented", format, e)
		}
	}
}
