package integrityscan

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
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
	if r.SchemaVersion != "1.6" || r.ExitCode != 3 || r.Findings != 0 || r.Advisories == nil || r.Advisories.State != "observed" {
		t.Fatal("matching silently disappeared or changed global coverage", r)
	}
	for _, format := range []string{"json", "terminal", "sarif"} {
		data, e := Render(r, format)
		if e != nil || bytes.Contains(data, []byte("PRIVATE")) || bytes.Contains(data, []byte("firstVersionProblem")) {
			t.Fatal("report is not an independent portable copy or invented a blocker", format, e)
		}
	}
	for _, corrupt := range []func(*Report){
		func(r *Report) { r.Advisories.Decisions[0].Gaps = []string{"PRIVATE-terminal\x1b[31m"} },
		func(r *Report) { r.Advisories.Decisions[0].EnforcementEligible = true },
		func(r *Report) { r.Advisories.Findings = 1 },
		func(r *Report) { r.SchemaVersion = "1.2" },
		func(r *Report) { r.SchemaVersion = "1.5" },
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

func TestAdvisoryReportFirstVersionProblem(t *testing.T) {
	for _, privacy := range []string{"portable", "local"} {
		for _, outcome := range []string{"match", "indeterminate"} {
			t.Run(privacy+"/"+outcome, func(t *testing.T) {
				plan := matchingPlan(t)
				plan.Privacy = privacy
				fixture := newMatchingFixture().inv
				inventory := projectinventory.Portable(fixture)
				n := uint64(1)
				info := Intelligence{ID: strings.Repeat("1", 64), State: "available", Selection: "current", Provenance: "operator-designated", CheckAge: "current", ReconciliationAge: "current", Records: &n, Gaps: []string{"advisory-originals-lazy", "storage-usage-not-observed"}}
				problem := AdvisoryVersionProblem{Scope: "affected", Kind: "version-outside-profile", Version: 1, Range: -1, Event: -1}
				d := AdvisoryDecision{Observation: 1, Advisory: 1, Affected: 0, Rule: 1, VersionOutcome: outcome, Outcome: outcome, Category: "malicious", Profile: "openssf-malicious-v1", Activity: "not-withdrawn", Origin: "operator-npm-rule", Source: "qualified", Support: []AdvisorySupport{}, Gaps: []string{"version-unsupported"}, FirstVersionProblem: &problem}
				a := AdvisoryReport{State: "observed", Decisions: []AdvisoryDecision{d}, Summary: AdvisorySummary{Decisions: 1, Observations: 1, TotalObservations: 1, Work: 2, BytesRead: 1, Gaps: []string{"declared-unassessed", "index-completeness"}}}
				if outcome == "match" {
					a.Decisions[0].Support = []AdvisorySupport{{Version: 0, Range: -1}}
					a.Decisions[0].EnforcementEligible = true
					a.Findings = 1
				}
				if privacy == "local" {
					local := CollectLocalObservations(fixture)
					local.Advisories = []LocalAdvisory{{Advisory: 1, ID: "MAL-2026-1", SHA256: strings.Repeat("2", 64)}}
					a.Local = &local
				}
				r := BuildReportWithAdvisories(plan, nil, Summary{}, Resources{}, false, false, &inventory, &info, &a)
				if r.SchemaVersion != "1.6" || r.ExitCode != 3 || r.Advisories.State != "observed" || r.Advisories.Findings != a.Findings || r.Advisories.Decisions[0].FullyEvaluated || r.Advisories.Decisions[0].FirstVersionProblem == &problem {
					t.Fatal("diagnostic lost, aliased, or changed matching/coverage", r.Advisories)
				}
				want := problem
				problem.Kind = "PRIVATE-mutated\x1b[31m"
				for _, format := range []string{"terminal", "json", "sarif"} {
					data, err := Render(r, format)
					if err != nil || bytes.Contains(data, []byte("PRIVATE")) {
						t.Fatal("independent diagnostic failed to render", format, err)
					}
					if privacy == "portable" && (bytes.Contains(data, []byte("left-pad")) || bytes.Contains(data, []byte("MAL-2026-1"))) {
						t.Fatal("portable diagnostic leaked identity", format)
					}
					if format == "terminal" {
						if !bytes.Contains(data, []byte(`First version problem: kind="version-outside-profile" scope="affected" version=1 range=-1 event=-1`)) {
							t.Fatal("terminal diagnostic missing fixed escaped code/locators", string(data))
						}
						continue
					}
					var rendered Report
					if format == "json" {
						if err := json.Unmarshal(data, &rendered); err != nil {
							t.Fatal(err)
						}
					} else {
						var sarif struct {
							Runs []struct {
								Properties Report `json:"properties"`
								Results    []struct {
									Properties AdvisoryDecision `json:"properties"`
								} `json:"results"`
							} `json:"runs"`
						}
						if err := json.Unmarshal(data, &sarif); err != nil || len(sarif.Runs) != 1 {
							t.Fatal("invalid SARIF", err)
						}
						rendered = sarif.Runs[0].Properties
						if len(sarif.Runs[0].Results) != a.Findings {
							t.Fatal("diagnostic created indeterminate alert or lost partial positive")
						}
						if a.Findings == 1 && !reflect.DeepEqual(sarif.Runs[0].Results[0].Properties.FirstVersionProblem, &want) {
							t.Fatal("eligible finding lost structured diagnostic")
						}
					}
					if rendered.SchemaVersion != "1.6" || rendered.Advisories == nil || len(rendered.Advisories.Decisions) != 1 || !reflect.DeepEqual(rendered.Advisories.Decisions[0].FirstVersionProblem, &want) {
						t.Fatal("structured report lost diagnostic", format)
					}
				}
				for _, corrupt := range []func(*Report){
					func(r *Report) { r.SchemaVersion = "1.3" },
					func(r *Report) { r.SchemaVersion = "1.4" },
					func(r *Report) { r.SchemaVersion = "1.5" },
					func(r *Report) { r.Advisories = nil },
					func(r *Report) { r.advisoryPlan = nil },
					func(r *Report) { r.Advisories.Decisions[0].FirstVersionProblem.Kind = "PRIVATE\x1b[31m" },
					func(r *Report) { r.Advisories.Decisions[0].FirstVersionProblem.Scope = "PRIVATE" },
					func(r *Report) { r.Advisories.Decisions[0].FirstVersionProblem.Event = 0 },
					func(r *Report) { r.Advisories.Decisions[0].FullyEvaluated = true },
					func(r *Report) { r.Advisories.Decisions[0].Gaps = []string{} },
					func(r *Report) { r.Advisories.Decisions[0].Source = "unqualified" },
					func(r *Report) {
						r.Privacy = "local"
						if privacy == "local" {
							r.Privacy = "portable"
						}
					},
				} {
					bad := r
					advisories := *r.Advisories
					advisories.Decisions = append([]AdvisoryDecision{}, r.Advisories.Decisions...)
					p := want
					advisories.Decisions[0].FirstVersionProblem = &p
					bad.Advisories = &advisories
					corrupt(&bad)
					if bad.Advisories != nil && !validateAdvisoryReport(plan, inventory, info, *bad.Advisories) {
						rejected := BuildReportWithAdvisories(plan, nil, Summary{}, Resources{}, false, false, &inventory, &info, bad.Advisories)
						if rejected.Advisories.State != "unavailable" || len(rejected.Advisories.Decisions) != 0 {
							t.Fatal("builder admitted forged diagnostic")
						}
					}
					for _, format := range []string{"terminal", "json", "sarif"} {
						if _, err := Render(bad, format); err == nil {
							t.Fatal("forged diagnostic rendered", format)
						}
					}
				}
			})
		}
	}
}

func TestAdvisoryReportBeforeInventoryIsUnavailableNotSuccessfulZero(t *testing.T) {
	info := UnavailableIntelligence()
	metadata := BuildReportWithAdvisories(Plan{}, nil, Summary{}, Resources{}, false, false, nil, &info, nil)
	if metadata.SchemaVersion != "1.2" || metadata.Advisories != nil {
		t.Fatal("advisory schema changed metadata-only builder")
	}
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
