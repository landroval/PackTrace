package integrityscan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/projectinventory"
)

// Hand-built, typed public evidence: no original/corpus/state access is needed.
func candidateReportFixture(t *testing.T, privacy string) (Plan, projectinventory.PublicInventory, Intelligence, AdvisoryReport) {
	t.Helper()
	plan := matchingPlan(t)
	plan.Policy.AdvisoryCandidates = true
	plan.Privacy = privacy
	fixture := newMatchingFixture().inv
	fixture.Model.Observations[0].Origin = "https://PRIVATE.invalid/left-pad.tgz"
	inventory := projectinventory.PortableMatching(fixture)
	n := uint64(1)
	info := Intelligence{ID: strings.Repeat("1", 64), State: "available", Selection: "current", Provenance: "operator-designated", CheckAge: "current", ReconciliationAge: "current", Records: &n, Gaps: []string{"advisory-originals-lazy", "storage-usage-not-observed"}}
	d := AdvisoryDecision{Observation: 1, Advisory: 1, Affected: 0, VersionOutcome: "match", Outcome: "indeterminate", Category: "malicious", Profile: "openssf-malicious-v1", Activity: "not-withdrawn", Origin: "unqualified", Source: "qualified", Candidate: true, FullyEvaluated: true, Support: []AdvisorySupport{{Version: 0, Range: -1}}, Gaps: []string{"origin-unqualified"}}
	second := d
	second.Sequence, second.Affected = 1, 1
	second.FullyEvaluated = false
	second.Gaps = []string{"origin-unqualified", "version-unsupported"}
	second.FirstVersionProblem = &AdvisoryVersionProblem{Scope: "affected", Kind: "version-outside-profile", Version: 1, Range: -1, Event: -1}
	a := AdvisoryReport{State: "observed", Decisions: []AdvisoryDecision{d, second}, Candidates: 2, Summary: AdvisorySummary{Decisions: 2, Observations: 1, TotalObservations: 1, Work: 3, BytesRead: 1, Gaps: []string{"declared-unassessed", "index-completeness"}}}
	if privacy == "local" {
		local := CollectLocalObservations(fixture)
		local.Advisories = []LocalAdvisory{{Advisory: 1, ID: "MAL-2026-1", SHA256: strings.Repeat("2", 64)}}
		a.Local = &local
	}
	return plan, inventory, info, a
}

func TestCandidateReportCountsObservationRowsWithoutAlerts(t *testing.T) {
	for _, privacy := range []string{"portable", "local"} {
		t.Run(privacy, func(t *testing.T) {
			plan, inventory, info, a := candidateReportFixture(t, privacy)
			r := BuildReportWithAdvisories(plan, nil, Summary{}, Resources{}, false, false, &inventory, &info, &a)
			if r.SchemaVersion != "1.6" || r.Advisories.State != "observed" || r.Advisories.Candidates != 2 || r.Advisories.Findings != 0 || r.Findings != 0 {
				t.Fatal("lost candidates or manufactured findings", r.Advisories)
			}
			a.Decisions[1].FirstVersionProblem.Kind = "PRIVATE-mutated"
			a.Decisions[0].Support[0].Version = 10
			a.Decisions[0].Gaps[0] = "PRIVATE-mutated"
			for _, format := range []string{"terminal", "json", "sarif"} {
				data, err := Render(r, format)
				if err != nil || bytes.Contains(data, []byte("PRIVATE")) {
					t.Fatal(format, err, string(data))
				}
				if privacy == "portable" && (bytes.Contains(data, []byte("left-pad")) || bytes.Contains(data, []byte("MAL-2026-1")) || bytes.Contains(data, []byte(strings.Repeat("2", 64)))) {
					t.Fatal("portable identity leak", format)
				}
				if format == "terminal" {
					if !bytes.Contains(data, []byte("eligible matches=0; candidates=2")) || bytes.Count(data, []byte("Candidate only: local version match; origin unconfirmed; not enforcement-eligible")) != 2 {
						t.Fatal("ambiguous terminal candidate presentation", string(data))
					}
					continue
				}
				var decoded Report
				if format == "json" {
					if err := json.Unmarshal(data, &decoded); err != nil {
						t.Fatal(err)
					}
				} else {
					var sarif struct {
						Runs []struct {
							Properties Report            `json:"properties"`
							Results    []json.RawMessage `json:"results"`
						} `json:"runs"`
					}
					if err := json.Unmarshal(data, &sarif); err != nil || len(sarif.Runs) != 1 {
						t.Fatal("invalid SARIF", err)
					}
					if len(sarif.Runs[0].Results) != 0 {
						t.Fatal("candidate became alert")
					}
					decoded = sarif.Runs[0].Properties
				}
				if decoded.SchemaVersion != "1.6" || decoded.Advisories.Candidates != 2 || !decoded.Advisories.Decisions[0].Candidate || decoded.Advisories.Decisions[1].FirstVersionProblem.Kind != "version-outside-profile" {
					t.Fatal("structured candidate/diagnostic lost")
				}
			}
		})
	}
}

func TestCandidateReportRejectsForgedCountFlagsAndContext(t *testing.T) {
	mutations := map[string]func(*Plan, *projectinventory.PublicInventory, *Intelligence, *AdvisoryReport){
		"count-zero": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Candidates = 0
		},
		"count-negative": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Candidates = -1
		},
		"count-unique-observations": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Candidates = 1
		},
		"findings": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) { a.Findings = 2 },
		"false-flag": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Decisions[0].Candidate = false
			a.Candidates = 1
		},
		"eligible": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Decisions[0].EnforcementEligible = true
			a.Findings = 1
		},
		"final-match": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Decisions[0].Outcome = "match"
		},
		"final-negative": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Decisions[0].Outcome = "no-match"
		},
		"withdrawn": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Decisions[0].Activity = "withdrawn"
		},
		"unknown-source": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Decisions[0].Source = "unqualified"
		},
		"unknown-profile": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Decisions[0].Profile = "unknown"
		},
		"lock-attribution": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Decisions[0].LockedObservation = 1
		},
		"optout": func(p *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, _ *AdvisoryReport) {
			p.Policy.AdvisoryCandidates = false
		},
		"no-pin": func(p *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, _ *AdvisoryReport) {
			p.TrustedPolicyDigest = ""
		},
		"incomplete-source": func(_ *Plan, inv *projectinventory.PublicInventory, _ *Intelligence, _ *AdvisoryReport) {
			inv.Evidence[0].Status = "incomplete"
		},
		"portable-local": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Local = &LocalDetails{}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			plan, inv, info, a := candidateReportFixture(t, "portable")
			mutate(&plan, &inv, &info, &a)
			if validateAdvisoryReport(plan, inv, info, a) {
				t.Fatal("forgery validated")
			}
			rejected := BuildReportWithAdvisories(plan, nil, Summary{}, Resources{}, false, false, &inv, &info, &a)
			if rejected.Advisories.State != "unavailable" || rejected.Advisories.Candidates != 0 {
				t.Fatal("builder admitted forgery")
			}
			a.candidatesPresent = true
			forged := rejected
			forged.Advisories = &a
			for _, format := range []string{"json", "terminal", "sarif"} {
				if _, err := Render(forged, format); err == nil {
					t.Fatal("forgery rendered", format)
				}
			}
		})
	}
}

func TestCandidateReportVersionNegativeRemainsIndeterminate(t *testing.T) {
	plan, inv, info, a := candidateReportFixture(t, "portable")
	a.Decisions = a.Decisions[:1]
	a.Decisions[0].Candidate = false
	a.Decisions[0].VersionOutcome = "no-match"
	a.Decisions[0].Support = []AdvisorySupport{}
	a.Candidates, a.Summary.Decisions, a.Summary.Work = 0, 1, 2
	r := BuildReportWithAdvisories(plan, nil, Summary{}, Resources{}, false, false, &inv, &info, &a)
	if r.Advisories.State != "observed" || r.Advisories.Candidates != 0 || r.Advisories.Findings != 0 || r.Advisories.Decisions[0].Outcome != "indeterminate" {
		t.Fatal("candidate version negative lost or laundered", r.Advisories)
	}
	for _, format := range []string{"json", "terminal", "sarif"} {
		if _, err := Render(r, format); err != nil {
			t.Fatal(format, err)
		}
	}
}

func TestCandidateReportCompatibleHistoricalReports(t *testing.T) {
	for _, schema := range []string{"1.3", "1.4", "1.5"} {
		plan, inv, info, a := candidateReportFixture(t, "portable")
		plan.Policy.AdvisoryCandidates = false
		a.Candidates, a.Findings = 0, len(a.Decisions)
		for i := range a.Decisions {
			d := &a.Decisions[i]
			d.Origin, d.Rule, d.Outcome = "operator-npm-rule", 1, "match"
			d.Candidate, d.EnforcementEligible = false, true
			d.Gaps = []string{}
			if schema != "1.5" || i == 0 {
				d.FullyEvaluated, d.FirstVersionProblem = true, nil
			} else {
				d.Gaps = []string{"version-unsupported"}
			}
		}
		r := BuildReportWithAdvisories(plan, nil, Summary{}, Resources{}, false, false, &inv, &info, &a)
		if r.Advisories.State != "observed" {
			t.Fatal("invalid qualified historical fixture", schema)
		}
		r.SchemaVersion = schema
		r.Advisories.candidatesPresent = false // Model an actually historical builder.
		for _, format := range []string{"json", "terminal", "sarif"} {
			data, err := Render(r, format)
			if err != nil || format != "terminal" && bytes.Contains(data, []byte(`"candidates"`)) {
				t.Fatal("compatible legacy report failed or gained a new field", schema, format, err)
			}
		}
	}
}

func TestCandidateReportHistoricalSchemasAndRequiredZeroCount(t *testing.T) {
	plan := matchingPlan(t)
	r := BuildReportWithAdvisories(plan, nil, Summary{}, Resources{}, false, true, nil, nil, nil)
	for _, format := range []string{"json", "sarif"} {
		data, err := Render(r, format)
		if err != nil || !bytes.Contains(data, []byte(`"candidates":0`)) && !bytes.Contains(data, []byte(`"candidates": 0`)) {
			t.Fatal("1.6 zero count omitted", format, err)
		}
	}
	for _, schema := range []string{"1.3", "1.4", "1.5"} {
		relabeled := r
		relabeled.SchemaVersion = schema
		for _, format := range []string{"json", "terminal", "sarif"} {
			if _, err := Render(relabeled, format); err == nil {
				t.Fatal("new zero field relabeled", schema, format)
			}
		}
		legacy := relabeled
		a := *r.Advisories
		a.candidatesPresent = false
		legacy.Advisories = &a
		data, err := Render(legacy, "json")
		if err != nil || bytes.Contains(data, []byte(`"candidates"`)) {
			t.Fatal("legacy report changed shape", schema, err)
		}
		// Presence survives decoding even if the new count is zero.
		var decoded AdvisoryReport
		if err := json.Unmarshal([]byte(`{"state":"unavailable","decisions":[],"summary":{"gaps":[]},"findings":0,"candidates":0}`), &decoded); err != nil {
			t.Fatal(err)
		}
		legacy.Advisories = &decoded
		if _, err := Render(legacy, "json"); err == nil {
			t.Fatal("decoded new count laundered to old schema")
		}
	}
	var oldWithFlag AdvisoryReport
	if err := json.Unmarshal([]byte(`{"state":"unavailable","decisions":[{"candidate":false}],"summary":{"gaps":[]},"findings":0}`), &oldWithFlag); err != nil {
		t.Fatal(err)
	}
	// Even removing the row must not erase its new-field provenance.
	oldWithFlag.Decisions = []AdvisoryDecision{}
	old := r
	old.SchemaVersion, old.Advisories = "1.5", &oldWithFlag
	if _, err := Render(old, "json"); err == nil {
		t.Fatal("explicit false candidate field relabeled to old schema")
	}
	var a AdvisoryReport
	if err := json.Unmarshal([]byte(`{"candidates":null}`), &a); err == nil {
		t.Fatal("null count accepted")
	}
}
