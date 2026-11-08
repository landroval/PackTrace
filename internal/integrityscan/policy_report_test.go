package integrityscan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/integrity"
	"packtrace/internal/projectinventory"
)

func policyReportPlan(t *testing.T) Plan {
	t.Helper()
	p, err := ConfigureBuiltin(cli.ScanArgumentRequest{Manager: "npm@10.9.4", Checks: cli.ArgumentCheckIntegrity, Privacy: "portable", Format: "json", Output: "-"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyReportOperationalIntegrityAndProvenance(t *testing.T) {
	plan := policyReportPlan(t)
	// Typed retained comparison rows, not a native acquisition/qualification claim.
	records := []Record{{Assessment: integrity.InstanceAssessment{InstanceID: "1", Differences: []integrity.Difference{{Kind: integrity.DifferenceModified, InstanceID: "1", EntryID: "1", EvidenceID: "1:observed:1"}}}}}
	r := BuildReportWithPolicy(plan, records, Summary{}, Resources{}, false, false, nil, nil, nil, nil, false, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if r.SchemaVersion != "1.7" || r.Policy == nil || r.Findings != 1 || len(r.Policy.Findings) != 1 || r.Policy.Findings[0].Accepted || r.Policy.Findings[0].Enforced || r.ExitCode != 3 || !RequiredCoverageIncomplete(r) {
		t.Fatalf("lost finding or coverage: %+v policy=%+v", r, r.Policy)
	}
	for _, format := range []string{"terminal", "json", "sarif"} {
		data, err := Render(r, format)
		if err != nil {
			t.Fatal(format, err)
		}
		if bytes.Contains(data, []byte("sha256-")) {
			t.Fatal("portable fingerprint leak")
		}
		if format == "sarif" {
			var sarif struct {
				Runs []struct {
					Results []struct {
						Properties struct {
							Policy PolicyFinding `json:"policy"`
						} `json:"properties"`
					} `json:"results"`
					Invocations []struct {
						Successful bool `json:"executionSuccessful"`
					} `json:"invocations"`
				} `json:"runs"`
			}
			if json.Unmarshal(data, &sarif) != nil || len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 || sarif.Runs[0].Results[0].Properties.Policy.Ordinal != 1 || sarif.Runs[0].Invocations[0].Successful {
				t.Fatal("missing SARIF annotation or predicted success", string(data))
			}
		}
	}
	mutations := []func(*Report){
		func(r *Report) { r.SchemaVersion = "1.6" },
		func(r *Report) { r.SchemaVersion = "1.0"; r.Policy = nil },
		func(r *Report) { r.Policy = nil },
		func(r *Report) { r.policyContext = nil },
		func(r *Report) { p := *r.Policy; p.EnforcedUnaccepted = 8; r.Policy = &p },
		func(r *Report) {
			p := *r.Policy
			p.Findings = append([]PolicyFinding(nil), p.Findings...)
			p.Findings[0].Accepted = true
			r.Policy = &p
		},
		func(r *Report) { r.ExitCode = 0 },
		func(r *Report) {
			r.Coverage = append([]Coverage(nil), r.Coverage...)
			r.Coverage[0].Outcome = "completed"
		},
	}
	for i, mutate := range mutations {
		changed := r
		mutate(&changed)
		for _, format := range []string{"terminal", "json", "sarif"} {
			if _, err := Render(changed, format); err == nil {
				t.Fatalf("tampering %d rendered as %s", i, format)
			}
		}
	}
	data, _ := Render(r, "json")
	var decoded Report
	if json.Unmarshal(data, &decoded) != nil {
		t.Fatal("decode")
	}
	if _, err := Render(decoded, "json"); err == nil {
		t.Fatal("deserialized report minted parent authority")
	}
	legacy := BuildReport(plan, records, Summary{}, Resources{}, false, false)
	legacy.Policy = r.Policy
	if _, err := Render(legacy, "json"); err == nil {
		t.Fatal("policy leaked into historical schema")
	}
	var historicalNull Report
	if json.Unmarshal([]byte(`{"schemaVersion":"1.0","privacy":"portable","policy":null}`), &historicalNull) != nil {
		t.Fatal("decode typed null provenance")
	}
	if _, err := Render(historicalNull, "json"); err == nil {
		t.Fatal("historical schema admitted new explicit-null policy field")
	}
}

func TestPolicyReportCandidatesRemainMetadata(t *testing.T) {
	for _, privacy := range []string{"portable", "local"} {
		plan, inventory, info, a := candidateReportFixture(t, privacy)
		r := BuildReportWithPolicy(plan, nil, Summary{}, Resources{}, false, false, &inventory, &info, &a, nil, false, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		if r.Policy == nil || len(r.Policy.Findings) != 0 || r.Policy.EnforcedUnaccepted != 0 || r.Advisories.Candidates != 2 {
			t.Fatalf("candidate promoted or lost: %+v", r.Policy)
		}
		for _, format := range []string{"terminal", "json", "sarif"} {
			data, err := Render(r, format)
			if err != nil {
				t.Fatal(privacy, format, err)
			}
			if strings.Contains(string(data), "PRIVATE") {
				t.Fatal("private origin leak")
			}
			if format == "sarif" {
				var s struct {
					Runs []struct {
						Results []json.RawMessage `json:"results"`
					} `json:"runs"`
				}
				if json.Unmarshal(data, &s) != nil || len(s.Runs[0].Results) != 0 {
					t.Fatal("candidate alert")
				}
			}
		}
	}
}

func TestPolicyReportAcceptedAlertsAndAllCategories(t *testing.T) {
	for _, privacy := range []string{"portable", "local"} {
		plan := matchingPlan(t)
		plan.Checks = cli.ArgumentCheckIntegrity | cli.ArgumentCheckMalicious | cli.ArgumentCheckVulnerability
		plan.FailOn = plan.Checks
		plan.Privacy = privacy
		fixture := newMatchingFixture().inv
		fixture.Model.Evidence[0].SHA256 = [32]byte{1}
		fixture.Model.Evidence = append(fixture.Model.Evidence, projectinventory.Evidence{ID: 2, Scope: 1, Location: "package.json", Method: "native-input-lease", Complete: true, SHA256: [32]byte{2}})
		project, ok := BuildProjectEvidence(fixture)
		if !ok {
			t.Fatal("typed project receipt")
		}
		inventory := projectinventory.PortableMatching(fixture)
		n := uint64(2)
		info := Intelligence{ID: strings.Repeat("1", 64), State: "available", Selection: "current", Provenance: "operator-designated", CheckAge: "current", ReconciliationAge: "current", Records: &n, Gaps: []string{"advisory-originals-lazy", "storage-usage-not-observed"}}
		d := AdvisoryDecision{Observation: 1, Advisory: 1, Affected: 0, Rule: 1, VersionOutcome: "match", Outcome: "match", Category: "malicious", Profile: "openssf-malicious-v1", Activity: "not-withdrawn", Origin: "operator-npm-rule", Source: "qualified", FullyEvaluated: true, EnforcementEligible: true, Support: []AdvisorySupport{{Version: 0, Range: -1}}, Gaps: []string{}}
		v := d
		v.Sequence, v.Advisory, v.Category, v.Profile = 1, 2, "vulnerability", "osv-github-reviewed-v1"
		a := AdvisoryReport{State: "observed", Decisions: []AdvisoryDecision{d, v}, Findings: 2, Summary: AdvisorySummary{Decisions: 2, Observations: 1, TotalObservations: 1, Work: 4, BytesRead: 2, Gaps: []string{"declared-unassessed", "index-completeness"}}}
		if privacy == "local" {
			local := CollectLocalObservations(fixture)
			local.Advisories = []LocalAdvisory{{Advisory: 1, ID: "MAL-2026-1", SHA256: strings.Repeat("3", 64)}, {Advisory: 2, ID: "GHSA-2345-6789-cfgh", SHA256: strings.Repeat("4", 64)}}
			a.Local = &local
		}
		m := PolicyMaterial{Project: project, Scope: FindingScope{Project: ProjectFingerprint(project), Category: "malicious", Rule: "osv-npm", Class: "locked", Package: "left-pad", Version: "1.0.0", Origin: npmTarballOrigin("left-pad", "1.0.0"), Instance: "node_modules/left-pad", Advisory: "MAL-2026-1"}, Observation: 1, Advisory: 1, Affected: 0, SourceSHA256: project.LockSHA256, LockSourceSHA256: project.LockSHA256, OriginalSHA256: strings.Repeat("3", 64), Profile: "openssf-malicious-v1"}
		now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
		plan.Policy.Exceptions = []Exception{{ID: "PRIVATE-ID", Reason: "PRIVATE-reason", Owner: "PRIVATE-owner", ApprovedAt: "2026-01-01T00:00:00Z", ExpiresAt: "2026-01-10T00:00:00Z", Scope: m.Scope, Acceptance: AcceptanceFingerprint(m)}}
		records := []Record{{Assessment: integrity.InstanceAssessment{InstanceID: "1", Differences: []integrity.Difference{{Kind: integrity.DifferenceModified, InstanceID: "1", EntryID: "1", EvidenceID: "1:observed:1"}}}}}
		r := BuildReportWithPolicy(plan, records, Summary{}, Resources{}, false, false, &inventory, &info, &a, []PolicyMaterial{m}, false, now)
		if r.Policy == nil || len(r.Policy.Findings) != 3 || r.Policy.EnforcedUnaccepted != 2 || !r.Policy.Findings[1].Accepted || r.Policy.Findings[1].Enforced || r.Advisories.Findings != 2 || !r.Advisories.Decisions[0].EnforcementEligible || r.ExitCode != 3 || !ReportConditions(r).EnforcedUnacceptedFindings {
			t.Fatalf("%s lost acceptance/category/coverage: policy=%+v advisories=%+v", privacy, r.Policy, r.Advisories)
		}
		for _, format := range []string{"terminal", "terminal-verbose", "json", "sarif"} {
			data, err := Render(r, format)
			if format == "terminal" && (!bytes.Contains(data, []byte("accepted findings: 1")) || !bytes.Contains(data, []byte("enforced/unaccepted: 2")) || privacy == "local" && !bytes.Contains(data, []byte("Advisory findings")) || bytes.Contains(data, []byte("Candidate only:"))) {
				t.Fatal("compact view lost accepted findings or mislabeled findings as candidates", string(data))
			}
			if err != nil || bytes.Contains(data, []byte("PRIVATE")) || bytes.Contains(data, []byte("registry.npmjs.org")) {
				t.Fatal(privacy, format, err, string(data))
			}
			if privacy == "portable" && (bytes.Contains(data, []byte("sha256-")) || bytes.Contains(data, []byte("left-pad")) || bytes.Contains(data, []byte("MAL-2026-1"))) {
				t.Fatal("portable policy identity leak")
			}
			if format == "sarif" {
				var s struct {
					Runs []struct {
						Results []struct {
							Properties struct {
								Policy PolicyFinding `json:"policy"`
							} `json:"properties"`
						} `json:"results"`
					} `json:"runs"`
				}
				if json.Unmarshal(data, &s) != nil || len(s.Runs[0].Results) != 3 || !s.Runs[0].Results[1].Properties.Policy.Accepted {
					t.Fatal("accepted alert disappeared", string(data))
				}
			}
		}
		limited := BuildReportWithPolicy(plan, records, Summary{}, Resources{}, false, false, &inventory, &info, &a, []PolicyMaterial{m}, true, now)
		if limited.Policy == nil || limited.Policy.EnforcedUnaccepted != 3 || limited.Policy.Findings[1].Accepted || limited.ExitCode != r.ExitCode {
			t.Fatal("material limit suppressed findings or waived gaps")
		}
		missing := BuildReportWithPolicy(plan, records, Summary{}, Resources{}, false, false, &inventory, &info, &a, nil, false, now)
		if missing.Policy == nil || missing.Policy.EnforcedUnaccepted != 3 || missing.Policy.Findings[1].Accepted {
			t.Fatal("missing receipt accepted")
		}
	}
}

func TestRequiredCoverageAndComparisonConditions(t *testing.T) {
	for _, outcome := range []string{"completed", "not-applicable", "incomplete", "not-run", "unknown", ""} {
		r := Report{Coverage: []Coverage{{Check: "required", Required: true, Outcome: outcome}, {Check: "excluded", Outcome: "not-run"}}}
		want := outcome != "completed" && outcome != "not-applicable"
		if RequiredCoverageIncomplete(r) != want {
			t.Fatal(outcome)
		}
	}
	if !RequiredCoverageIncomplete(Report{}) {
		t.Fatal("absence became completion")
	}
	plan := policyReportPlan(t)
	r := BuildReportWithPolicy(plan, nil, Summary{}, Resources{QueryFailed: true}, true, true, nil, nil, nil, nil, true, time.Now().UTC())
	c := ReportConditions(r)
	if !c.Interrupted || !c.RequiredCoverageIncomplete || cli.SelectScanExit(c) != 130 {
		t.Fatalf("lost interruption/coverage %+v", c)
	}
	r.Policy = nil
	if !ReportConditions(r).ReportPreventingError {
		t.Fatal("missing evaluation became usable")
	}
}
