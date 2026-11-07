package integrityscan

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	"packtrace/internal/nativefs"
	"packtrace/internal/projectinventory"
)

type matchingFixture struct{ inv projectinventory.Result }

func newMatchingFixture() matchingFixture {
	return matchingFixture{inv: projectinventory.Result{Complete: true,
		Selection: projectinventory.Selection{Profile: "npm@10.9.4", Family: "npm", File: "package-lock.json", State: "usable", Reason: "none"},
		Model:     projectinventory.Model{Scopes: []projectinventory.Scope{{ID: 1, Kind: "project", Status: "complete"}}, Evidence: []projectinventory.Evidence{{ID: 1, Scope: 1, Location: "package-lock.json", Method: "native-input-lease", Complete: true}}, Observations: []projectinventory.Observation{{ID: 1, Workspace: 1, Source: 1, Class: "locked", Kind: "url", Status: "complete", Location: "node_modules/left-pad", Name: "left-pad", Version: "1.0.0", Origin: npmTarballOrigin("left-pad", "1.0.0"), Fields: map[string]string{"installation-name": "left-pad", "name-qualification": "installation-claim", "version-state": "value", "origin-state": "value"}}}}}}
}

var matchingNow = time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)

const matchingRaw = `{"id":"MAL-2026-1","modified":"2026-10-02T00:00:00Z","published":"2026-10-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["1.0.0"]}],"database_specific":{"malicious-packages-origins":[{"source":"packtrace-fixture","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","import_time":"2026-10-02T00:00:00Z","modified_time":"2026-10-02T00:00:00Z"}]}}`

func TestMaliciousProfileClosedMetadata(t *testing.T) {
	if !maliciousProfile([]byte(matchingRaw), matchingNow) {
		t.Fatal("documented origins rejected")
	}
	for _, tc := range []struct{ name, old, new string }{
		{"id-alone", `"database_specific":{`, `"database_specific":{"malicious-packages-origins":[],"other":`},
		{"other-namespace", "MAL-2026-1", "GHSA-xxxx-yyyy-zzzz"},
		{"no-origins", `"malicious-packages-origins"`, `"origins"`},
		{"correction", `"database_specific":{`, `"database_specific":{"withdrawn_versions":["1.0.0"],`},
		{"unknown-activity", `"affected":`, `"active":true,"affected":`},
		{"unknown-affected", `"package":`, `"version_corrections":[],"package":`},
		{"unknown-package", `"ecosystem":"npm"`, `"ecosystem":"npm","activity":"active"`},
		{"unknown-range", `"versions":["1.0.0"]`, `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}],"correction":true}]`},
		{"unknown-event", `"versions":["1.0.0"]`, `"ranges":[{"type":"SEMVER","events":[{"introduced":"0","withdrawn":true}]}]`},
		{"nonempty-extension", `"package":`, `"ecosystem_specific":{"correction":true},"package":`},
		{"bad-source", `packtrace-fixture`, `../../source`},
		{"source-repository-path", `packtrace-fixture`, `ossf/package-analysis`},
		{"source-url", `packtrace-fixture`, `https://example.invalid/source`},
		{"source-uppercase", `packtrace-fixture`, `PackTrace`},
		{"multiple-affected", `"versions":["1.0.0"]}]`, `"versions":["1.0.0"]},{"package":{"ecosystem":"npm","name":"other"},"versions":["1.0.0"]}]`},
		{"upper-hash", `0123456789abcdef`, `0123456789ABCDEF`},
		{"null-time", `"import_time":"2026-10-02T00:00:00Z"`, `"import_time":null`},
		{"future", `"import_time":"2026-10-02T00:00:00Z"`, `"import_time":"2026-11-02T00:00:00Z"`},
		{"inconsistent", `"import_time":"2026-10-02T00:00:00Z"`, `"import_time":"2026-10-01T00:00:00Z"`},
		{"origin-unknown", `"source":`, `"withdrawn":false,"source":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(matchingRaw, tc.old, tc.new, 1)
			if maliciousProfile([]byte(raw), matchingNow) {
				t.Fatal("unsupported profile promoted")
			}
		})
	}
}
func TestMatchingActivityConservative(t *testing.T) {
	for _, tc := range []struct{ name, extra, want string }{
		{"absent", "", "not-withdrawn"},
		{"withdrawn", `,"withdrawn":"2026-10-02T00:00:00Z"`, "withdrawn"},
		{"null", `,"withdrawn":null`, "unknown"},
		{"future", `,"withdrawn":"2026-12-02T00:00:00Z"`, "unknown"},
		{"before-published", `,"withdrawn":"2026-09-02T00:00:00Z"`, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(matchingRaw, `"affected":`, strings.TrimPrefix(tc.extra, ",")+`,"affected":`, 1)
			if tc.extra == "" {
				raw = matchingRaw
			}
			doc, e := intel.ParseOSVRecord([]byte(raw))
			if e != nil {
				t.Fatal(e)
			}
			times, e := intel.ProjectOSVTimes(doc)
			if e != nil {
				t.Fatal(e)
			}
			if got := matchingActivity(times, matchingNow); got != tc.want {
				t.Fatalf("%s != %s", got, tc.want)
			}
		})
	}
}
func TestSharedVersionPrimitiveDoesNotBorrowAnotherAffectedSlot(t *testing.T) {
	raw := `{"id":"MAL-2026-1","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["2.0.0"]},{"package":{"ecosystem":"npm","name":"other"},"versions":["1.0.0"]}]}`
	doc, e := intel.ParseOSVRecord([]byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	header, _ := intel.ProjectOSVHeader(doc)
	affected, _ := intel.ProjectOSVAffected(doc)
	identity, _ := intel.QualifyOSVNPMIdentities(header, affected)
	query, _ := intel.ParseSemVer("1.0.0")
	versions, e := intel.EvaluateOSVVersionConditions(header, affected, query)
	if e != nil {
		t.Fatal(e)
	}
	if identity.Entries[0].Name.Value != "left-pad" || versions.Entries[0].Outcome != intel.OSVVersionNoMatch || versions.Entries[1].Outcome != intel.OSVVersionMatch || len(versions.Entries[0].Support) != 0 {
		t.Fatal("cross-slot support")
	}
}
func TestSharedVersionPartialPositiveAndConservativeNegative(t *testing.T) {
	for _, tc := range []struct {
		name, conditions string
		want             intel.OSVVersionOutcome
		full             bool
	}{
		{"partial-positive", `"versions":["1.0.0","unsupported"]`, intel.OSVVersionMatch, false},
		{"partial-negative", `"versions":["2.0.0","unsupported"]`, intel.OSVVersionIndeterminate, false},
		{"complete-negative", `"versions":["2.0.0"]`, intel.OSVVersionNoMatch, true},
		{"unsupported-range-positive", `"versions":["1.0.0"],"ranges":[{"type":"GIT","repo":"https://example.invalid/repo","events":[{"introduced":"0"}]}]`, intel.OSVVersionMatch, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(matchingRaw, `"versions":["1.0.0"]`, tc.conditions, 1)
			doc, err := intel.ParseOSVRecord([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			h, _ := intel.ProjectOSVHeader(doc)
			a, _ := intel.ProjectOSVAffected(doc)
			q, _ := intel.ParseSemVer("1.0.0")
			v, err := intel.EvaluateOSVVersionConditions(h, a, q)
			if err != nil || v.Entries[0].Outcome != tc.want || v.Entries[0].FullyEvaluated != tc.full {
				t.Fatal(v, err)
			}
		})
	}
}
func matchingSnapshot(t *testing.T) (*intelstore.Snapshot, Intelligence) {
	t.Helper()
	return matchingSnapshotNamed(t, "matching.bundle")
}

func matchingSnapshotNamed(t *testing.T, filename string) (*intelstore.Snapshot, Intelligence) {
	t.Helper()
	ctx := context.Background()
	store, e := intelstore.Open(ctx, filepath.Join(t.TempDir(), "state"), intelstore.CreateOwned)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	fixturePath, e := filepath.Abs(filepath.Join("..", "execution", "testdata", "intel"))
	if e != nil {
		t.Fatal(e)
	}
	root, e := nativefs.OpenRoot(ctx, fixturePath)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	input, e := root.OpenDistributionInput(ctx, filename)
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	imported, e := store.Import(ctx, input, intelstore.ImportOptions{})
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := store.ReadPinned(ctx, &imported.Generation)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { snapshot.Close() })
	observed, e := snapshot.Observe(ctx, matchingNow, &imported.Generation)
	if e != nil {
		t.Fatal(e)
	}
	return snapshot, SnapshotIntelligence(observed, "expected-digest")
}
func matchingPinnedPlan(t *testing.T, info Intelligence) Plan {
	t.Helper()
	plan := matchingPlan(t)
	raw, err := hex.DecodeString(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	plan.TrustedSnapshotDigest = "sha256-" + base64.StdEncoding.EncodeToString(raw)
	return plan
}
func TestMatchInventoryActualSnapshot(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	for _, tc := range []struct {
		name    string
		version string
		pin     bool
		want    string
	}{
		{"positive", "1.0.0", true, "match"}, {"negative", "2.0.0", true, "no-match"}, {"unpinned", "1.0.0", false, "indeterminate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := matchingPinnedPlan(t, info)
			f := newMatchingFixture()
			f.inv.Model.Observations[0].Version = tc.version
			f.inv.Model.Observations[0].Origin = npmTarballOrigin("left-pad", tc.version)
			plan.Policy.NPMOrigins[0].Version = tc.version
			plan.Policy.NPMOrigins[0].Origin = f.inv.Model.Observations[0].Origin
			if !tc.pin {
				plan.TrustedPolicyDigest = ""
			}
			rows := []AdvisoryDecision{}
			summary, e := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
			if e != nil {
				t.Fatal(e)
			}
			public := projectinventory.Portable(f.inv)
			if e := ValidateAdvisorySummary(summary, rows, public); e != nil {
				t.Fatal("closure", summary, e)
			}
			if len(rows) == 0 || rows[0].Outcome != tc.want {
				t.Fatalf("decision: %+v", rows)
			}
			for _, row := range rows {
				if e := ValidateAdvisoryDecision(plan, public, info, row); e != nil {
					t.Fatalf("invalid emitted row %+v: %v", row, e)
				}
			}
			if tc.pin {
				if len(rows) != 3 || summary.BytesRead == 0 {
					t.Fatal("missing real originals", summary)
				}
				if rows[1].Activity != "withdrawn" || rows[1].Outcome != "no-match" || rows[1].EnforcementEligible {
					t.Fatal("withdrawal", rows[1])
				}
				if rows[2].Outcome != "indeterminate" || rows[2].Category != "unknown" || rows[2].EnforcementEligible {
					t.Fatal("correction", rows[2])
				}
			} else if summary.BytesRead != 0 {
				t.Fatal("unpinned identity read")
			}
			encoded, _ := json.Marshal(rows)
			for _, private := range []string{"left-pad", "registry.npmjs.org", "MAL-2026", "sha256", "node_modules"} {
				if strings.Contains(string(encoded), private) {
					t.Fatal("private output", private)
				}
			}
		})
	}
}
func TestMatchInventoryUnqualifiedImportCannotClassify(t *testing.T) {
	snapshot, _ := matchingSnapshot(t)
	observed, err := snapshot.Observe(context.Background(), matchingNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	info := SnapshotIntelligence(observed, "current")
	plan := matchingPlan(t)
	f := newMatchingFixture()
	rows := []AdvisoryDecision{}
	_, err = MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if err != nil || len(rows) != 3 || rows[0].VersionOutcome != "match" {
		t.Fatal(rows, err)
	}
	for _, d := range rows {
		if d.Category != "unknown" || d.Profile != "unknown" || d.Outcome != "indeterminate" || d.EnforcementEligible {
			t.Fatal("unqualified source promoted", d)
		}
		if ValidateAdvisoryDecision(plan, projectinventory.Portable(f.inv), info, d) != nil {
			t.Fatal("invalid unqualified row", d)
		}
	}
}
func TestMatchInventoryMissingIdentityAndReadFailureStayVisible(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	plan := matchingPinnedPlan(t, info)
	f := newMatchingFixture()
	rule := NPMOriginRule{Location: "node_modules/not-in-snapshot", Name: "not-in-snapshot", Version: "1.0.0", Origin: npmTarballOrigin("not-in-snapshot", "1.0.0")}
	plan.Policy.NPMOrigins[0] = rule
	o := &f.inv.Model.Observations[0]
	o.Location, o.Name, o.Origin = rule.Location, rule.Name, rule.Origin
	o.Fields["installation-name"] = rule.Name
	for _, failed := range []bool{false, true} {
		if failed {
			if err := snapshot.Close(); err != nil {
				t.Fatal(err)
			}
		}
		rows := []AdvisoryDecision{}
		summary, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
		if err != nil || len(rows) != 1 || rows[0].Outcome != "indeterminate" || rows[0].EnforcementEligible {
			t.Fatal(rows, err)
		}
		gap := "identity-empty"
		if failed {
			gap = "identity-read-failed"
		}
		if !hasMatchingGap(rows[0].Gaps, gap) {
			t.Fatal(rows[0])
		}
		if ValidateAdvisoryDecision(plan, projectinventory.Portable(f.inv), info, rows[0]) != nil || ValidateAdvisorySummary(summary, rows, projectinventory.Portable(f.inv)) != nil {
			t.Fatal("invalid conservative result")
		}
	}
}
func TestMatchingCancellationEmissionAndActiveNotTotalCap(t *testing.T) {
	plan := matchingPlan(t)
	f := newMatchingFixture()
	info := UnavailableIntelligence()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := MatchInventory(ctx, plan, f.inv, nil, info, matchingNow, func(AdvisoryDecision) error { return nil }); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	sentinel := errors.New("stop")
	if _, e := MatchInventory(context.Background(), plan, f.inv, nil, info, matchingNow, func(AdvisoryDecision) error { return sentinel }); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	for i := 1; i < 65; i++ {
		o := f.inv.Model.Observations[0]
		o.ID = uint32(i + 1)
		o.Location = "other"
		f.inv.Model.Observations = append(f.inv.Model.Observations, o)
	}
	rows := []AdvisoryDecision{}
	s, e := MatchInventory(context.Background(), plan, f.inv, nil, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if e != nil || s.Observations != 65 || s.TotalObservations != 65 || s.Work != 65 || hasMatchingGap(s.Gaps, "observation-limit") {
		t.Fatal(s, e)
	}
	if ValidateAdvisorySummary(s, rows, projectinventory.Portable(f.inv)) != nil {
		t.Fatal("cap closure invalid")
	}
}
func TestAdvisoryCategorySelectionAndClosedProfiles(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	f := newMatchingFixture()
	plan := matchingPinnedPlan(t, info)
	var positive AdvisoryDecision
	_, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error {
		if d.Outcome == "match" {
			positive = d
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	public := projectinventory.Portable(f.inv)
	// Admission tests intentionally vary controlled profile/category declarations;
	// classifier behavior is independently original-bound, not inferred here.
	for _, tc := range []struct {
		category, profile string
		selected          cli.ArgumentChecks
	}{
		{"malicious", "openssf-malicious-v1", cli.ArgumentCheckMalicious},
		{"malicious", "osv-openssf-malicious-v1", cli.ArgumentCheckMalicious},
		{"malicious", "osv-github-malware-v1", cli.ArgumentCheckMalicious},
		{"vulnerability", "osv-github-reviewed-v1", cli.ArgumentCheckVulnerability},
	} {
		for _, checks := range []cli.ArgumentChecks{cli.ArgumentCheckMalicious, cli.ArgumentCheckVulnerability, cli.ArgumentCheckMalicious | cli.ArgumentCheckVulnerability} {
			p := plan
			p.Checks = checks
			d := positive
			d.Category = tc.category
			d.Profile = tc.profile
			d.EnforcementEligible = checks&tc.selected != 0
			if ValidateAdvisoryDecision(p, public, info, d) != nil {
				t.Fatal("category selection", tc, d)
			}
			d.EnforcementEligible = !d.EnforcementEligible
			if ValidateAdvisoryDecision(p, public, info, d) == nil {
				t.Fatal("forged category eligibility")
			}
		}
	}
	d := positive
	d.Category = "vulnerability"
	if ValidateAdvisoryDecision(plan, public, info, d) == nil {
		t.Fatal("cross-category profile")
	}
}

func TestAdvisoryParentValidatorsRejectForgery(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	plan := matchingPinnedPlan(t, info)
	f := newMatchingFixture()
	rows := []AdvisoryDecision{}
	summary, e := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if e != nil {
		t.Fatal(e)
	}
	public := projectinventory.Portable(f.inv)
	for _, tc := range []struct {
		name   string
		change func(*AdvisoryDecision)
	}{
		{"gap", func(d *AdvisoryDecision) { d.Gaps = []string{"private-name"} }},
		{"observation", func(d *AdvisoryDecision) { d.Observation = 2 }},
		{"rule", func(d *AdvisoryDecision) { d.Rule = 2 }},
		{"no-slot", func(d *AdvisoryDecision) { d.Affected = -1 }},
		{"no-support", func(d *AdvisoryDecision) { d.Support = nil }},
		{"origin", func(d *AdvisoryDecision) { d.Origin = "unqualified" }},
		{"source", func(d *AdvisoryDecision) { d.Source = "unqualified" }},
		{"category", func(d *AdvisoryDecision) { d.Category = "unknown" }},
		{"activity", func(d *AdvisoryDecision) { d.Activity = "unknown" }},
		{"eligible", func(d *AdvisoryDecision) { d.EnforcementEligible = false }},
		{"unsupported-activity", func(d *AdvisoryDecision) { d.Activity = "active" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := rows[0]
			tc.change(&d)
			if ValidateAdvisoryDecision(plan, public, info, d) == nil {
				t.Fatal("forgery admitted")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*AdvisorySummary, *[]AdvisoryDecision)
	}{
		{"count", func(s *AdvisorySummary, r *[]AdvisoryDecision) { s.Decisions++ }},
		{"observation-count", func(s *AdvisorySummary, r *[]AdvisoryDecision) { s.Observations++ }},
		{"bytes", func(s *AdvisorySummary, r *[]AdvisoryDecision) { s.BytesRead = maxMatchingBytes + 1 }},
		{"work-cap", func(s *AdvisorySummary, r *[]AdvisoryDecision) { s.Work = maxMatchingDecisions + 1 }},
		{"missing-evaluation-work", func(s *AdvisorySummary, r *[]AdvisoryDecision) { s.Work = s.Decisions }},
		{"installed-count", func(s *AdvisorySummary, r *[]AdvisoryDecision) { s.InstalledObservations++ }},
		{"total-installed-count", func(s *AdvisorySummary, r *[]AdvisoryDecision) { s.TotalInstalledObservations++ }},
		{"unread-evaluations", func(s *AdvisorySummary, r *[]AdvisoryDecision) { s.BytesRead = 0 }},
		{"old-locked-only-claim", func(s *AdvisorySummary, r *[]AdvisoryDecision) {
			s.Gaps = append(append([]string{}, s.Gaps...), "locked-only")
		}},
		{"old-installed-unassessed-claim", func(s *AdvisorySummary, r *[]AdvisoryDecision) {
			s.Gaps = append(append([]string{}, s.Gaps...), "installed-unassessed")
		}},
		{"hidden-truncation", func(s *AdvisorySummary, r *[]AdvisoryDecision) { s.TotalObservations++ }},
		{"duplicate", func(s *AdvisorySummary, r *[]AdvisoryDecision) {
			*r = append(*r, (*r)[0])
			(*r)[len(*r)-1].Sequence = len(*r) - 1
			s.Decisions++
		}},
		{"gap", func(s *AdvisorySummary, r *[]AdvisoryDecision) { s.Gaps = []string{"complete"} }},
		{"global-ordinal", func(s *AdvisorySummary, r *[]AdvisoryDecision) { (*r)[0].Advisory = 17 }},
		{"false-byte-cap", func(s *AdvisorySummary, r *[]AdvisoryDecision) {
			s.Gaps = append(append([]string{}, s.Gaps...), "identity-byte-limit")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := summary
			r := append([]AdvisoryDecision{}, rows...)
			tc.change(&s, &r)
			if ValidateAdvisorySummary(s, r, public) == nil {
				t.Fatal("closure forgery admitted")
			}
		})
	}
}
