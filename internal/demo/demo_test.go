package demo

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Removing same-slot correlation, using inclusive fixed, or ignoring withdrawal
// must break these literal expectations through the real reader/evaluator pipeline.
func TestEvaluateScenario(t *testing.T) {
	for _, tc := range []struct {
		name       string
		candidates int
		outcomes   []string
		fully      bool
		withdrawal string
	}{
		{"candidate", 1, []string{"match"}, true, "not-declared"},
		{"no-version-match", 0, []string{"no-match"}, true, "not-declared"},
		{"unsupported", 0, []string{"indeterminate"}, false, "not-declared"},
		{"withdrawn", 0, []string{"match"}, true, "reported"},
		{"different-identity", 0, []string{"match", "no-match"}, true, "not-declared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EvaluateScenario(tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if got.Schema != "packtrace.demo.v1" || !got.Experimental || got.Scope != "owned-synthetic-fixture" || got.Scenario != tc.name || got.ExitCode != 3 {
				t.Fatal("demo falsely qualified its scope or exit", got)
			}
			if len(got.Inventory) != 1 || got.Inventory[0].Name != "demo-package" || got.Inventory[0].Observation != "locked" || got.Inventory[0].Location != "node_modules/demo-package" {
				t.Fatal("locked observation lost or installation invented", got.Inventory)
			}
			wantVersion := "1.2.3"
			if tc.name == "no-version-match" {
				wantVersion = "2.0.0"
			}
			if got.Inventory[0].Version != wantVersion || len(got.Candidates) != tc.candidates || got.Findings == nil || len(got.Findings) != 0 || len(got.Evaluations) != len(tc.outcomes) {
				t.Fatal("wrong observations/candidates/findings", got)
			}
			for i, e := range got.Evaluations {
				if e.PackageIndex != 0 || e.AffectedIndex != i || e.VersionOutcome != tc.outcomes[i] || e.VersionFullyEvaluated != tc.fully || e.Withdrawal != tc.withdrawal || e.IdentityQualification != "candidate" {
					t.Fatal("evaluation, source slot or limitation lost", e)
				}
			}
			if tc.name == "different-identity" && (got.Evaluations[0].IdentityEqual || !got.Evaluations[1].IdentityEqual) {
				t.Fatal("different affected identities collapsed")
			}
			if tc.candidates == 1 && (got.Candidates[0].PackageIndex != 0 || got.Candidates[0].AffectedIndex != 0 || got.Candidates[0].EnforcementEligible || got.Candidates[0].Kind != "identity-version-only" || !reflect.DeepEqual(got.Evaluations[0].Support, []Support{{-1, 0}})) {
				t.Fatal("candidate promoted or support locator lost")
			}
			if tc.name == "unsupported" && (len(got.Evaluations[0].Problems) == 0 || got.Evaluations[0].Problems[0].Kind != "range-outside-profile" || got.Evaluations[0].Problems[0].RangeIndex != 0) {
				t.Fatal("unsupported version evidence disappeared")
			}
			wantVersionCoverage := "completed"
			if !tc.fully {
				wantVersionCoverage = "incomplete"
			}
			wantCoverage := map[string]string{"fixture-inventory": "completed", "version-conditions": wantVersionCoverage, "advisory-applicability": "incomplete", "installed-inventory": "not-run", "integrity": "not-run"}
			if len(got.Coverage) != len(wantCoverage) {
				t.Fatal("coverage missing")
			}
			for _, c := range got.Coverage {
				if wantCoverage[c.Check] != c.Outcome || c.Reason == "" {
					t.Fatal("coverage falsely completed", c)
				}
				delete(wantCoverage, c.Check)
			}
			if len(wantCoverage) != 0 {
				t.Fatal("coverage duplicated")
			}
		})
	}
}

func TestEvaluateScenarioFailurePrivacy(t *testing.T) {
	for _, name := range []string{"malformed", "PRIVATE-SCENARIO-MARKER"} {
		got, err := EvaluateScenario(name)
		if err == nil || !reflect.DeepEqual(got, Result{}) || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("fatal error returned a report or disclosed input")
		}
	}
}

func TestSourceDigestsAndIndependentResults(t *testing.T) {
	got, err := EvaluateScenario("candidate")
	if err != nil {
		t.Fatal(err)
	}
	// Independent literal original bytes, not a production fixture/evaluator helper.
	lock := `{"lockfileVersion":3,"packages":{"":{},"node_modules/demo-package":{"name":"demo-package","version":"1.2.3"}}}`
	advisory := `{"id":"DEMO-OSV-001","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"demo-package"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]}`
	if got.Inputs.LockSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(lock))) || got.Inputs.AdvisorySHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(advisory))) || got.Inputs.AdvisoryID != "DEMO-OSV-001" {
		t.Fatal("input binding invented or hashed different bytes")
	}
	want := got
	got.Inventory = append([]Observation(nil), got.Inventory...)
	got.Inventory[0].Name = "mutated"
	got.Candidates[0].AffectedIndex = 9
	got.Evaluations[0].Support[0].RangeIndex = 9
	fresh, err := EvaluateScenario("candidate")
	if err != nil || fresh.Inventory[0].Name != "demo-package" || fresh.Candidates[0].AffectedIndex != 0 || fresh.Evaluations[0].Support[0].RangeIndex != 0 || fresh.Inputs != want.Inputs {
		t.Fatal("mutable state shared across runs")
	}
	again, err := EvaluateScenario("candidate")
	if err != nil || !reflect.DeepEqual(fresh, again) {
		t.Fatal("nondeterministic result")
	}
}
