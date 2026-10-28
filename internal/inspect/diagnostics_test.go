package inspect

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"packtrace/internal/demo"
)

const diagnosticLock = `{"lockfileVersion":3,"packages":{"node_modules/example":{"name":"example","version":"1.2.3"}}}`
const diagnosticDerivedLock = `{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.2.3"}}}`
const diagnosticBunLock = `{"lockfileVersion":1,"workspaces":{},"packages":{"example":["example@1.2.3","",{},""]}}`
const diagnosticAffected = `{"package":{"ecosystem":"npm","name":"example"},"versions":["1.2.3"]}`
const diagnosticHeader = `{"id":"OWNED-PRIVATE-ID","modified":"2026-01-01T00:00:00Z","schema_version":"2.0.0"`
const diagnosticAdvisory = diagnosticHeader + `,"affected":[` + diagnosticAffected + `]}`

func TestGlobalDiagnosticsAcrossReaders(t *testing.T) {
	for _, tc := range []struct {
		name, lock, profile string
		bun, batch          bool
	}{
		{"npm", diagnosticLock, "explicit-only", false, false},
		{"npm-profile", diagnosticDerivedLock, "npm-lock-v2-v3", false, false},
		{"bun", diagnosticBunLock, "", true, false},
		{"batch", diagnosticLock, "explicit-only", false, true},
		{"batch-profile", diagnosticDerivedLock, "npm-lock-v2-v3", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r Result
			var err error
			var render func(string) ([]byte, error)
			if tc.batch {
				input := `{"lockfile":` + tc.lock + `,"advisories":[` + diagnosticAdvisory + `]}`
				b, err := ReadBatchProfile(strings.NewReader(input), tc.profile)
				if err != nil {
					t.Fatal(err)
				}
				if len(b.Advisories) != 1 || b.Advisories[0].State != "usable" || b.Advisories[0].Report == nil || b.CandidateCount != 0 || b.ExitCode != 3 {
					t.Fatal("batch lost its partial report", b)
				}
				r = *b.Advisories[0].Report
				render = func(format string) ([]byte, error) { return RenderBatch(b, format) }
			} else {
				if tc.bun {
					input, marshalErr := json.Marshal(map[string]any{"lockfile_text": tc.lock, "advisory": json.RawMessage(diagnosticAdvisory)})
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					r, err = ReadBun(strings.NewReader(string(input)))
				} else {
					r, err = ReadProfile(strings.NewReader(packet(tc.lock, diagnosticAdvisory)), tc.profile)
				}
				if err != nil {
					t.Fatal(err)
				}
				render = func(format string) ([]byte, error) { return Render(r, format) }
			}
			if len(r.Evaluations) != 1 || len(r.Candidates) != 0 || len(r.Findings) != 0 || r.ExitCode != 3 {
				t.Fatal("conservative result changed", r)
			}
			e := r.Evaluations[0]
			want := []demo.Problem{{Kind: "header-unsupported", VersionIndex: -1, RangeIndex: -1, EventIndex: -1}}
			if e.VersionOutcome != "indeterminate" || e.VersionFullyEvaluated || !reflect.DeepEqual(e.Problems, want) {
				t.Errorf("global diagnostic lost or altered: %+v", e)
			}
			for _, format := range []string{"terminal", "json"} {
				out, err := render(format)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(out), "header-unsupported") || strings.Contains(string(out), "OWNED-PRIVATE-ID") || strings.Contains(string(out), "example") {
					t.Errorf("%s lost reason or leaked metadata: %s", format, out)
				}
			}
		})
	}
}

func TestDiagnosticLocatorsAndGating(t *testing.T) {
	global := demo.Problem{Kind: "header-unsupported", VersionIndex: -1, RangeIndex: -1, EventIndex: -1}
	for _, tc := range []struct {
		name, lock, advisory, outcome string
		problems                      [][]demo.Problem
		support                       []demo.Support
		candidates                    int
	}{
		{"multiple-affected", diagnosticLock, diagnosticHeader + `,"affected":[` + diagnosticAffected + `,` + diagnosticAffected + `]}`, "indeterminate", [][]demo.Problem{{global}, {global}}, nil, 0},
		{"global-before-local", diagnosticLock, diagnosticHeader + `,"affected":[null]}`, "indeterminate", [][]demo.Problem{{global, {Kind: "affected-uninspectable", VersionIndex: -1, RangeIndex: -1, EventIndex: -1}}}, nil, 0},
		{"local-problem-with-support", diagnosticLock, `{"id":"OWNED-PRIVATE-ID","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example"},"versions":["1.2.3","not-semver"]}]}`, "match", [][]demo.Problem{{{Kind: "version-outside-profile", VersionIndex: 1, RangeIndex: -1, EventIndex: -1}}}, []demo.Support{{VersionIndex: 0, RangeIndex: -1}}, 1},
		{"unqualified-query", strings.Replace(diagnosticLock, `"version":"1.2.3"`, `"version":"not-semver"`, 1), diagnosticAdvisory, "not-evaluated", [][]demo.Problem{{}}, nil, 0},
		{"absent-affected", diagnosticLock, diagnosticHeader + `}`, "", nil, nil, 0},
		{"empty-affected", diagnosticLock, diagnosticHeader + `,"affected":[]}`, "", nil, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Read(strings.NewReader(packet(tc.lock, tc.advisory)))
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Evaluations) != len(tc.problems) || len(r.Candidates) != tc.candidates || len(r.Findings) != 0 || r.ExitCode != 3 {
				t.Fatal("evaluation scope or outcome changed", r)
			}
			for i, e := range r.Evaluations {
				if e.PackageIndex != 0 || e.AffectedIndex != i || e.VersionOutcome != tc.outcome || e.VersionFullyEvaluated || !reflect.DeepEqual(e.Problems, tc.problems[i]) {
					t.Errorf("evaluation %d lost diagnostic locators/gating: %+v", i, e)
				}
				if len(tc.support) == 0 {
					if len(e.Support) != 0 {
						t.Errorf("evaluation %d invented support: %+v", i, e.Support)
					}
				} else if !reflect.DeepEqual(e.Support, tc.support) {
					t.Errorf("evaluation %d lost support: %+v", i, e.Support)
				}
			}
			for _, coverage := range r.Coverage {
				if coverage.Check == "version-conditions" && coverage.Outcome == "completed" {
					t.Fatal("incomplete conditions became completed")
				}
			}
		})
	}
}
