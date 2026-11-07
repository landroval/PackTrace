package intel

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEvaluateOSVNPMVersionConditions(t *testing.T) {
	cases := []struct {
		name, conditions, query string
		want                    OSVVersionOutcome
		full                    bool
	}{
		{"introduced", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]`, "1.0.0", OSVVersionMatch, true},
		{"below", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]`, "1.0.0-rc.1", OSVVersionNoMatch, true},
		{"prerelease", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]`, "2.0.0-rc.1", OSVVersionMatch, true},
		{"fixed", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]`, "2.0.0", OSVVersionNoMatch, true},
		{"zero", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]`, "0.0.0-0", OSVVersionMatch, true},
		{"last-inclusive", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"2.0.0"}]}]`, "2.0.0", OSVVersionMatch, true},
		{"last-above", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"2.0.0"}]}]`, "2.0.1-0", OSVVersionNoMatch, true},
		{"limit", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"limit":"2.0.0"}]}]`, "2.0.0", OSVVersionNoMatch, true},
		{"limit-star", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"limit":"*"}]}]`, "99.0.0", OSVVersionMatch, true},
		{"loose-bound", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"v1.0.0"}]}]`, "1.0.0", OSVVersionIndeterminate, false},
		{"short-bound", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"}]}]`, "1.0.0", OSVVersionIndeterminate, false},
		{"constraint", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"^1.0.0"}]}]`, "1.0.0", OSVVersionIndeterminate, false},
		{"order-shared", `"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"2.0.0"},{"introduced":"1.0.0"}]}]`, "1.0.0", OSVVersionMatch, true},
		{"precedence-tie", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0+a"},{"fixed":"1.0.0+b"}]}]`, "1.0.0", OSVVersionIndeterminate, false},
		{"partial-positive", `"versions":["1.0.0"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"v1.0.0"}]}]`, "1.0.0", OSVVersionMatch, false},
		{"partial-negative", `"versions":["1.0.0"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"v1.0.0"}]}]`, "1.0.1", OSVVersionIndeterminate, false},
		{"partial-range-positive", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]},{"type":"GIT","events":[{"introduced":"0"}]}]`, "1.0.0", OSVVersionMatch, false},
		{"loose-version", `"versions":["v1.0.0"]`, "1.0.0", OSVVersionIndeterminate, false},
		{"mixed-types", `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]},{"type":"ECOSYSTEM","events":[{"introduced":"2.0.0"}]}]`, "1.5.0", OSVVersionNoMatch, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, a := structureInput(t, `{"id":"SYNTHETIC","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"test"},`+tc.conditions+`}]}`)
			before, _ := json.Marshal(a)
			q := semverTestValue(t, tc.query)
			legacyBefore, err := EvaluateOSVVersionConditions(h, a, q)
			if err != nil {
				t.Fatal(err)
			}
			got, err := EvaluateOSVNPMVersionConditions(h, a, q)
			if err != nil || len(got.Entries) != 1 {
				t.Fatal(got, err)
			}
			d := got.Entries[0]
			if d.Outcome != tc.want || d.FullyEvaluated != tc.full || (len(d.Support) != 0) != (tc.want == OSVVersionMatch) {
				t.Fatalf("got %+v", d)
			}
			after, _ := json.Marshal(a)
			legacyAfter, err := EvaluateOSVVersionConditions(h, a, q)
			if err != nil || !reflect.DeepEqual(legacyBefore, legacyAfter) || string(before) != string(after) || got.SourceSHA256 != h.SourceSHA256 {
				t.Fatal("evidence or legacy semantics changed")
			}
		})
	}
}

func TestEvaluateOSVNPMVersionConditionsPerEntryAndGuards(t *testing.T) {
	h, a := structureInput(t, `{"id":"SYNTHETIC","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"test"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},{"package":{"ecosystem":"PyPI","name":"test"},"versions":["1.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]},{"versions":["1.0.0"]}]}`)
	got, err := EvaluateOSVNPMVersionConditions(h, a, semverTestValue(t, "1.0.0"))
	if err != nil || len(got.Entries) != 3 {
		t.Fatal(got, err)
	}
	if got.Entries[0].Outcome != OSVVersionMatch {
		t.Fatal(got)
	}
	for _, d := range got.Entries[1:] {
		if d.Outcome != OSVVersionIndeterminate || d.FullyEvaluated || len(d.Support) != 0 {
			t.Fatal(d)
		}
	}
	got, err = EvaluateOSVNPMVersionConditions(h, a, SemVer{})
	if err != nil || len(got.Problems) == 0 || got.Entries[0].Outcome != OSVVersionIndeterminate {
		t.Fatal(got, err)
	}
	h.SourceSHA256[0] ^= 1
	if _, err := EvaluateOSVNPMVersionConditions(h, a, SemVer{}); err == nil {
		t.Fatal("accepted cross-document projections")
	}
}
