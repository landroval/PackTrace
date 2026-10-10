package intel

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestEvaluateOSVVersionConditionsReferences(t *testing.T) {
	// Rows are independently copied literal expectations from #15, not evaluator output.
	cases := []struct {
		id, fragment, query string
		want                OSVVersionOutcome
		full                bool
		support             []OSVVersionSupport
	}{
		{"R01", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}`, "0.9.9", OSVVersionNoMatch, true, nil},
		{"R02", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}`, "1.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R03", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}`, "2.0.0-rc.1", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R04", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}`, "2.0.0", OSVVersionNoMatch, true, nil},
		{"R05", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}`, "2.0.0+build", OSVVersionNoMatch, true, nil},
		{"R06", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"last_affected":"2.0.0"}]}]}`, "2.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R07", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"last_affected":"2.0.0"}]}]}`, "2.0.1-alpha", OSVVersionNoMatch, true, nil},
		{"R08", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "0.0.0-0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R09", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0.0.0"}]}]}`, "0.0.0-0", OSVVersionNoMatch, true, nil},
		{"R10", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "999.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R11", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0-alpha"},{"fixed":"1.0.0"}]}]}`, "1.0.0-beta", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R12", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"}]}]}`, "1.0.0-rc.1", OSVVersionNoMatch, true, nil},
		{"R13", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]}]}`, "2.0.0", OSVVersionNoMatch, true, nil},
		{"R14", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]}]}`, "2.0.0-rc.1", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R15", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"1.0.0"},{"limit":"2.0.0"}]}]}`, "1.5.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R16", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"1.0.0"},{"limit":"2.0.0"}]}]}`, "2.0.0", OSVVersionNoMatch, true, nil},
		{"R17", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"1.0.0"},{"limit":"*"}]}]}`, "9.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R18", `{"ranges":[{"type":"SEMVER","events":[{"fixed":"2.0.0"},{"introduced":"1.0.0"}]}]}`, "1.5.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R19", `{"ranges":[{"type":"SEMVER","events":[{"fixed":"0.5.0"},{"introduced":"1.0.0"}]}]}`, "1.5.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R20", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"introduced":"1.5.0"},{"fixed":"2.0.0"}]}]}`, "1.7.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R21", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"},{"fixed":"2.0.0"}]}]}`, "2.0.0", OSVVersionNoMatch, true, nil},
		{"R22", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"},{"introduced":"3.0.0"},{"fixed":"4.0.0"}]}]}`, "2.5.0", OSVVersionNoMatch, true, nil},
		{"R23", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"},{"introduced":"3.0.0"},{"fixed":"4.0.0"}]}]}`, "3.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"R24", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0+one"},{"fixed":"1.0.0+two"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"R25", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.0.0"}]}]}`, "1.1.0", OSVVersionIndeterminate, false, nil},
		{"R26", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"*suffix"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"R27", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"R28", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"A01", `{"versions":["1.2.3"]}`, "1.2.3", OSVVersionMatch, true, []OSVVersionSupport{{0, -1}}},
		{"A02", `{"versions":["1.2.3"]}`, "1.2.4", OSVVersionNoMatch, true, nil},
		{"A03", `{"versions":["1.2.3+one"]}`, "1.2.3+two", OSVVersionNoMatch, true, nil},
		{"A04", `{"versions":["1.2.3+one"]}`, "1.2.3+one", OSVVersionMatch, true, []OSVVersionSupport{{0, -1}}},
		{"A05", `{"versions":["1.2.3","1.2.3"]}`, "1.2.3", OSVVersionMatch, true, []OSVVersionSupport{{0, -1}, {1, -1}}},
		{"A06", `{"versions":["1.2.3",null]}`, "1.2.3", OSVVersionMatch, false, []OSVVersionSupport{{0, -1}}},
		{"A07", `{"versions":["1.2.3",null]}`, "1.2.4", OSVVersionIndeterminate, false, nil},
		{"A08", `{"versions":["1.2.3","v1.2.4"]}`, "1.2.4", OSVVersionIndeterminate, false, nil},
		{"A09", `{"versions":["1.2.3"],"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]}`, "2.5.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"A10", `{"versions":["1.2.3"],"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]}`, "1.5.0", OSVVersionNoMatch, true, nil},
		{"A11", `{"versions":[],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}`, "1.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 0}}},
		{"A12", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}`, "2.0.0", OSVVersionNoMatch, true, nil},
		{"A13", `{"versions":["1.2.3"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}`, "1.2.3", OSVVersionMatch, false, []OSVVersionSupport{{0, -1}}},
		{"A14", `{"versions":["1.2.3"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}`, "1.2.4", OSVVersionIndeterminate, false, nil},
		{"A15", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]},{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]}`, "2.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1, 1}}},
		{"A16", `{"versions":[]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"A17", `{}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"A18", `{"versions":null}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"A19", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]},{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]}`, "1.5.0", OSVVersionNoMatch, true, nil},
		{"A20", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]},{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}`, "2.5.0", OSVVersionMatch, false, []OSVVersionSupport{{-1, 0}}},
		{"U01", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U02", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "^1.0.0", OSVVersionIndeterminate, false, nil},
		{"U03", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "", OSVVersionIndeterminate, false, nil},
		{"U04", `{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U05", `{"ranges":[{"type":"GIT","events":[{"introduced":"0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U06", `{"ranges":[{"type":"OTHER","events":[{"introduced":"0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U07", `{"ranges":[{"type":"SEMVER","events":null}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U08", `{"ranges":[{"type":"SEMVER","events":[]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U09", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"not-a-version"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U10", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0","fixed":"2.0.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U11", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"},{"last_affected":"1.5.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U12", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"future_bound":"2.0.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U13", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},null]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U14", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"not-a-version"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U15", `null`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"U16", `null`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"E01", `{"ranges":[{"type":"SEMVER","events":[{"last_affected":"1.0.0"},{"introduced":"2.0.0"}]}]}`, "1.0.0", OSVVersionNoMatch, true, nil},
		{"E02", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.0.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"E03", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.0.0"},{"limit":"0.5.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
		{"E04", `{"versions":null,"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "1.0.0", OSVVersionMatch, false, []OSVVersionSupport{{-1, 0}}},
		{"E05", `{"ranges":[{"type":"SEMVER","events":[{"fixed":"2.0.0"},{"introduced":"1.0.0"}]}]}`, "2.0.0", OSVVersionNoMatch, true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			rawAffected := `[` + tc.fragment + `]`
			if tc.id == "U15" {
				rawAffected = `null`
			}
			schema := `"1.9.1"`
			if tc.id == "U01" {
				schema = `"2.0.0"`
			}
			body := `{"id":"PACKTRACE-SYNTHETIC","modified":"2026-10-02T00:00:00Z","schema_version":` + schema + `,"affected":` + rawAffected + `}`
			h, a := structureInput(t, body)
			before, _ := json.Marshal(a)
			var q SemVer
			if tc.id != "U03" {
				var err error
				q, err = ParseSemVer(tc.query)
				if (err != nil) != (tc.id == "U02") {
					t.Fatal("unexpected query qualification")
				}
			}
			got, err := EvaluateOSVVersionConditions(h, a, q)
			if err != nil || got.SourceSHA256 != h.SourceSHA256 || got.HeaderSchema != h.Schema || got.Query != q || got.State != a.State {
				t.Fatal("lost source or fatal reference result", err)
			}
			after, _ := json.Marshal(a)
			if string(before) != string(after) {
				t.Fatal("mutated source evidence")
			}
			if tc.id == "U15" {
				if got.Entries != nil || len(got.Problems) != 1 || got.Problems[0].Kind != "affected-uninspectable" {
					t.Fatal("root absence invented a negative")
				}
				return
			}
			if len(got.Entries) != 1 {
				t.Fatal("lost affected slot")
			}
			d := got.Entries[0]
			if d.Index != 0 || d.State != a.Entries[0].State || d.Outcome != tc.want || d.FullyEvaluated != tc.full {
				t.Fatalf("want %v/%v, got %v/%v", tc.want, tc.full, d.Outcome, d.FullyEvaluated)
			}
			if len(d.Support) != len(tc.support) {
				t.Fatal("wrong positive support count")
			}
			blocked := tc.id == "U01" || tc.id == "U02" || tc.id == "U03" || tc.id == "U16"
			if blocked && d.Support != nil || !blocked && d.Support == nil || d.Problems == nil {
				t.Fatal("wrong nil/empty decision representation")
			}
			for i := range tc.support {
				if d.Support[i] != tc.support[i] {
					t.Fatal("wrong support locator/order")
				}
			}
			if !tc.full && len(d.Problems)+len(got.Problems) == 0 {
				t.Fatal("hidden evaluation gap")
			}
			if tc.full && len(d.Problems)+len(got.Problems) != 0 {
				t.Fatal("invented evaluation gap")
			}
			if tc.id == "U01" && got.Problems[0].Kind != "header-unsupported" {
				t.Fatal("lost header gate")
			}
			if (tc.id == "U02" || tc.id == "U03") && got.Problems[0].Kind != "query-unqualified" {
				t.Fatal("lost query gate")
			}
		})
	}
}

func versionConditionError(t *testing.T, h OSVHeader, a OSVAffectedProjection, code string) {
	t.Helper()
	got, err := EvaluateOSVVersionConditions(h, a, semverTestValue(t, "1.0.0"))
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != code || err.Error() != "intel: "+code || !reflect.DeepEqual(got, OSVVersionConditions{}) {
		t.Fatal("expected whole-zero private error")
	}
}

func TestEvaluateOSVVersionConditionsGuards(t *testing.T) {
	for _, name := range []string{"digest", "schema-enum", "versions-nil", "versions-state", "member-state", "member-residue", "late-index", "field-state", "type-state", "field-order", "null-version-list", "version-count", "affected-count", "range-count", "text-limit", "blocked-text-limit"} {
		t.Run(name, func(t *testing.T) {
			h, a := structureInput(t, `{"id":"private-marker","modified":"opaque","affected":[{"versions":["1.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`)
			code := "invalid-shape"
			switch name {
			case "digest":
				h.SourceSHA256[0] ^= 1
			case "schema-enum":
				h.Schema = 255
			case "versions-nil":
				a.Entries[0].Versions.Entries = nil
			case "versions-state":
				a.Entries[0].Versions.State = OSVFieldUnavailable
			case "member-state":
				a.Entries[0].Versions.Entries[0].State = OSVFieldAbsent
			case "member-residue":
				a.Entries[0].Versions.Entries[0] = OSVString{OSVFieldNull, "private-marker"}
			case "late-index":
				a.Entries[0].Ranges.Entries[0].Events.Entries[0].Index = 4
			case "field-state":
				a.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields[0].Value.State = OSVFieldAbsent
			case "type-state":
				a.Entries[0].Ranges.Entries[0].Type.State = OSVFieldUnavailable
			case "field-order":
				f := a.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields[0]
				a.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields = []OSVEventField{f, f}
			case "null-version-list":
				a.Entries[0].Versions.State = OSVFieldNull
			case "version-count":
				a.Entries[0].Versions.Entries = make([]OSVString, 20_001)
				code = "limit-exceeded"
			case "affected-count":
				a.Entries = make([]OSVAffectedEntry, 20_001)
				code = "limit-exceeded"
			case "range-count":
				a.Entries[0].Ranges.Entries = make([]OSVRange, 20_001)
				code = "limit-exceeded"
			case "text-limit", "blocked-text-limit":
				a.Entries[0].Versions.Entries = []OSVString{{OSVFieldValue, "1.0.0"}, {OSVFieldValue, strings.Repeat("x", 4<<20)}}
				code = "limit-exceeded"
				if name == "blocked-text-limit" {
					h.Schema = OSVHeaderSchemaUnknown
				}
			}
			versionConditionError(t, h, a, code)
		})
	}
}

func TestEvaluateOSVVersionConditionsLimits(t *testing.T) {
	t.Run("text-guard-boundary", func(t *testing.T) {
		// Fabricated layouts exercise the guard allowance, not authenticated source evidence.
		h, a := structureInput(t, `{"id":"TEST","modified":"opaque","affected":[{"versions":[]}]}`)
		a.Entries[0].Versions.Entries = []OSVString{{OSVFieldValue, strings.Repeat("x", (4<<20)-1)}, {OSVFieldValue, "x"}}
		if err := validateOSVVersionConditionsInput(h, a); err != nil {
			t.Fatal("inclusive text guard rejected", err)
		}
		a.Entries[0].Versions.Entries[1].Value = "xx"
		versionConditionError(t, h, a, "limit-exceeded")
	})
	t.Run("per-text-limit-retains-positive", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{"id": "TEST", "modified": "opaque", "affected": []any{map[string]any{"versions": []string{"1.0.0", strings.Repeat("x", (1<<20)+1)}}}})
		h, a := structureInput(t, string(raw))
		got, err := EvaluateOSVVersionConditions(h, a, semverTestValue(t, "1.0.0"))
		if err != nil || got.Entries[0].Outcome != OSVVersionMatch || got.Entries[0].FullyEvaluated || !reflect.DeepEqual(got.Entries[0].Support, []OSVVersionSupport{{0, -1}}) || got.Entries[0].Problems[0] != (OSVVersionProblem{"version-limit", 1, -1, -1}) {
			t.Fatal("per-text limit erased support or falsely completed")
		}
	})
	t.Run("bound-limit", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{"id": "TEST", "modified": "opaque", "affected": []any{map[string]any{"ranges": []any{map[string]any{"type": "SEMVER", "events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": strings.Repeat("x", (1<<20)+1)}}}}}}})
		h, a := structureInput(t, string(raw))
		got, err := EvaluateOSVVersionConditions(h, a, semverTestValue(t, "1.0.0"))
		if err != nil || got.Entries[0].Outcome != OSVVersionIndeterminate || got.Entries[0].Problems[0] != (OSVVersionProblem{"bound-limit", -1, 0, 1}) {
			t.Fatal("bound limit hidden")
		}
	})
	for _, name := range []string{"affected", "versions", "range-units"} {
		t.Run(name+"-guard-boundary", func(t *testing.T) {
			h, a := structureInput(t, `{"id":"TEST","modified":"opaque","affected":[{"versions":[],"ranges":[]}]}`)
			switch name {
			case "affected":
				a.Entries = make([]OSVAffectedEntry, 20_000)
				for i := range a.Entries {
					a.Entries[i] = OSVAffectedEntry{Index: i, State: OSVFieldNull}
				}
			case "versions":
				a.Entries[0].Versions.Entries = make([]OSVString, 20_000)
				for i := range a.Entries[0].Versions.Entries {
					a.Entries[0].Versions.Entries[i] = OSVString{State: OSVFieldNull}
				}
			case "range-units":
				a.Entries[0].Ranges.Entries = make([]OSVRange, 20_000)
				for i := range a.Entries[0].Ranges.Entries {
					a.Entries[0].Ranges.Entries[i] = OSVRange{Index: i, State: OSVFieldNull}
				}
			}
			if err := validateOSVVersionConditionsInput(h, a); err != nil {
				t.Fatal("inclusive structural guard rejected", err)
			}
		})
	}
}

func TestEvaluateOSVVersionConditionsPrivacyOwnership(t *testing.T) {
	h, a := structureInput(t, `{"id":"TEST","modified":"opaque","affected":[{"versions":["1.0.0","1.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"private-marker-field":"private-marker-value"}]}]}]}`)
	before, _ := json.Marshal(a)
	got, err := EvaluateOSVVersionConditions(h, a, semverTestValue(t, "1.0.0"))
	if err != nil || got.Entries[0].Outcome != OSVVersionMatch || got.Entries[0].FullyEvaluated {
		t.Fatal("wrong positive with unsupported range")
	}
	encoded, _ := json.Marshal(got.Entries[0].Problems)
	if strings.Contains(string(encoded), "private-marker") || !reflect.DeepEqual(got.Entries[0].Problems, []OSVVersionProblem{{"range-structure", -1, 0, -1}}) {
		t.Fatal("uncontrolled diagnostic or wrong locator")
	}
	got.Entries[0].Support[0].VersionIndex = 7
	got.Entries[0].Problems[0].Kind = "mutated-output"
	after, _ := json.Marshal(a)
	fresh, err := EvaluateOSVVersionConditions(h, a, semverTestValue(t, "1.0.0"))
	if err != nil || string(before) != string(after) || fresh.Entries[0].Support[0].VersionIndex != 0 || fresh.Entries[0].Problems[0].Kind != "range-structure" {
		t.Fatal("shared mutable output or source change")
	}
	// Tie diagnostics refer to all original events, not derived sort positions.
	h, a = structureInput(t, `{"id":"TEST","modified":"opaque","affected":[{"ranges":[{"type":"SEMVER","events":[{"fixed":"2.0.0"},{"introduced":"1.0.0"},{"introduced":"2.0.0"}]}]}]}`)
	tie, err := EvaluateOSVVersionConditions(h, a, semverTestValue(t, "1.5.0"))
	if err != nil || !reflect.DeepEqual(tie.Entries[0].Problems, []OSVVersionProblem{{"precedence-tie", -1, 0, 0}, {"precedence-tie", -1, 0, 2}, {"no-usable-condition", -1, -1, -1}}) {
		t.Fatal("tie source locators lost")
	}
}

func TestEvaluateOSVVersionConditionsMultipleEntries(t *testing.T) {
	h, a := structureInput(t, `{"id":"TEST","modified":"opaque","affected":[{"versions":["1.0.0"]},{"versions":["2.0.0"]},null,{}]}`)
	got, err := EvaluateOSVVersionConditions(h, a, semverTestValue(t, "1.0.0"))
	want := []OSVVersionEntryDecision{
		{Index: 0, State: OSVFieldValue, Outcome: OSVVersionMatch, FullyEvaluated: true, Support: []OSVVersionSupport{{0, -1}}, Problems: []OSVVersionProblem{}},
		{Index: 1, State: OSVFieldValue, Outcome: OSVVersionNoMatch, FullyEvaluated: true, Support: []OSVVersionSupport{}, Problems: []OSVVersionProblem{}},
		{Index: 2, State: OSVFieldNull, Problems: []OSVVersionProblem{{"affected-uninspectable", -1, -1, -1}}},
		{Index: 3, State: OSVFieldValue, Support: []OSVVersionSupport{}, Problems: []OSVVersionProblem{{"no-usable-condition", -1, -1, -1}}},
	}
	if err != nil || !reflect.DeepEqual(got.Entries, want) {
		t.Fatal("affected slots collapsed or borrowed another slot's decision")
	}
}

func TestEvaluateOSVVersionConditionsRootStates(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		state     OSVFieldState
	}{
		{"absent", "", OSVFieldAbsent}, {"null", "null", OSVFieldNull},
		{"wrong-type", "false", OSVFieldInvalidType}, {"empty", "[]", OSVFieldValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"id":"TEST","modified":"opaque"`
			if tc.raw != "" {
				body += `,"affected":` + tc.raw
			}
			h, a := structureInput(t, body+`}`)
			got, err := EvaluateOSVVersionConditions(h, a, semverTestValue(t, "1.0.0"))
			if err != nil || got.State != tc.state || len(got.Entries) != 0 || got.Problems == nil {
				t.Fatal("root state lost")
			}
			if tc.state == OSVFieldValue {
				if got.Entries == nil || len(got.Problems) != 0 {
					t.Fatal("inspectable empty list confused with unavailable scope")
				}
			} else if got.Entries != nil || !reflect.DeepEqual(got.Problems, []OSVVersionProblem{{"affected-uninspectable", -1, -1, -1}}) {
				t.Fatal("unavailable root invented a negative or lost its gap")
			}
		})
	}
}
