package intel

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func structureInput(t *testing.T, body string) (OSVHeader, OSVAffectedProjection) {
	t.Helper()
	doc, err := ParseOSVRecord([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	header, err := ProjectOSVHeader(doc)
	if err != nil {
		t.Fatal(err)
	}
	affected, err := ProjectOSVAffected(doc)
	if err != nil {
		t.Fatal(err)
	}
	return header, affected
}

// Literal results catch incorrect gates, selected/dropped bounds and invented ordering rules.
func TestCheckOSVRangeStructureProfile(t *testing.T) {
	for _, tc := range []struct {
		name, raw          string
		state, events      OSVFieldState
		checked, satisfied bool
		problems           []OSVRangeStructureProblem
	}{
		{"introduced-only", `{"type":"SEMVER","events":[{"introduced":"0"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
		{"fixed", `{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
		{"last-affected", `{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"opaque"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
		{"limits", `{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"*"},{"limit":"*"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
		{"unsorted-first-fixed", `{"type":"SEMVER","events":[{"fixed":"8"},{"introduced":"3"},{"introduced":"1"},{"limit":"2"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
		{"nonalternating", `{"type":"ECOSYSTEM","events":[{"introduced":"z"},{"introduced":"a"},{"fixed":"m"},{"fixed":"b"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
		{"opaque-text", `{"type":"SEMVER","repo":false,"events":[{"introduced":" "},{"fixed":"not-a-version"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
		{"escaped-kind-and-type", `{"type":"\u0053EMVER","events":[{"\u0069ntroduced":"\u0030"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
		{"range-null", `null`, OSVFieldNull, OSVFieldUnavailable, false, false, []OSVRangeStructureProblem{{OSVRangeProblemRangeNotObject, -1, ""}}},
		{"range-number", `42`, OSVFieldInvalidType, OSVFieldUnavailable, false, false, []OSVRangeStructureProblem{{OSVRangeProblemRangeNotObject, -1, ""}}},
		{"type-absent", `{}`, OSVFieldValue, OSVFieldAbsent, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeUnusable, -1, "type"}}},
		{"type-null", `{"type":null,"events":[]}`, OSVFieldValue, OSVFieldValue, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeUnusable, -1, "type"}}},
		{"type-wrong", `{"type":false,"events":[]}`, OSVFieldValue, OSVFieldValue, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeUnusable, -1, "type"}}},
		{"empty-type", `{"type":"","events":[]}`, OSVFieldValue, OSVFieldValue, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeOutsideProfile, -1, "type"}}},
		{"type-space", `{"type":" SEMVER","events":[]}`, OSVFieldValue, OSVFieldValue, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeOutsideProfile, -1, "type"}}},
		{"type-case", `{"type":"semver","events":[]}`, OSVFieldValue, OSVFieldValue, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeOutsideProfile, -1, "type"}}},
		{"git", `{"type":"GIT","repo":"not-fetched","events":[{"introduced":"X"}]}`, OSVFieldValue, OSVFieldValue, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeOutsideProfile, -1, "type"}}},
		{"unknown-type", `{"type":"future","events":[]}`, OSVFieldValue, OSVFieldValue, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeOutsideProfile, -1, "type"}}},
		{"events-absent", `{"type":"SEMVER"}`, OSVFieldValue, OSVFieldAbsent, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventsUnusable, -1, "events"}}},
		{"events-null", `{"type":"SEMVER","events":null}`, OSVFieldValue, OSVFieldNull, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventsUnusable, -1, "events"}}},
		{"events-wrong-type", `{"type":"SEMVER","events":false}`, OSVFieldValue, OSVFieldInvalidType, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventsUnusable, -1, "events"}}},
		{"events-empty", `{"type":"SEMVER","events":[]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEmptyEvents, -1, "events"}, {OSVRangeProblemIntroducedNotRecorded, -1, "events"}}},
		{"event-null", `{"type":"SEMVER","events":[null]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventNotObject, 0, ""}}},
		{"event-wrong", `{"type":"SEMVER","events":[false,{"fixed":"1"}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventNotObject, 0, ""}}},
		{"event-empty-object", `{"type":"SEMVER","events":[{}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemNoKnownEventKind, 0, ""}, {OSVRangeProblemIntroducedNotRecorded, -1, "events"}}},
		{"only-fixed", `{"type":"SEMVER","events":[{"fixed":"2"}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemIntroducedNotRecorded, -1, "events"}}},
		{"unknown-only", `{"type":"SEMVER","events":[{"future":false}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemNoKnownEventKind, 0, ""}, {OSVRangeProblemUnknownEventField, 0, "future"}, {OSVRangeProblemIntroducedNotRecorded, -1, "events"}}},
		{"unknown-sibling", `{"type":"SEMVER","events":[{"introduced":"0","future":null}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemUnknownEventField, 0, "future"}}},
		{"unusable-introduced", `{"type":"SEMVER","events":[{"introduced":null}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventValueUnusable, 0, "introduced"}}},
		{"empty-introduced", `{"type":"SEMVER","events":[{"introduced":""}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventValueUnusable, 0, "introduced"}}},
		{"wrong-introduced", `{"type":"SEMVER","events":[{"introduced":42}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventValueUnusable, 0, "introduced"}}},
		{"multi-kind", `{"type":"SEMVER","events":[{"introduced":"0","fixed":"1"}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemMultipleKnownEventKinds, 0, ""}}},
		{"multi-unusable", `{"type":"SEMVER","events":[{"introduced":null,"fixed":false}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemMultipleKnownEventKinds, 0, ""}, {OSVRangeProblemEventValueUnusable, 0, "fixed"}, {OSVRangeProblemEventValueUnusable, 0, "introduced"}}},
		{"mixed-closing", `{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1"},{"last_affected":"2"}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemMixedFixedLastAffected, -1, "events"}}},
		{"missing-and-mixed", `{"type":"SEMVER","events":[{"fixed":"1"},{"last_affected":"2"}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemIntroducedNotRecorded, -1, "events"}, {OSVRangeProblemMixedFixedLastAffected, -1, "events"}}},
		{"unusable-mixed-presence", `{"type":"SEMVER","events":[{"introduced":null},{"fixed":false},{"last_affected":""}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventValueUnusable, 0, "introduced"}, {OSVRangeProblemEventValueUnusable, 1, "fixed"}, {OSVRangeProblemEventValueUnusable, 2, "last_affected"}, {OSVRangeProblemMixedFixedLastAffected, -1, "events"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"id":"TEST","modified":"opaque","affected":[{"package":null,"versions":false,"ranges":[` + tc.raw + `]}]}`
			header, affected := structureInput(t, body)
			before, snapshotErr := json.Marshal(affected)
			if snapshotErr != nil {
				t.Fatal(snapshotErr)
			}
			got, err := CheckOSVRangeStructure(header, affected)
			after, snapshotErr := json.Marshal(affected)
			if snapshotErr != nil || string(before) != string(after) {
				t.Fatal("source evidence changed, including event order")
			}
			want := OSVRangeStructureProjection{SourceSHA256: sha256.Sum256([]byte(body)), HeaderSchema: OSVHeaderSchemaV1Implicit, State: OSVFieldValue,
				Entries: []OSVAffectedRangeStructure{{Index: 0, State: OSVFieldValue, RangesState: OSVFieldValue,
					Entries: []OSVRangeStructure{{Index: 0, State: tc.state, EventsState: tc.events, Checked: tc.checked, Satisfied: tc.satisfied, Problems: tc.problems}},
				}},
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("want %#v, got %#v, %v", want, got, err)
			}
		})
	}
}

func assertStructureError(t *testing.T, header OSVHeader, affected OSVAffectedProjection, code string) {
	t.Helper()
	got, err := CheckOSVRangeStructure(header, affected)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != code || err.Error() != "intel: "+code || !reflect.DeepEqual(got, OSVRangeStructureProjection{}) {
		t.Fatalf("want zero/%s, got %#v, %v", code, got, err)
	}
}

// A missing profile gate would invent problems under uninspectable headers.
func TestCheckOSVRangeStructureHeaderGate(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		schema  OSVHeaderSchemaState
		checked bool
	}{
		{"", OSVHeaderSchemaV1Implicit, true}, {`"1.0.0"`, OSVHeaderSchemaV1Declared, true},
		{`null`, OSVHeaderSchemaUnknown, false}, {`false`, OSVHeaderSchemaUnknown, false},
		{`"future"`, OSVHeaderSchemaUnknown, false}, {`"2.0.0"`, OSVHeaderSchemaUnsupported, false}, {`"1.0.0+build"`, OSVHeaderSchemaUnknown, false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			body := `{"id":"TEST","modified":"opaque","affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0","fixed":"1"}]}]}]`
			if tc.raw != "" {
				body += `,"schema_version":` + tc.raw
			}
			header, affected := structureInput(t, body+`}`)
			got, err := CheckOSVRangeStructure(header, affected)
			if err != nil || got.HeaderSchema != tc.schema || len(got.Entries) != 1 || len(got.Entries[0].Entries) != 1 {
				t.Fatal("header/source hierarchy lost", err)
			}
			var problems []OSVRangeStructureProblem
			if tc.checked {
				problems = []OSVRangeStructureProblem{{OSVRangeProblemMultipleKnownEventKinds, 0, ""}}
			}
			want := OSVRangeStructure{Index: 0, State: OSVFieldValue, EventsState: OSVFieldValue, Checked: tc.checked, Problems: problems}
			if !reflect.DeepEqual(got.Entries[0].Entries[0], want) {
				t.Fatal("abstention interpreted as profile success/failure")
			}
		})
	}
}

// These intentionally forged projections test basic guards, not authentication.
func TestCheckOSVRangeStructureGuards(t *testing.T) {
	body := `{"id":"private-marker","modified":"opaque","affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`
	for _, name := range []string{"digest", "top-unavailable", "nil-affected", "affected-index", "nil-ranges", "range-index", "nil-events", "event-index", "nil-fields", "nonvalue-children", "null-ranges-children", "null-range-children", "null-events-children", "null-event-fields", "unavailable-ranges", "unavailable-events", "bad-member-state", "unknown-list-state", "late-event-index"} {
		t.Run(name, func(t *testing.T) {
			header, affected := structureInput(t, body)
			switch name {
			case "digest":
				header.SourceSHA256[0] ^= 255
			case "top-unavailable":
				affected.State = OSVFieldUnavailable
			case "nil-affected":
				affected.Entries = nil
			case "affected-index":
				affected.Entries[0].Index = 7
			case "nil-ranges":
				affected.Entries[0].Ranges.Entries = nil
			case "range-index":
				affected.Entries[0].Ranges.Entries[0].Index = 7
			case "nil-events":
				affected.Entries[0].Ranges.Entries[0].Events.Entries = nil
			case "event-index":
				affected.Entries[0].Ranges.Entries[0].Events.Entries[0].Index = 7
			case "nil-fields":
				affected.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields = nil
			case "nonvalue-children":
				affected.Entries[0].State = OSVFieldNull
			case "null-ranges-children":
				affected.Entries[0].Ranges.State = OSVFieldNull
			case "null-range-children":
				affected.Entries[0].Ranges.Entries[0].State = OSVFieldNull
			case "null-events-children":
				affected.Entries[0].Ranges.Entries[0].Events.State = OSVFieldNull
			case "null-event-fields":
				affected.Entries[0].Ranges.Entries[0].Events.Entries[0].State = OSVFieldNull
			case "unavailable-ranges":
				affected.Entries[0].Ranges.State = OSVFieldUnavailable
			case "unavailable-events":
				affected.Entries[0].Ranges.Entries[0].Events.State = OSVFieldUnavailable
			case "bad-member-state":
				affected.Entries[0].Ranges.Entries[0].Events.Entries[0].State = OSVFieldAbsent
			case "unknown-list-state":
				affected.State = OSVFieldState(255)
			case "late-event-index":
				affected.Entries[0].Ranges.Entries[0].Events.Entries[1].Index = 0
			}
			assertStructureError(t, header, affected, "invalid-shape")
		})
	}
}

func TestCheckOSVRangeStructureOwnership(t *testing.T) {
	field := strings.Repeat("x", 4096)
	rawField, err := json.Marshal(field)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"id":"TEST","modified":"opaque","affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0",` + string(rawField) + `:null}]}]}]}`
	header, affected := structureInput(t, body)
	snapshot := func(v any) []byte {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	before := snapshot(struct {
		H OSVHeader
		A OSVAffectedProjection
	}{header, affected})
	got, err := CheckOSVRangeStructure(header, affected)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(snapshot(struct {
		H OSVHeader
		A OSVAffectedProjection
	}{header, affected})) {
		t.Fatal("source changed")
	}
	if len(got.Entries) != 1 || len(got.Entries[0].Entries) != 1 {
		t.Fatal("output hierarchy lost")
	}
	if !reflect.DeepEqual(got.Entries[0].Entries[0].Problems, []OSVRangeStructureProblem{{OSVRangeProblemUnknownEventField, 0, field}}) {
		t.Fatal("exact field locator lost")
	}
	frozen := snapshot(got)
	affected.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields[1].Name = "changed"
	affected.Entries[0].Ranges.Entries[0].Type.Value = "GIT"
	affected.SourceSHA256[0] ^= 255
	header.SourceSHA256[0] ^= 255
	if string(frozen) != string(snapshot(got)) {
		t.Fatal("output aliases nested input")
	}
	before = snapshot(struct {
		H OSVHeader
		A OSVAffectedProjection
	}{header, affected})
	got.Entries[0].Entries[0].Problems[0].Field = "output-change"
	got.Entries[0].Index = 99
	if string(before) != string(snapshot(struct {
		H OSVHeader
		A OSVAffectedProjection
	}{header, affected})) {
		t.Fatal("output mutation changed input")
	}
}

func TestCheckOSVRangeStructureCumulativeUnits(t *testing.T) {
	events := make(map[string]any, 9998)
	for i := 0; i < 9998; i++ {
		events[fmt.Sprintf("f%05d", i)] = "opaque"
	}
	versions := make([]string, 20000)
	for i := range versions {
		versions[i] = "1"
	}
	entry := func() map[string]any {
		return map[string]any{"ranges": []any{map[string]any{"type": "SEMVER", "events": []any{events}}}}
	}
	first, second := entry(), entry()
	first["versions"] = versions
	body, err := json.Marshal(map[string]any{"id": "TEST", "modified": "opaque", "schema_version": "2.0.0", "affected": []any{first, second}})
	if err != nil {
		t.Fatal(err)
	}
	header, affected := structureInput(t, string(body))
	if len(affected.Entries[0].Versions.Entries) != 20000 {
		t.Fatal("independent version budget lost")
	}
	got, err := CheckOSVRangeStructure(header, affected)
	if err != nil || len(got.Entries) != 2 || len(got.Entries[1].Entries) != 1 || got.Entries[1].Entries[0].Checked {
		t.Fatal("exact budget/header abstention", err)
	}
	// Forged late extra unit: the old projector would already reject such raw source.
	fields := &affected.Entries[1].Ranges.Entries[0].Events.Entries[0].Fields
	*fields = append(*fields, OSVEventField{Name: "z", Value: OSVString{State: OSVFieldValue, Value: "opaque"}})
	assertStructureError(t, header, affected, "limit-exceeded")
}

func TestCheckOSVRangeStructureDerivedProblemBound(t *testing.T) {
	ranges := make([]any, 20000)
	for i := range ranges {
		ranges[i] = map[string]any{"type": "SEMVER", "events": []any{}}
	}
	body, err := json.Marshal(map[string]any{"id": "TEST", "modified": "opaque", "affected": []any{map[string]any{"ranges": ranges}}})
	if err != nil {
		t.Fatal(err)
	}
	header, affected := structureInput(t, string(body))
	got, err := CheckOSVRangeStructure(header, affected)
	if err != nil || len(got.Entries) != 1 || len(got.Entries[0].Entries) != 20000 {
		t.Fatal("exact range-unit bound", err)
	}
	count := 0
	for i, row := range got.Entries[0].Entries {
		want := OSVRangeStructure{Index: i, State: OSVFieldValue, EventsState: OSVFieldValue, Checked: true, Problems: []OSVRangeStructureProblem{{OSVRangeProblemEmptyEvents, -1, "events"}, {OSVRangeProblemIntroducedNotRecorded, -1, "events"}}}
		if !reflect.DeepEqual(row, want) {
			t.Fatal("empty event diagnostics/prefix loss", i)
		}
		count += len(row.Problems)
	}
	if count != 40000 {
		t.Fatal("derived problem bound", count)
	}
}

func TestCheckOSVRangeStructureHierarchy(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		state     OSVFieldState
		entries   []OSVAffectedRangeStructure
	}{
		{"absent", "", OSVFieldAbsent, nil}, {"null", `null`, OSVFieldNull, nil}, {"wrong-type", `false`, OSVFieldInvalidType, nil}, {"empty", `[]`, OSVFieldValue, []OSVAffectedRangeStructure{}},
		{"mixed", `[null,false,{}, {"ranges":null}, {"ranges":false}, {"ranges":[]}]`, OSVFieldValue, []OSVAffectedRangeStructure{
			{Index: 0, State: OSVFieldNull, RangesState: OSVFieldUnavailable}, {Index: 1, State: OSVFieldInvalidType, RangesState: OSVFieldUnavailable},
			{Index: 2, State: OSVFieldValue, RangesState: OSVFieldAbsent}, {Index: 3, State: OSVFieldValue, RangesState: OSVFieldNull},
			{Index: 4, State: OSVFieldValue, RangesState: OSVFieldInvalidType}, {Index: 5, State: OSVFieldValue, RangesState: OSVFieldValue, Entries: []OSVRangeStructure{}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"id":"TEST","modified":"opaque"`
			if tc.raw != "" {
				body += `,"affected":` + tc.raw
			}
			body += `}`
			header, affected := structureInput(t, body)
			got, err := CheckOSVRangeStructure(header, affected)
			want := OSVRangeStructureProjection{SourceSHA256: sha256.Sum256([]byte(body)), HeaderSchema: OSVHeaderSchemaV1Implicit, State: tc.state, Entries: tc.entries}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("hierarchy/absence fabricated", got, err)
			}
		})
	}
}

func TestCheckOSVRangeStructureSeparation(t *testing.T) {
	body := `{"id":"TEST","modified":"opaque","affected":[
 {"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2"}]},{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"2"}]}]},
 {"ranges":[{"type":"SEMVER","events":[{"":false,"future":null,"introduced":"0"},{"fixed":"7","introduced":null}]}]}]}`
	header, affected := structureInput(t, body)
	got, err := CheckOSVRangeStructure(header, affected)
	if err != nil || len(got.Entries) != 2 || len(got.Entries[0].Entries) != 2 || len(got.Entries[1].Entries) != 1 {
		t.Fatal("positions lost", err)
	}
	for i, row := range got.Entries[0].Entries {
		want := OSVRangeStructure{Index: i, State: OSVFieldValue, EventsState: OSVFieldValue, Checked: true, Satisfied: true, Problems: []OSVRangeStructureProblem{}}
		if !reflect.DeepEqual(row, want) {
			t.Fatal("cross-range closing mixture invented", row)
		}
	}
	want := OSVRangeStructure{Index: 0, State: OSVFieldValue, EventsState: OSVFieldValue, Checked: true, Problems: []OSVRangeStructureProblem{
		{OSVRangeProblemUnknownEventField, 0, ""}, {OSVRangeProblemUnknownEventField, 0, "future"}, {OSVRangeProblemMultipleKnownEventKinds, 1, ""}, {OSVRangeProblemEventValueUnusable, 1, "introduced"},
	}}
	if got.Entries[1].Index != 1 || !reflect.DeepEqual(got.Entries[1].Entries[0], want) {
		t.Fatal("complete ordered locators lost")
	}
}

func TestCheckOSVRangeStructureInputBounds(t *testing.T) {
	for _, axis := range []string{"affected", "ranges", "events", "fields"} {
		for _, mode := range []string{"v1", "unknown-header", "git-type"} {
			t.Run(axis+"/"+mode, func(t *testing.T) {
				typ := "SEMVER"
				if mode == "git-type" {
					typ = "GIT"
				}
				root := map[string]any{"id": "TEST", "modified": "opaque"}
				if mode == "unknown-header" {
					root["schema_version"] = "2.0.0"
				}
				switch axis {
				case "affected":
					root["affected"] = make([]any, 20000)
				case "ranges":
					root["affected"] = []any{map[string]any{"ranges": make([]any, 20000)}}
				case "events":
					root["affected"] = []any{map[string]any{"ranges": []any{map[string]any{"type": typ, "events": make([]any, 19999)}}}}
				case "fields":
					fields := make(map[string]any, 19998)
					for i := 0; i < 19998; i++ {
						fields[fmt.Sprintf("f%05d", i)] = "opaque"
					}
					root["affected"] = []any{map[string]any{"ranges": []any{map[string]any{"type": typ, "events": []any{fields}}}}}
				}
				body, err := json.Marshal(root)
				if err != nil {
					t.Fatal(err)
				}
				header, affected := structureInput(t, string(body))
				if _, err := CheckOSVRangeStructure(header, affected); err != nil {
					t.Fatal("exact source bound", err)
				}
				// Forged extra slot/field must fail before any returned prefix or abstention.
				switch axis {
				case "affected":
					affected.Entries = append(affected.Entries, OSVAffectedEntry{Index: 20000, State: OSVFieldNull})
				case "ranges":
					r := &affected.Entries[0].Ranges.Entries
					*r = append(*r, OSVRange{Index: 20000, State: OSVFieldNull})
				case "events":
					e := &affected.Entries[0].Ranges.Entries[0].Events.Entries
					*e = append(*e, OSVEvent{Index: 19999, State: OSVFieldNull})
				case "fields":
					f := &affected.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields
					*f = append(*f, OSVEventField{Name: "z", Value: OSVString{State: OSVFieldValue, Value: "opaque"}})
				}
				assertStructureError(t, header, affected, "limit-exceeded")
			})
		}
	}
}
