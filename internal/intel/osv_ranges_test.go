package intel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestProjectOSVRangesParentAndListStates(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		state OSVFieldState
	}{
		{`null`, OSVFieldUnavailable}, {`false`, OSVFieldUnavailable}, {`[]`, OSVFieldUnavailable},
		{`{}`, OSVFieldAbsent}, {`{"package":{"ranges":[{}]},"events":[{}]}`, OSVFieldAbsent},
		{`{"ranges":null}`, OSVFieldNull}, {`{"ranges":false}`, OSVFieldInvalidType},
		{`{"ranges":42}`, OSVFieldInvalidType}, {`{"ranges":"x"}`, OSVFieldInvalidType},
		{`{"ranges":{}}`, OSVFieldInvalidType}, {`{"package":null,"versions":false,"ranges":[]}`, OSVFieldValue},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			doc := affectedDocument(t, "["+tc.raw+"]")
			got, err := ProjectOSVAffected(doc)
			if err != nil || got.SourceSHA256 != doc.SHA256 || len(got.Entries) != 1 || got.Entries[0].Index != 0 {
				t.Fatal("affected evidence lost", err)
			}
			want := OSVRanges{State: tc.state}
			if tc.state == OSVFieldValue {
				want.Entries = []OSVRange{}
			}
			if !reflect.DeepEqual(got.Entries[0].Ranges, want) {
				t.Fatal("range list state/nil/empty collapsed", got.Entries[0].Ranges)
			}
		})
	}
}

func TestProjectOSVRangesElementStates(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		state OSVFieldState
	}{
		{`null`, OSVFieldNull}, {`false`, OSVFieldInvalidType}, {`1e400`, OSVFieldInvalidType},
		{`"range"`, OSVFieldInvalidType}, {`[]`, OSVFieldInvalidType}, {`{}`, OSVFieldValue},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := ProjectOSVAffected(affectedDocument(t, `[{"ranges":[`+tc.raw+`]}]`))
			if err != nil || len(got.Entries) != 1 || len(got.Entries[0].Ranges.Entries) != 1 {
				t.Fatal("range slot lost", err)
			}
			want := OSVRange{State: tc.state}
			if tc.state == OSVFieldValue {
				want.Type, want.Repo = OSVString{State: OSVFieldAbsent}, OSVString{State: OSVFieldAbsent}
				want.Events = OSVEvents{State: OSVFieldAbsent}
			}
			if !reflect.DeepEqual(got.Entries[0].Ranges.Entries[0], want) {
				t.Fatal("range children incorrectly available/absent")
			}
		})
	}
}

func TestProjectOSVRangesStringStates(t *testing.T) {
	for _, key := range []string{"type", "repo"} {
		for _, tc := range []struct {
			raw   string
			state OSVFieldState
			value string
		}{
			{"", OSVFieldAbsent, ""}, {`null`, OSVFieldNull, ""}, {`false`, OSVFieldInvalidType, ""},
			{`42`, OSVFieldInvalidType, ""}, {`[]`, OSVFieldInvalidType, ""}, {`{}`, OSVFieldInvalidType, ""},
			{`""`, OSVFieldValue, ""}, {`" Exact\u0020text "`, OSVFieldValue, " Exact text "},
		} {
			t.Run(key+"/"+tc.raw, func(t *testing.T) {
				raw := `{"events":[{}]`
				if tc.raw != "" {
					raw += fmt.Sprintf(`,%q:%s`, key, tc.raw)
				}
				got, err := ProjectOSVAffected(affectedDocument(t, `[{"ranges":[`+raw+`}]}]`))
				if err != nil || len(got.Entries) != 1 || len(got.Entries[0].Ranges.Entries) != 1 {
					t.Fatal("range lost", err)
				}
				want := OSVRange{State: OSVFieldValue, Type: OSVString{State: OSVFieldAbsent}, Repo: OSVString{State: OSVFieldAbsent}, Events: OSVEvents{State: OSVFieldValue, Entries: []OSVEvent{{State: OSVFieldValue, Fields: []OSVEventField{}}}}}
				field := OSVString{State: tc.state, Value: tc.value}
				if key == "type" {
					want.Type = field
				} else {
					want.Repo = field
				}
				if !reflect.DeepEqual(got.Entries[0].Ranges.Entries[0], want) {
					t.Fatal("string altered or event gated on string usability")
				}
			})
		}
	}
}

func TestProjectOSVRangesEventListStates(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		state OSVFieldState
	}{
		{"", OSVFieldAbsent}, {`null`, OSVFieldNull}, {`false`, OSVFieldInvalidType},
		{`42`, OSVFieldInvalidType}, {`"events"`, OSVFieldInvalidType}, {`{}`, OSVFieldInvalidType}, {`[]`, OSVFieldValue},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			raw := `{"type":false,"repo":null`
			if tc.raw != "" {
				raw += `,"events":` + tc.raw
			}
			got, err := ProjectOSVAffected(affectedDocument(t, `[{"ranges":[`+raw+`}]}]`))
			if err != nil || len(got.Entries) != 1 || len(got.Entries[0].Ranges.Entries) != 1 {
				t.Fatal("range lost", err)
			}
			want := OSVEvents{State: tc.state}
			if tc.state == OSVFieldValue {
				want.Entries = []OSVEvent{}
			}
			if !reflect.DeepEqual(got.Entries[0].Ranges.Entries[0].Events, want) {
				t.Fatal("event list state/nil/empty collapsed")
			}
		})
	}
}

func TestProjectOSVRangesEventElementStates(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		state OSVFieldState
	}{
		{`null`, OSVFieldNull}, {`false`, OSVFieldInvalidType}, {`1e400`, OSVFieldInvalidType},
		{`"event"`, OSVFieldInvalidType}, {`[]`, OSVFieldInvalidType}, {`{}`, OSVFieldValue},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := ProjectOSVAffected(affectedDocument(t, `[{"ranges":[{"events":[`+tc.raw+`]}]}]`))
			if err != nil || len(got.Entries) != 1 || len(got.Entries[0].Ranges.Entries) != 1 {
				t.Fatal("range lost", err)
			}
			events := got.Entries[0].Ranges.Entries[0].Events
			want := OSVEvent{State: tc.state}
			if tc.state == OSVFieldValue {
				want.Fields = []OSVEventField{}
			}
			if events.State != OSVFieldValue || !reflect.DeepEqual(events.Entries, []OSVEvent{want}) {
				t.Fatal("event state/empty object lost")
			}
		})
	}
}

func TestProjectOSVRangesEvidenceAndOwnership(t *testing.T) {
	const event = `{"last_affected":"2", "introduced":"0", "fixed":"", "limit":null, "future":false, "array":[], "object":{}, "num":1e400, "":" ", "\u0061":" Exact\u0020text "}`
	const rng = `{"type":" UNKNOWN ","repo":" https://repo.invalid/ ","events":[` + event + `,` + event + `],"database_specific":{"untouched":true}}`
	doc := affectedDocument(t, `[{"package":null,"versions":false,"ranges":[`+rng+`,`+rng+`]},{"ranges":[`+rng+`]}]`)
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProjectOSVAffected(doc)
	if err != nil || got.SourceSHA256 != doc.SHA256 || len(got.Entries) != 2 {
		t.Fatal("source/entries lost", err)
	}
	fields := []OSVEventField{
		{Name: "", Value: OSVString{State: OSVFieldValue, Value: " "}},
		{Name: "a", Value: OSVString{State: OSVFieldValue, Value: " Exact text "}},
		{Name: "array", Value: OSVString{State: OSVFieldInvalidType}},
		{Name: "fixed", Value: OSVString{State: OSVFieldValue}},
		{Name: "future", Value: OSVString{State: OSVFieldInvalidType}},
		{Name: "introduced", Value: OSVString{State: OSVFieldValue, Value: "0"}},
		{Name: "last_affected", Value: OSVString{State: OSVFieldValue, Value: "2"}},
		{Name: "limit", Value: OSVString{State: OSVFieldNull}},
		{Name: "num", Value: OSVString{State: OSVFieldInvalidType}},
		{Name: "object", Value: OSVString{State: OSVFieldInvalidType}},
	}
	for i, entry := range got.Entries {
		count := 2 - i
		if entry.Index != i || entry.Ranges.State != OSVFieldValue || len(entry.Ranges.Entries) != count {
			t.Fatal("range duplicates/order lost")
		}
		for j, r := range entry.Ranges.Entries {
			want := OSVRange{Index: j, State: OSVFieldValue, Type: OSVString{State: OSVFieldValue, Value: " UNKNOWN "}, Repo: OSVString{State: OSVFieldValue, Value: " https://repo.invalid/ "}, Events: OSVEvents{State: OSVFieldValue, Entries: []OSVEvent{{State: OSVFieldValue, Fields: fields}, {Index: 1, State: OSVFieldValue, Fields: fields}}}}
			if !reflect.DeepEqual(r, want) {
				t.Fatal("unknown/multiple event fields interpreted, lost, unsorted or merged")
			}
		}
	}
	if got.Entries[0].PackageState != OSVFieldNull || got.Entries[0].Versions.State != OSVFieldInvalidType {
		t.Fatal("independent evidence changed")
	}
	after, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("raw source changed")
	}
	snapshot, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for i := range doc.Fields["affected"] {
		doc.Fields["affected"][i] = 'X'
	}
	doc.Fields["affected"] = json.RawMessage(`[]`)
	doc.SHA256[0] ^= 255
	after, err = json.Marshal(got)
	if err != nil || !bytes.Equal(snapshot, after) {
		t.Fatal("nested output aliases source")
	}
	sourceBefore, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields[0] = OSVEventField{Name: "changed"}
	for i, entry := range got.Entries {
		for j, r := range entry.Ranges.Entries {
			for k, e := range r.Events.Entries {
				if i == 0 && j == 0 && k == 0 {
					continue
				}
				if !reflect.DeepEqual(e.Fields, fields) {
					t.Fatal("duplicates share mutable field storage")
				}
			}
		}
	}
	sourceAfter, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(sourceBefore, sourceAfter) {
		t.Fatal("output mutation reached input")
	}
}

func TestProjectOSVRangesSourceOrder(t *testing.T) {
	t.Run("ranges", func(t *testing.T) {
		got, err := ProjectOSVAffected(affectedDocument(t, `[{"ranges":[{"type":"Z"},{"type":"A"},{"type":"Y"}]}]`))
		if err != nil || len(got.Entries) != 1 || len(got.Entries[0].Ranges.Entries) != 3 {
			t.Fatal("ranges lost", err)
		}
		for i, value := range []string{"Z", "A", "Y"} {
			r := got.Entries[0].Ranges.Entries[i]
			if r.Index != i || r.Type != (OSVString{State: OSVFieldValue, Value: value}) {
				t.Fatal("range order normalized", i)
			}
		}
	})
	t.Run("events", func(t *testing.T) {
		got, err := ProjectOSVAffected(affectedDocument(t, `[{"ranges":[{"events":[{"fixed":"2"},{"introduced":"0"},{"limit":"1"}]}]}]`))
		if err != nil || len(got.Entries) != 1 || len(got.Entries[0].Ranges.Entries) != 1 {
			t.Fatal("range lost", err)
		}
		events := got.Entries[0].Ranges.Entries[0].Events.Entries
		want := []OSVEvent{
			{State: OSVFieldValue, Fields: []OSVEventField{{Name: "fixed", Value: OSVString{State: OSVFieldValue, Value: "2"}}}},
			{Index: 1, State: OSVFieldValue, Fields: []OSVEventField{{Name: "introduced", Value: OSVString{State: OSVFieldValue, Value: "0"}}}},
			{Index: 2, State: OSVFieldValue, Fields: []OSVEventField{{Name: "limit", Value: OSVString{State: OSVFieldValue, Value: "1"}}}},
		}
		if !reflect.DeepEqual(events, want) {
			t.Fatal("event sequence reordered or interpreted")
		}
	})
}

func TestProjectOSVRangesCumulativeBudget(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			last := `{}`
			if extra {
				last = `{"future":null}`
			}
			events := strings.Repeat(`{},`, 19_992) + last
			versions := strings.Repeat(`"v",`, 19_999) + `"v"`
			doc := affectedDocument(t, `[{"package":false,"versions":false,"ranges":[null,{"type":null,"events":[null,{"introduced":"0","future":false}]}]},{"package":null,"versions":[`+versions+`],"ranges":[{"events":[`+events+`]}]},{"ranges":[]},{}]`)
			if extra {
				assertAffectedError(t, doc, "limit-exceeded")
				return
			}
			got, err := ProjectOSVAffected(doc)
			if err != nil || got.SourceSHA256 != doc.SHA256 || len(got.Entries) != 4 {
				t.Fatal("exact mixed bound or independent version budget rejected", err)
			}
			if len(got.Entries[1].Versions.Entries) != 20_000 || len(got.Entries[0].Ranges.Entries) != 2 || len(got.Entries[1].Ranges.Entries) != 1 {
				t.Fatal("ranges/versions truncated")
			}
			first := got.Entries[0].Ranges.Entries[1].Events
			if first.State != OSVFieldValue || len(first.Entries) != 2 || first.Entries[0].State != OSVFieldNull || len(first.Entries[1].Fields) != 2 {
				t.Fatal("mixed event evidence lost")
			}
			repeated := got.Entries[1].Ranges.Entries[0].Events
			if repeated.State != OSVFieldValue || len(repeated.Entries) != 19_993 {
				t.Fatal("repeated events truncated")
			}
			for i, e := range repeated.Entries {
				if !reflect.DeepEqual(e, OSVEvent{Index: i, State: OSVFieldValue, Fields: []OSVEventField{}}) {
					t.Fatal("empty event position/nil distinction lost", i)
				}
			}
			if !reflect.DeepEqual(got.Entries[2].Ranges, OSVRanges{State: OSVFieldValue, Entries: []OSVRange{}}) || !reflect.DeepEqual(got.Entries[3].Ranges, OSVRanges{State: OSVFieldAbsent}) {
				t.Fatal("zero allowance rejects empty/absent later lists")
			}
		})
	}
}

func TestProjectOSVRangesCollectionLimits(t *testing.T) {
	for _, kind := range []string{"ranges", "events", "fields"} {
		for _, extra := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/%d", kind, extra), func(t *testing.T) {
				count := 20_000 + extra
				var raw string
				switch kind {
				case "ranges":
					raw = `[{"ranges":[` + strings.Repeat(`null,`, count-1) + `null]}]`
				case "events":
					count-- // One range slot also consumes a unit.
					raw = `[{"ranges":[{"events":[` + strings.Repeat(`false,`, count-1) + `false]}]}]`
				case "fields":
					count -= 2 // One range and one event slot.
					var fields strings.Builder
					for i := 0; i < count; i++ {
						if i > 0 {
							fields.WriteByte(',')
						}
						fmt.Fprintf(&fields, `"%05d":null`, i)
					}
					raw = `[{"ranges":[{"events":[{` + fields.String() + `}]}]}]`
				}
				doc := affectedDocument(t, raw)
				if extra > 0 {
					assertAffectedError(t, doc, "limit-exceeded")
					return
				}
				got, err := ProjectOSVAffected(doc)
				if err != nil || len(got.Entries) != 1 {
					t.Fatal("exact collection limit rejected", err)
				}
				ranges := got.Entries[0].Ranges.Entries
				switch kind {
				case "ranges":
					if len(ranges) != count {
						t.Fatal("range count lost")
					}
					for i, r := range ranges {
						if !reflect.DeepEqual(r, OSVRange{Index: i, State: OSVFieldNull}) {
							t.Fatal("null range lost", i)
						}
					}
				case "events":
					if len(ranges) != 1 || len(ranges[0].Events.Entries) != count {
						t.Fatal("event count lost")
					}
					for i, e := range ranges[0].Events.Entries {
						if !reflect.DeepEqual(e, OSVEvent{Index: i, State: OSVFieldInvalidType}) {
							t.Fatal("invalid event lost", i)
						}
					}
				case "fields":
					if len(ranges) != 1 || len(ranges[0].Events.Entries) != 1 || len(ranges[0].Events.Entries[0].Fields) != count {
						t.Fatal("field count lost")
					}
					for i, f := range ranges[0].Events.Entries[0].Fields {
						if f.Name != fmt.Sprintf("%05d", i) || f.Value != (OSVString{State: OSVFieldNull}) {
							t.Fatal("unknown/null field lost or unsorted", i)
						}
					}
				}
			})
		}
	}
}
