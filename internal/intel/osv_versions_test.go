package intel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestProjectOSVVersionsStates(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		state OSVFieldState
	}{
		{`null`, OSVFieldUnavailable}, {`42`, OSVFieldUnavailable}, {`[]`, OSVFieldUnavailable},
		{`{}`, OSVFieldAbsent}, {`{"package":{"versions":["wrong-level"]}}`, OSVFieldAbsent},
		{`{"versions":null}`, OSVFieldNull}, {`{"versions":false}`, OSVFieldInvalidType},
		{`{"versions":42}`, OSVFieldInvalidType}, {`{"versions":"1"}`, OSVFieldInvalidType},
		{`{"versions":{}}`, OSVFieldInvalidType}, {`{"package":null,"versions":[]}`, OSVFieldValue},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			doc := affectedDocument(t, "["+tc.raw+"]")
			got, err := ProjectOSVAffected(doc)
			if err != nil || got.SourceSHA256 != doc.SHA256 || len(got.Entries) != 1 || got.Entries[0].Index != 0 {
				t.Fatal("entry evidence lost", err)
			}
			want := OSVVersions{State: tc.state}
			if tc.state == OSVFieldValue {
				want.Entries = []OSVString{}
			}
			if !reflect.DeepEqual(got.Entries[0].Versions, want) {
				t.Fatal("version list state/nil/empty changed", got.Entries[0].Versions)
			}
		})
	}
}

func TestProjectOSVVersionsEvidenceAndOwnership(t *testing.T) {
	const versions = `["1",null,false,42,{},[],"", " v1.0.0 ","1","\u0031","workspace:*", "1e400"]`
	const wantedRaw = `[{"package":null,"versions":` + versions + `,"ranges":[{"type":"UNKNOWN","events":[{"introduced":"0"}]}]}, {"versions":` + versions + `}, {"package":false,"versions":` + versions + `}, {"package":{"ecosystem":"PyPI","name":"x","versions":["wrong-level"]},"versions":` + versions + `}]`
	doc := affectedDocument(t, wantedRaw)
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProjectOSVAffected(doc)
	if err != nil || got.SourceSHA256 != doc.SHA256 || len(got.Entries) != 4 {
		t.Fatal("entries lost", err)
	}
	want := OSVVersions{State: OSVFieldValue, Entries: []OSVString{
		{State: OSVFieldValue, Value: "1"}, {State: OSVFieldNull}, {State: OSVFieldInvalidType},
		{State: OSVFieldInvalidType}, {State: OSVFieldInvalidType}, {State: OSVFieldInvalidType},
		{State: OSVFieldValue, Value: ""}, {State: OSVFieldValue, Value: " v1.0.0 "},
		{State: OSVFieldValue, Value: "1"}, {State: OSVFieldValue, Value: "1"},
		{State: OSVFieldValue, Value: "workspace:*"}, {State: OSVFieldValue, Value: "1e400"},
	}}
	for i, entry := range got.Entries {
		if entry.Index != i || !reflect.DeepEqual(entry.Versions, want) {
			t.Fatal("versions filtered/interpreted/merged", i, entry.Versions)
		}
	}
	for i, state := range []OSVFieldState{OSVFieldNull, OSVFieldAbsent, OSVFieldInvalidType, OSVFieldValue} {
		if got.Entries[i].PackageState != state {
			t.Fatal("package states changed")
		}
	}
	after, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("raw versions/ranges changed")
	}
	projectionBefore, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate every input byte so a borrowed nested string would change.
	for i := range doc.Fields["affected"] {
		doc.Fields["affected"][i] = 'X'
	}
	doc.Fields["affected"] = json.RawMessage(`[]`)
	doc.SHA256[0] ^= 255
	projectionAfter, err := json.Marshal(got)
	if err != nil || !bytes.Equal(projectionBefore, projectionAfter) {
		t.Fatal("nested version output aliases input")
	}
	sourceBefore, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got.Entries[0].Versions.Entries[0].Value = "changed"
	got.Entries[0].Versions.Entries[1].State = OSVFieldValue
	for _, entry := range got.Entries[1:] {
		if !reflect.DeepEqual(entry.Versions, want) {
			t.Fatal("version lists share mutable backing storage")
		}
	}
	sourceAfter, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(sourceBefore, sourceAfter) {
		t.Fatal("output mutation affected input")
	}
}

func TestProjectOSVVersionsCumulativeLimit(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			var list strings.Builder
			list.WriteByte('[')
			parts := []string{`null`, `false`, `"same"`}
			for i := 0; i < 10_000; i++ {
				if i > 0 {
					list.WriteByte(',')
				}
				list.WriteString(parts[i%3])
			}
			list.WriteByte(']')
			last := `[]`
			if extra {
				last = `[null]`
			}
			doc := affectedDocument(t, `[{"package":null,"versions":`+list.String()+`},{"package":false,"versions":`+list.String()+`},{"versions":`+last+`},{}]`)
			if extra {
				assertAffectedError(t, doc, "limit-exceeded")
				return
			}
			got, err := ProjectOSVAffected(doc)
			if err != nil || got.SourceSHA256 != doc.SHA256 || len(got.Entries) != 4 {
				t.Fatal("exact cumulative limit rejected", err)
			}
			for _, entry := range got.Entries[:2] {
				if entry.Versions.State != OSVFieldValue || len(entry.Versions.Entries) != 10_000 {
					t.Fatal("slots truncated")
				}
				for i, member := range entry.Versions.Entries {
					want := OSVString{State: OSVFieldNull}
					if i%3 == 1 {
						want.State = OSVFieldInvalidType
					}
					if i%3 == 2 {
						want = OSVString{State: OSVFieldValue, Value: "same"}
					}
					if member != want {
						t.Fatal("null/invalid/repeated position lost", i)
					}
				}
			}
			if !reflect.DeepEqual(got.Entries[2].Versions, OSVVersions{State: OSVFieldValue, Entries: []OSVString{}}) || !reflect.DeepEqual(got.Entries[3].Versions, OSVVersions{State: OSVFieldAbsent}) {
				t.Fatal("zero allowance incorrectly rejected later empty/absent lists")
			}
		})
	}
}
