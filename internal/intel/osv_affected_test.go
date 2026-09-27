package intel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestProjectOSVAffectedRootStates(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		state OSVFieldState
	}{
		{"", OSVFieldAbsent}, {`null`, OSVFieldNull}, {`false`, OSVFieldInvalidType},
		{`42`, OSVFieldInvalidType}, {`"not-an-array"`, OSVFieldInvalidType}, {`{}`, OSVFieldInvalidType}, {`[]`, OSVFieldValue},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			doc := affectedDocument(t, tc.raw)
			got, err := ProjectOSVAffected(doc)
			want := OSVAffectedProjection{SourceSHA256: doc.SHA256, State: tc.state}
			if tc.state == OSVFieldValue {
				want.Entries = []OSVAffectedEntry{}
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("root state/nil/empty distinction lost", got, err)
			}
		})
	}
}

func TestProjectOSVAffectedParentStates(t *testing.T) {
	for _, tc := range []struct {
		raw                             string
		state, packageState, childState OSVFieldState
	}{
		{`null`, OSVFieldNull, OSVFieldUnavailable, OSVFieldUnavailable},
		{`false`, OSVFieldInvalidType, OSVFieldUnavailable, OSVFieldUnavailable},
		{`1e400`, OSVFieldInvalidType, OSVFieldUnavailable, OSVFieldUnavailable},
		{`[]`, OSVFieldInvalidType, OSVFieldUnavailable, OSVFieldUnavailable},
		{`"pkg"`, OSVFieldInvalidType, OSVFieldUnavailable, OSVFieldUnavailable},
		{`{}`, OSVFieldValue, OSVFieldAbsent, OSVFieldUnavailable},
		{`{"name":"outer","ecosystem":"npm","purl":"outer"}`, OSVFieldValue, OSVFieldAbsent, OSVFieldUnavailable},
		{`{"package":null}`, OSVFieldValue, OSVFieldNull, OSVFieldUnavailable},
		{`{"package":false}`, OSVFieldValue, OSVFieldInvalidType, OSVFieldUnavailable},
		{`{"package":42}`, OSVFieldValue, OSVFieldInvalidType, OSVFieldUnavailable},
		{`{"package":[]}`, OSVFieldValue, OSVFieldInvalidType, OSVFieldUnavailable},
		{`{"package":"pkg"}`, OSVFieldValue, OSVFieldInvalidType, OSVFieldUnavailable},
		{`{"package":{}}`, OSVFieldValue, OSVFieldValue, OSVFieldAbsent},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			doc := affectedDocument(t, "["+tc.raw+"]")
			got, err := ProjectOSVAffected(doc)
			child := OSVString{State: tc.childState}
			want := OSVAffectedEntry{Index: 0, State: tc.state, PackageState: tc.packageState, Ecosystem: child, Name: child, PURL: child}
			if tc.state == OSVFieldValue {
				want.Versions = OSVVersions{State: OSVFieldAbsent}
			}
			if err != nil || got.SourceSHA256 != doc.SHA256 || got.State != OSVFieldValue || !reflect.DeepEqual(got.Entries, []OSVAffectedEntry{want}) {
				t.Fatal("unavailable/absent parent or child collapsed", got, err)
			}
		})
	}
}

func TestProjectOSVAffectedStringStates(t *testing.T) {
	for _, key := range []string{"ecosystem", "name", "purl"} {
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
				pkg := `{}`
				if tc.raw != "" {
					pkg = fmt.Sprintf(`{%q:%s}`, key, tc.raw)
				}
				doc := affectedDocument(t, `[{"package":`+pkg+`}]`)
				got, err := ProjectOSVAffected(doc)
				if err != nil || got.State != OSVFieldValue || len(got.Entries) != 1 {
					t.Fatal("record lost", err)
				}
				want := OSVAffectedEntry{State: OSVFieldValue, PackageState: OSVFieldValue, Ecosystem: OSVString{State: OSVFieldAbsent}, Name: OSVString{State: OSVFieldAbsent}, PURL: OSVString{State: OSVFieldAbsent}, Versions: OSVVersions{State: OSVFieldAbsent}}
				field := OSVString{State: tc.state, Value: tc.value}
				switch key {
				case "ecosystem":
					want.Ecosystem = field
				case "name":
					want.Name = field
				case "purl":
					want.PURL = field
				}
				if !reflect.DeepEqual(got.Entries[0], want) {
					t.Fatal("string evidence altered", got.Entries[0])
				}
			})
		}
	}
}

func TestProjectOSVAffectedEvidenceAndOrder(t *testing.T) {
	const repeated = `{"package":{"ecosystem":"PyPI","name":"mismatch","purl":"pkg:npm/other@9","future":true},"versions":["9"],"ranges":[{"type":"UNKNOWN","events":[{"introduced":"0"}]}],"database_specific":{"future":1e400}}`
	doc := affectedDocument(t, "["+repeated+`,null,{"package":{"ecosystem":" NPM ","na\u006de":"\u0061lias","purl":" not a purl "}},`+repeated+`,{"package":{"ecosystem":"npm","name":false,"purl":"keep"}}]`)
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProjectOSVAffected(doc)
	if err != nil || got.SourceSHA256 != doc.SHA256 || got.State != OSVFieldValue || len(got.Entries) != 5 {
		t.Fatal("array evidence lost", err)
	}
	for i, entry := range got.Entries {
		if entry.Index != i {
			t.Fatal("positions changed")
		}
	}
	first := OSVAffectedEntry{State: OSVFieldValue, PackageState: OSVFieldValue, Ecosystem: OSVString{State: OSVFieldValue, Value: "PyPI"}, Name: OSVString{State: OSVFieldValue, Value: "mismatch"}, PURL: OSVString{State: OSVFieldValue, Value: "pkg:npm/other@9"}, Versions: OSVVersions{State: OSVFieldValue, Entries: []OSVString{{State: OSVFieldValue, Value: "9"}}}}
	if !reflect.DeepEqual(got.Entries[0], first) {
		t.Fatal("non-npm/conflicting identity interpreted")
	}
	first.Index = 3
	if !reflect.DeepEqual(got.Entries[3], first) {
		t.Fatal("duplicate identity merged")
	}
	if !reflect.DeepEqual(got.Entries[1], OSVAffectedEntry{Index: 1, State: OSVFieldNull}) {
		t.Fatal("bad element discarded or child absence invented")
	}
	middle := got.Entries[2]
	if middle.Ecosystem.Value != " NPM " || middle.Name.Value != "alias" || middle.PURL.Value != " not a purl " {
		t.Fatal("exact strings normalized")
	}
	last := got.Entries[4]
	if last.Ecosystem.Value != "npm" || last.Name.State != OSVFieldInvalidType || last.Name.Value != "" || last.PURL.Value != "keep" {
		t.Fatal("bad string erased usable siblings")
	}
	after, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("raw versions/ranges/unknowns changed")
	}
	saved := got
	saved.Entries = append([]OSVAffectedEntry(nil), got.Entries...)
	doc.Fields["affected"][1] = 'X'
	doc.Fields["affected"] = json.RawMessage(`[]`)
	doc.SHA256[0] ^= 255
	if !reflect.DeepEqual(got, saved) {
		t.Fatal("output aliases source")
	}
	got.Entries[0].Name.Value = "changed"
	if got.Entries[3].Name.Value != "mismatch" {
		t.Fatal("duplicates share mutable output")
	}
}

func TestProjectOSVAffectedLimits(t *testing.T) {
	for _, count := range []int{20_000, 20_001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var src strings.Builder
			src.WriteByte('[')
			parts := []string{`null`, `42`, `{"package":{"name":"same"}}`}
			for i := 0; i < count; i++ {
				if i > 0 {
					src.WriteByte(',')
				}
				src.WriteString(parts[i%3])
			}
			src.WriteByte(']')
			doc := affectedDocument(t, src.String())
			if count > 20_000 {
				assertAffectedError(t, doc, "limit-exceeded")
				return
			}
			got, err := ProjectOSVAffected(doc)
			if err != nil || got.SourceSHA256 != doc.SHA256 || got.State != OSVFieldValue || len(got.Entries) != count {
				t.Fatal("exact bound lost slots", err)
			}
			for i, entry := range got.Entries {
				want := OSVAffectedEntry{Index: i}
				switch i % 3 {
				case 0:
					want.State = OSVFieldNull
				case 1:
					want.State = OSVFieldInvalidType
				case 2:
					want.State, want.PackageState = OSVFieldValue, OSVFieldValue
					want.Versions = OSVVersions{State: OSVFieldAbsent}
					want.Name = OSVString{State: OSVFieldValue, Value: "same"}
					want.Ecosystem, want.PURL = OSVString{State: OSVFieldAbsent}, OSVString{State: OSVFieldAbsent}
				}
				if !reflect.DeepEqual(entry, want) {
					t.Fatal("slot/state/duplicate lost", i)
				}
			}
		})
	}
}

func TestProjectOSVAffectedNilFields(t *testing.T) {
	assertAffectedError(t, OSVDocument{}, "invalid-shape")
}

func affectedDocument(t *testing.T, affected string) OSVDocument {
	t.Helper()
	src := `{"id":"TEST","modified":"uninterpreted"`
	if affected != "" {
		src += `,"affected":` + affected
	}
	doc, err := ParseOSVRecord([]byte(src + "}"))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func assertAffectedError(t *testing.T, doc OSVDocument, code string) {
	t.Helper()
	got, err := ProjectOSVAffected(doc)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != code || err.Error() != "intel: "+code || !reflect.DeepEqual(got, OSVAffectedProjection{}) {
		t.Fatal("controlled error/zero projection required", got, err)
	}
}
