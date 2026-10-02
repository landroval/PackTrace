package intel

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func npmIdentityDocument(t *testing.T, source string) (OSVDocument, OSVHeader, OSVAffectedProjection) {
	t.Helper()
	doc, err := ParseOSVRecord([]byte(source))
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
	return doc, header, affected
}

func npmIdentityInput(t *testing.T, packageJSON string) (OSVDocument, OSVHeader, OSVAffectedProjection) {
	t.Helper()
	return npmIdentityDocument(t, `{"id":"fixture","modified":"opaque","affected":[{"package":`+packageJSON+`}]}`)
}

func npmIdentitySnapshot[T any](t *testing.T, value T) T {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func assertNPMIdentityError(t *testing.T, header OSVHeader, affected OSVAffectedProjection, code string) {
	t.Helper()
	got, err := QualifyOSVNPMIdentities(header, affected)
	var parseErr *ParseError
	if !errors.As(err, &parseErr) || parseErr.Code != code || err.Error() != "intel: "+code || !reflect.DeepEqual(got, OSVNPMIdentityProjection{}) {
		t.Fatal("error category or zero whole result lost", got, err)
	}
}

// A fallback, case fold, diagnostic omission or source mutation breaks these literal cases.
func TestQualifyOSVNPMIdentitiesProfile(t *testing.T) {
	for _, tc := range []struct {
		name, pkg     string
		qualification OSVNPMIdentityQualification
		purlUsable    bool
		purlName      string
		problems      []OSVNPMIdentityProblem
	}{
		{"absent-purl", `{"ecosystem":"npm","name":"Foo"}`, OSVNPMIdentityCandidate, false, "", []OSVNPMIdentityProblem{}},
		{"equal-legacy", `{"ecosystem":"npm","name":"Foo","purl":"pkg:npm/Foo"}`, OSVNPMIdentityCandidate, true, "Foo", []OSVNPMIdentityProblem{}},
		{"escaped-legacy", `{"ecosystem":"npm","name":"Foo","purl":"pkg:npm/%46oo"}`, OSVNPMIdentityCandidate, true, "Foo", []OSVNPMIdentityProblem{}},
		{"case-conflict", `{"ecosystem":"npm","name":"Foo","purl":"pkg:npm/foo"}`, OSVNPMIdentityConflict, true, "foo", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemPURLNameConflict, "purl"}}},
		{"name-conflict", `{"ecosystem":"npm","name":"Foo","purl":"pkg:npm/Bar"}`, OSVNPMIdentityConflict, true, "Bar", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemPURLNameConflict, "purl"}}},
		{"scoped-legacy", `{"ecosystem":"npm","name":"@Scope/_Name","purl":"pkg:npm/%40Scope/_Name"}`, OSVNPMIdentityCandidate, true, "@Scope/_Name", []OSVNPMIdentityProblem{}},
		{"scoped-dot", `{"ecosystem":"npm","name":"@scope/.name","purl":"pkg:npm/%40scope/.name"}`, OSVNPMIdentityCandidate, true, "@scope/.name", []OSVNPMIdentityProblem{}},
		{"scope-dot", `{"ecosystem":"npm","name":"@.scope/name","purl":"pkg:npm/%40.scope/name"}`, OSVNPMIdentityCandidate, true, "@.scope/name", []OSVNPMIdentityProblem{}},
		{"unreserved", `{"ecosystem":"npm","name":"A-._~9","purl":"pkg:npm/A%2d%2e%5f%7e9"}`, OSVNPMIdentityCandidate, true, "A-._~9", []OSVNPMIdentityProblem{}},
		{"scoped-case-conflict", `{"ecosystem":"npm","name":"@Scope/Name","purl":"pkg:npm/%40scope/Name"}`, OSVNPMIdentityConflict, true, "@scope/Name", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemPURLNameConflict, "purl"}}},
		{"purl-null", `{"ecosystem":"npm","name":"Foo","purl":null}`, OSVNPMIdentityUnqualified, false, "", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemPURLUnusable, "purl"}}},
		{"purl-boolean", `{"ecosystem":"npm","name":"Foo","purl":false}`, OSVNPMIdentityUnqualified, false, "", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemPURLUnusable, "purl"}}},
		{"no-ecosystem-fallback", `{"name":"Foo","purl":"pkg:npm/Foo"}`, OSVNPMIdentityUnqualified, true, "Foo", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemEcosystemUnusable, "ecosystem"}}},
		{"no-name-fallback", `{"ecosystem":"npm","purl":"pkg:npm/Foo"}`, OSVNPMIdentityUnqualified, true, "Foo", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemNameUnusable, "name"}}},
		{"purl-only", `{"purl":"pkg:npm/Foo"}`, OSVNPMIdentityUnqualified, true, "Foo", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemEcosystemUnusable, "ecosystem"}, {OSVNPMIdentityProblemNameUnusable, "name"}}},
		{"null-required", `{"ecosystem":null,"name":null,"purl":"pkg:npm/Foo"}`, OSVNPMIdentityUnqualified, true, "Foo", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemEcosystemUnusable, "ecosystem"}, {OSVNPMIdentityProblemNameUnusable, "name"}}},
		{"invalid-required", `{"ecosystem":false,"name":[],"purl":"pkg:npm/Foo"}`, OSVNPMIdentityUnqualified, true, "Foo", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemEcosystemUnusable, "ecosystem"}, {OSVNPMIdentityProblemNameUnusable, "name"}}},
		{"other-domain", `{"ecosystem":"PyPI","name":"Foo","purl":"pkg:npm/Bar"}`, OSVNPMIdentityUnqualified, true, "Bar", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemEcosystemOutsideProfile, "ecosystem"}}},
		{"three-problems", `{"name":42,"purl":false}`, OSVNPMIdentityUnqualified, false, "", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemEcosystemUnusable, "ecosystem"}, {OSVNPMIdentityProblemNameUnusable, "name"}, {OSVNPMIdentityProblemPURLUnusable, "purl"}}},
		{"empty-package", `{}`, OSVNPMIdentityUnqualified, false, "", []OSVNPMIdentityProblem{{OSVNPMIdentityProblemEcosystemUnusable, "ecosystem"}, {OSVNPMIdentityProblemNameUnusable, "name"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, header, affected := npmIdentityInput(t, tc.pkg)
			headerBefore, affectedBefore := header, npmIdentitySnapshot(t, affected)
			rawBefore := make(map[string]json.RawMessage, len(doc.Fields))
			for k, v := range doc.Fields {
				rawBefore[k] = bytes.Clone(v)
			}
			got, err := QualifyOSVNPMIdentities(header, affected)
			e := affected.Entries[0]
			want := OSVNPMIdentityProjection{SourceSHA256: doc.SHA256, HeaderSchema: OSVHeaderSchemaV1Implicit, State: OSVFieldValue,
				Entries: []OSVNPMIdentityEntry{{Index: 0, State: OSVFieldValue, PackageState: OSVFieldValue,
					Ecosystem: e.Ecosystem, Name: e.Name, PURL: e.PURL, Qualification: tc.qualification,
					PURLUsable: tc.purlUsable, PURLName: tc.purlName, Problems: tc.problems}}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("literal qualification/evidence lost", got, err)
			}
			if !reflect.DeepEqual(header, headerBefore) || !reflect.DeepEqual(affected, affectedBefore) || !reflect.DeepEqual(doc.Fields, rawBefore) {
				t.Fatal("source evidence mutated")
			}
		})
	}
	for _, key := range []string{"ecosystem", "name", "purl"} {
		for _, raw := range []string{`null`, `false`, `42`, `1e400`, `[]`, `{}`} {
			t.Run(key+"-unusable-"+raw, func(t *testing.T) {
				pkg := `{"ecosystem":"npm","name":"Foo"}`
				if key == "ecosystem" {
					pkg = `{"ecosystem":` + raw + `,"name":"Foo"}`
				}
				if key == "name" {
					pkg = `{"ecosystem":"npm","name":` + raw + `}`
				}
				if key == "purl" {
					pkg = `{"ecosystem":"npm","name":"Foo","purl":` + raw + `}`
				}
				_, h, a := npmIdentityInput(t, pkg)
				got, err := QualifyOSVNPMIdentities(h, a)
				kind := map[string]OSVNPMIdentityProblemKind{"ecosystem": OSVNPMIdentityProblemEcosystemUnusable, "name": OSVNPMIdentityProblemNameUnusable, "purl": OSVNPMIdentityProblemPURLUnusable}[key]
				if err != nil || len(got.Entries) != 1 || got.Entries[0].Qualification != OSVNPMIdentityUnqualified || !reflect.DeepEqual(got.Entries[0].Problems, []OSVNPMIdentityProblem{{kind, key}}) {
					t.Fatal("bad present sibling rescued", got, err)
				}
			})
		}
	}
	for _, ecosystem := range []string{"", "NPM", "npm ", " npm", "npm\n", "PyPI", "unknown"} {
		t.Run("ecosystem-"+ecosystem, func(t *testing.T) {
			pkg, _ := json.Marshal(map[string]string{"ecosystem": ecosystem, "name": "Foo"})
			_, h, a := npmIdentityInput(t, string(pkg))
			got, err := QualifyOSVNPMIdentities(h, a)
			if err != nil || len(got.Entries) != 1 || got.Entries[0].Qualification != OSVNPMIdentityUnqualified || !reflect.DeepEqual(got.Entries[0].Problems, []OSVNPMIdentityProblem{{OSVNPMIdentityProblemEcosystemOutsideProfile, "ecosystem"}}) {
				t.Fatal(got, err)
			}
		})
	}
	for _, name := range []string{"", ".name", "_name", "*", "a/b", "@scope/", "@/name", "@@scope/name", "@scope/a/b", "a:b", "a+b", "a%20b", "a\\b", "a?b", "a#b", "a!b", "name ", "a\x00b", "a\nb", "é", "@scope/é"} {
		t.Run("name-"+name, func(t *testing.T) {
			pkg, _ := json.Marshal(map[string]string{"ecosystem": "npm", "name": name})
			_, h, a := npmIdentityInput(t, string(pkg))
			got, err := QualifyOSVNPMIdentities(h, a)
			if err != nil || len(got.Entries) != 1 || got.Entries[0].Name.Value != name || got.Entries[0].Qualification != OSVNPMIdentityUnqualified || !reflect.DeepEqual(got.Entries[0].Problems, []OSVNPMIdentityProblem{{OSVNPMIdentityProblemNameOutsideProfile, "name"}}) {
				t.Fatal(got, err)
			}
		})
	}
	for _, purl := range []string{"", " pkg:npm/Foo", "pkg:npm/Foo ", "pkg:NPM/Foo", "PKG:npm/Foo", "pkg:pypi/Foo", "pkg:npm/Foo@1", "pkg:npm/Foo?key=value", "pkg:npm/Foo#path", "pkg:npm/@scope/name", "pkg:npm//Foo", "pkg:npm//", "pkg:npm/Foo/", "pkg:npm/scope/a/b", "pkg:npm/Foo%2fBar", "pkg:npm/%40scope%2fname/Foo", "pkg:npm/%40scope/Foo%2fBar", "pkg:npm/%40scope/%40name", "pkg:npm/%40scope", "pkg:npm/%2540scope/name", "pkg:npm/Foo%", "pkg:npm/Foo%GG", "pkg:npm/%00", "pkg:npm/%ff", "pkg:npm/%C3%A9", "pkg:npm/a+b", "pkg:npm/Foo%3fkey", "pkg:npm/Foo%23path", "pkg:npm/Foo%401", "pkg:npm/Foo%5cBar", "pkg:npm/Foo\n"} {
		t.Run("purl-"+purl, func(t *testing.T) {
			pkg, _ := json.Marshal(map[string]string{"ecosystem": "npm", "name": "Foo", "purl": purl})
			_, h, a := npmIdentityInput(t, string(pkg))
			got, err := QualifyOSVNPMIdentities(h, a)
			if err != nil || len(got.Entries) != 1 || got.Entries[0].PURL.Value != purl || got.Entries[0].PURLUsable || got.Entries[0].PURLName != "" || got.Entries[0].Qualification != OSVNPMIdentityUnqualified || !reflect.DeepEqual(got.Entries[0].Problems, []OSVNPMIdentityProblem{{OSVNPMIdentityProblemPURLOutsideProfile, "purl"}}) {
				t.Fatal(got, err)
			}
		})
	}
}

func TestQualifyOSVNPMIdentitiesHierarchy(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		state OSVFieldState
	}{{"", OSVFieldAbsent}, {`null`, OSVFieldNull}, {`false`, OSVFieldInvalidType}, {`42`, OSVFieldInvalidType}, {`"x"`, OSVFieldInvalidType}, {`{}`, OSVFieldInvalidType}, {`[]`, OSVFieldValue}} {
		t.Run("root-"+tc.raw, func(t *testing.T) {
			source := `{"id":"fixture","modified":"opaque"}`
			if tc.raw != "" {
				source = `{"id":"fixture","modified":"opaque","affected":` + tc.raw + `}`
			}
			doc, h, a := npmIdentityDocument(t, source)
			got, err := QualifyOSVNPMIdentities(h, a)
			want := OSVNPMIdentityProjection{SourceSHA256: doc.SHA256, HeaderSchema: OSVHeaderSchemaV1Implicit, State: tc.state}
			if tc.state == OSVFieldValue {
				want.Entries = []OSVNPMIdentityEntry{}
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("root layout lost", got, err)
			}
		})
	}
	for _, tc := range []struct {
		raw               string
		state, pkg, child OSVFieldState
	}{
		{`null`, OSVFieldNull, OSVFieldUnavailable, OSVFieldUnavailable},
		{`false`, OSVFieldInvalidType, OSVFieldUnavailable, OSVFieldUnavailable},
		{`42`, OSVFieldInvalidType, OSVFieldUnavailable, OSVFieldUnavailable},
		{`"x"`, OSVFieldInvalidType, OSVFieldUnavailable, OSVFieldUnavailable},
		{`[]`, OSVFieldInvalidType, OSVFieldUnavailable, OSVFieldUnavailable},
		{`{}`, OSVFieldValue, OSVFieldAbsent, OSVFieldUnavailable},
		{`{"ecosystem":"npm","name":"Foo","purl":"pkg:npm/Foo"}`, OSVFieldValue, OSVFieldAbsent, OSVFieldUnavailable},
		{`{"package":null}`, OSVFieldValue, OSVFieldNull, OSVFieldUnavailable},
		{`{"package":false}`, OSVFieldValue, OSVFieldInvalidType, OSVFieldUnavailable},
		{`{"package":42}`, OSVFieldValue, OSVFieldInvalidType, OSVFieldUnavailable},
		{`{"package":"x"}`, OSVFieldValue, OSVFieldInvalidType, OSVFieldUnavailable},
		{`{"package":[]}`, OSVFieldValue, OSVFieldInvalidType, OSVFieldUnavailable},
	} {
		t.Run("parent-"+tc.raw, func(t *testing.T) {
			doc, h, a := npmIdentityDocument(t, `{"id":"fixture","modified":"opaque","affected":[`+tc.raw+`]}`)
			got, err := QualifyOSVNPMIdentities(h, a)
			child := OSVString{State: tc.child}
			want := OSVNPMIdentityProjection{SourceSHA256: doc.SHA256, HeaderSchema: OSVHeaderSchemaV1Implicit, State: OSVFieldValue,
				Entries: []OSVNPMIdentityEntry{{Index: 0, State: tc.state, PackageState: tc.pkg, Ecosystem: child, Name: child, PURL: child}}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("unavailable child became absent", got, err)
			}
		})
	}
	_, h, a := npmIdentityDocument(t, `{"id":"fixture","modified":"opaque","affected":[{"package":{"ecosystem":"npm","name":"Zoo"}},null,{"package":{"ecosystem":"npm","name":"Alpha"}},{"package":{"ecosystem":"npm","name":"Zoo"}}]}`)
	got, err := QualifyOSVNPMIdentities(h, a)
	if err != nil || len(got.Entries) != 4 {
		t.Fatal(got, err)
	}
	for i, want := range []string{"Zoo", "", "Alpha", "Zoo"} {
		if got.Entries[i].Index != i || got.Entries[i].Name.Value != want {
			t.Fatal("array reordered/filtered/deduplicated", got)
		}
	}
}

func TestQualifyOSVNPMIdentitiesHeaderGate(t *testing.T) {
	for _, tc := range []struct {
		schema        string
		state         OSVHeaderSchemaState
		qualification OSVNPMIdentityQualification
	}{
		{"", OSVHeaderSchemaV1Implicit, OSVNPMIdentityCandidate},
		{`"1.9.1"`, OSVHeaderSchemaV1Declared, OSVNPMIdentityCandidate},
		{`null`, OSVHeaderSchemaUnknown, OSVNPMIdentityUnknown},
		{`false`, OSVHeaderSchemaUnknown, OSVNPMIdentityUnknown},
		{`"broken"`, OSVHeaderSchemaUnknown, OSVNPMIdentityUnknown},
		{`"2.0.0"`, OSVHeaderSchemaUnsupported, OSVNPMIdentityUnknown},
	} {
		t.Run(tc.schema, func(t *testing.T) {
			source := `{"id":"fixture","modified":"opaque","affected":[null,{}, {"package":{}},{"package":{"ecosystem":"npm","name":"Foo","purl":"pkg:npm/Foo"}}]`
			if tc.schema != "" {
				source += `,"schema_version":` + tc.schema
			}
			source += `}`
			doc, h, a := npmIdentityDocument(t, source)
			before := npmIdentitySnapshot(t, a)
			got, err := QualifyOSVNPMIdentities(h, a)
			if err != nil || got.SourceSHA256 != doc.SHA256 || got.HeaderSchema != tc.state || len(got.Entries) != 4 || got.Entries[3].Qualification != tc.qualification {
				t.Fatal(got, err)
			}
			for i, e := range got.Entries {
				if e.Index != i || e.State != a.Entries[i].State || e.PackageState != a.Entries[i].PackageState || e.Ecosystem != a.Entries[i].Ecosystem || e.Name != a.Entries[i].Name || e.PURL != a.Entries[i].PURL {
					t.Fatal("gate lost source", got)
				}
				if tc.qualification == OSVNPMIdentityUnknown && (e.Problems != nil || e.PURLUsable || e.PURLName != "") {
					t.Fatal("unsupported header interpreted", got)
				}
			}
			if !reflect.DeepEqual(a, before) {
				t.Fatal("gate mutated input")
			}
		})
	}
}

func TestQualifyOSVNPMIdentitiesLimits(t *testing.T) {
	for _, tc := range []struct {
		label, name, purl string
		qualification     OSVNPMIdentityQualification
		problem           OSVNPMIdentityProblemKind
	}{
		{"name-214", strings.Repeat("A", 214), "", OSVNPMIdentityCandidate, OSVNPMIdentityProblemUnknown},
		{"name-215", strings.Repeat("A", 215), "", OSVNPMIdentityUnqualified, OSVNPMIdentityProblemNameOutsideProfile},
		{"scoped-214", "@Scope/" + strings.Repeat("A", 207), "", OSVNPMIdentityCandidate, OSVNPMIdentityProblemUnknown},
		{"scoped-215", "@Scope/" + strings.Repeat("A", 208), "", OSVNPMIdentityUnqualified, OSVNPMIdentityProblemNameOutsideProfile},
		{"purl-650", strings.Repeat("A", 214), "pkg:npm/" + strings.Repeat("%41", 214), OSVNPMIdentityCandidate, OSVNPMIdentityProblemUnknown},
		{"purl-651", strings.Repeat("A", 214), "pkg:npm/" + strings.Repeat("%41", 214) + "A", OSVNPMIdentityUnqualified, OSVNPMIdentityProblemPURLOutsideProfile},
	} {
		t.Run(tc.label, func(t *testing.T) {
			pkg := map[string]string{"ecosystem": "npm", "name": tc.name}
			if tc.purl != "" {
				pkg["purl"] = tc.purl
			}
			data, _ := json.Marshal(pkg)
			_, h, a := npmIdentityInput(t, string(data))
			got, err := QualifyOSVNPMIdentities(h, a)
			if err != nil || len(got.Entries) != 1 || got.Entries[0].Qualification != tc.qualification {
				t.Fatal(got, err)
			}
			if tc.problem == OSVNPMIdentityProblemUnknown {
				if got.Entries[0].Problems == nil || len(got.Entries[0].Problems) != 0 {
					t.Fatal(got)
				}
				if tc.purl != "" && (!got.Entries[0].PURLUsable || got.Entries[0].PURLName != tc.name) {
					t.Fatal("escape boundary lost", got)
				}
			} else {
				field := "name"
				if tc.problem == OSVNPMIdentityProblemPURLOutsideProfile {
					field = "purl"
				}
				if !reflect.DeepEqual(got.Entries[0].Problems, []OSVNPMIdentityProblem{{tc.problem, field}}) {
					t.Fatal(got)
				}
			}
		})
	}
	for _, schema := range []string{`"1.9.1"`, `null`, `"2.0.0"`} {
		t.Run("slots-"+schema, func(t *testing.T) {
			raw := strings.Repeat(`{"package":{"ecosystem":"npm","name":"Foo"}},null,`, 10_000)
			_, h, a := npmIdentityDocument(t, `{"id":"fixture","modified":"opaque","schema_version":`+schema+`,"affected":[`+strings.TrimSuffix(raw, ",")+`]}`)
			got, err := QualifyOSVNPMIdentities(h, a)
			if err != nil || len(got.Entries) != 20_000 || got.Entries[19_999].Index != 19_999 {
				t.Fatal("slots reset/truncated", err)
			}
			late := a.Entries[1]
			late.Index = 20_000
			a.Entries = append(a.Entries, late) // forged excess tests the consumer guard, not reader acceptance
			assertNPMIdentityError(t, h, a, "limit-exceeded")
		})
	}
}

func TestQualifyOSVNPMIdentitiesGuards(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func(*OSVHeader, *OSVAffectedProjection)
	}{
		{"digest", func(h *OSVHeader, a *OSVAffectedProjection) { h.SourceSHA256[0] ^= 1 }},
		{"top-unavailable", func(h *OSVHeader, a *OSVAffectedProjection) { a.State = OSVFieldUnavailable; a.Entries = nil }},
		{"top-enum", func(h *OSVHeader, a *OSVAffectedProjection) { a.State = 255 }},
		{"value-nil", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries = nil }},
		{"nonvalue-children", func(h *OSVHeader, a *OSVAffectedProjection) { a.State = OSVFieldNull }},
		{"nonvalue-empty", func(h *OSVHeader, a *OSVAffectedProjection) {
			a.State = OSVFieldAbsent
			a.Entries = []OSVAffectedEntry{}
		}},
		{"late-index", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[1].Index = 4 }},
		{"first-index", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[0].Index = -1 }},
		{"reorder", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[0], a.Entries[1] = a.Entries[1], a.Entries[0] }},
		{"member-absent", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[1].State = OSVFieldAbsent }},
		{"member-unavailable", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[1].State = OSVFieldUnavailable }},
		{"member-enum", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[1].State = 255 }},
		{"member-null-package", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[1].State = OSVFieldNull }},
		{"package-unavailable", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[1].PackageState = OSVFieldUnavailable }},
		{"package-enum", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[1].PackageState = 255 }},
		{"package-null-children", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[1].PackageState = OSVFieldNull }},
		{"child-unavailable", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[1].Name = OSVString{} }},
		{"child-enum", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[1].Name.State = 255 }},
		{"child-absent-value", func(h *OSVHeader, a *OSVAffectedProjection) { a.Entries[1].Name.State = OSVFieldAbsent }},
		{"fabricated-unavailable-value", func(h *OSVHeader, a *OSVAffectedProjection) {
			a.Entries[1].PackageState = OSVFieldAbsent
			a.Entries[1].Ecosystem = OSVString{}
			a.Entries[1].PURL = OSVString{}
			a.Entries[1].Name = OSVString{Value: "Foo"}
		}},
	} {
		for _, schema := range []OSVHeaderSchemaState{OSVHeaderSchemaV1Implicit, OSVHeaderSchemaUnknown, OSVHeaderSchemaUnsupported} {
			t.Run(mutate.name+"/"+string(rune('0'+schema)), func(t *testing.T) {
				_, h, a := npmIdentityDocument(t, `{"id":"fixture","modified":"opaque","affected":[{"package":{"ecosystem":"npm","name":"Foo"}},{"package":{"ecosystem":"npm","name":"Bar"}}]}`)
				h.Schema = schema
				mutate.fn(&h, &a)
				assertNPMIdentityError(t, h, a, "invalid-shape")
			})
		}
	}
}

func TestQualifyOSVNPMIdentitiesOwnership(t *testing.T) {
	doc, h, a := npmIdentityDocument(t, `{"id":"fixture","modified":"opaque","extra":{"spaces" : [1, 2]},"affected":[{"package":{"ecosystem":"npm","name":"Foo","purl":"pkg:npm/Bar"},"versions":["1","1"],"ranges":[{"type":"GIT","events":[{"unknown":null}]}]},{"package":{"ecosystem":"npm","name":"Foo","purl":"pkg:npm/Bar"}}]}`)
	rawBefore := make(map[string]json.RawMessage, len(doc.Fields))
	for k, v := range doc.Fields {
		rawBefore[k] = bytes.Clone(v)
	}
	before := npmIdentitySnapshot(t, a)
	headerBefore := h
	got, err := QualifyOSVNPMIdentities(h, a)
	if err != nil || len(got.Entries) != 2 || len(got.Entries[0].Problems) != 1 {
		t.Fatal(got, err)
	}
	if !reflect.DeepEqual(a, before) || !reflect.DeepEqual(h, headerBefore) || !reflect.DeepEqual(doc.Fields, rawBefore) {
		t.Fatal("source changed")
	}
	resultBefore := npmIdentitySnapshot(t, got)
	a.Entries[0].Name.Value = "input mutation"
	a.Entries[0].Index = 88
	a.Entries[0].Versions.Entries[0].Value = "changed version"
	a.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields[0].Name = "changed field"
	if !reflect.DeepEqual(got, resultBefore) {
		t.Fatal("input aliases output")
	}
	inputAfter := npmIdentitySnapshot(t, a)
	got.Entries[0].Problems[0].Field = "output mutation"
	got.Entries[0].Name.Value = "output mutation"
	got.Entries[0].Index = 99
	if !reflect.DeepEqual(a, inputAfter) || got.Entries[1].Problems[0].Field != "purl" || got.Entries[1].Name.Value != "Foo" || got.Entries[1].Index != 1 {
		t.Fatal("output aliases source/sibling")
	}
}

func TestQualifyOSVNPMIdentitiesSeparation(t *testing.T) {
	_, h, a := npmIdentityInput(t, `{"ecosystem":"npm","name":"F%6fo","purl":"pkg:npm/Foo"}`)
	got, err := QualifyOSVNPMIdentities(h, a)
	if err != nil || len(got.Entries) != 1 || got.Entries[0].Name.Value != "F%6fo" || got.Entries[0].Qualification != OSVNPMIdentityUnqualified || got.Entries[0].PURLName != "Foo" {
		t.Fatal("package.name decoded or rescued", got, err)
	}
	for _, raw := range []string{
		`{"id":"fixture","modified":"opaque","withdrawn":"now","affected":[{"package":{"ecosystem":"npm","name":"Foo","repository_url":"https://private.invalid"},"versions":[null,"not-version"],"ranges":[{"type":"GIT"}],"installed":true}]}`,
		`{"id":"fixture","modified":"opaque","affected":[{"package":{"ecosystem":"npm","name":"Foo"}}]}`,
	} {
		doc, h, a := npmIdentityDocument(t, raw)
		before := npmIdentitySnapshot(t, a)
		got, err := QualifyOSVNPMIdentities(h, a)
		if err != nil || len(got.Entries) != 1 || got.Entries[0].Qualification != OSVNPMIdentityCandidate || got.SourceSHA256 != doc.SHA256 || !reflect.DeepEqual(a, before) {
			t.Fatal("unrelated claims interpreted/changed", got, err)
		}
	}
	prefix := `{"id":"fixture","modified":"opaque","affected":[{"package":{"ecosystem":"npm","name":"Foo"}}],"padding":"`
	data := prefix + strings.Repeat("x", 4*1024*1024-len(prefix)-2) + `"}`
	_, h, a = npmIdentityDocument(t, data)
	got, err = QualifyOSVNPMIdentities(h, a)
	if err != nil || len(got.Entries) != 1 || got.Entries[0].Qualification != OSVNPMIdentityCandidate {
		t.Fatal("reader boundary lost", got, err)
	}
	_, err = ParseOSVRecord([]byte(data + " "))
	var parseErr *ParseError
	if !errors.As(err, &parseErr) || parseErr.Code != "limit-exceeded" {
		t.Fatal("reader byte limit changed", err)
	}
	deep := `{"id":"fixture","modified":"opaque","nested":` + strings.Repeat("[", 128) + `0` + strings.Repeat("]", 128) + `}`
	_, err = ParseOSVRecord([]byte(deep))
	if !errors.As(err, &parseErr) || parseErr.Code != "limit-exceeded" {
		t.Fatal("reader depth limit changed", err)
	}
}
