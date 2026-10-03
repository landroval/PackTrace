package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"testing"
)

func bunWorkspaceTestDocument(t *testing.T, w map[string]any) (BunLockDocument, []byte) {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"lockfileVersion": 1, "workspaces": w, "packages": map[string]any{},
	})
	if err != nil {
		t.Fatal("invalid owned fixture")
	}
	doc, err := ParseBunLock(data)
	if err != nil {
		t.Fatal("reader rejected owned fixture")
	}
	return doc, data
}

func bunWorkspaceTestMembers(n int, value any) map[string]any {
	m := make(map[string]any, n)
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("x%05d", i)] = value
	}
	return m
}

func bunWorkspaceTestFatal(t *testing.T, doc BunLockDocument, code string) {
	t.Helper()
	got, err := ProjectBunWorkspaces(doc)
	pe, ok := err.(*ParseError)
	if !ok || pe == nil || pe.Code != code || err.Error() != "inventory: "+code ||
		!reflect.DeepEqual(got, BunWorkspaceProjection{}) {
		t.Fatal("missing exact controlled whole-zero fatal")
	}
}

// Literal expected-record builder: fixed absent groups, no production oracle.
func bunWorkspaceTestRecord(location string, name, version LockField[string], groups ...DependencyGroup) BunWorkspaceRecord {
	r := BunWorkspaceRecord{Location: location, Name: name, Version: version, Requirements: []DependencyGroup{
		{Name: "dependencies"}, {Name: "devDependencies"}, {Name: "optionalDependencies"}, {Name: "peerDependencies"},
	}}
	for _, g := range groups {
		for i := range r.Requirements {
			if r.Requirements[i].Name == g.Name {
				r.Requirements[i] = g
			}
		}
	}
	return r
}

func bunWorkspaceTestExact(t *testing.T, doc BunLockDocument, data []byte, want []BunWorkspaceRecord) {
	t.Helper()
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal("cannot snapshot owned document")
	}
	input := append([]byte(nil), data...)
	got, err := ProjectBunWorkspaces(doc)
	if err != nil || got.Records == nil || got.SourceSHA256 != sha256.Sum256(input) || !reflect.DeepEqual(got.Records, want) {
		t.Fatal("literal declarations/states/order/source mismatch")
	}
	after, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(before, after) || !bytes.Equal(data, input) {
		t.Fatal("document/input changed")
	}
}

func TestProjectBunWorkspacesReference(t *testing.T) {
	absent := LockField[string]{}
	value := func(s string) LockField[string] { return LockField[string]{State: FieldValue, Value: s} }
	null := LockField[string]{State: FieldNull}
	invalid := LockField[string]{State: FieldInvalidType}
	dep := func(n, s string) DeclaredDependency {
		return DeclaredDependency{Name: n, Requirement: s, State: FieldValue}
	}
	group := func(n string, entries ...DeclaredDependency) DependencyGroup {
		return DependencyGroup{Name: n, State: FieldValue, Entries: entries}
	}
	rows := func(rs ...BunWorkspaceRecord) []BunWorkspaceRecord {
		if rs == nil {
			return []BunWorkspaceRecord{}
		}
		return rs
	}
	cases := []struct {
		id, w string
		want  []BunWorkspaceRecord
	}{
		{"C01", `{}`, rows()},
		{"C02", `{"":{}}`, rows(bunWorkspaceTestRecord("", absent, absent))},
		{"C03", `{"apps/a":{"name":"a","version":"1.2.3","dependencies":{"x":"^1"}}}`, rows(bunWorkspaceTestRecord("apps/a", value("a"), value("1.2.3"), group("dependencies", dep("x", "^1"))))},
		{"C04", `{"z":{"name":"same"},"":{"name":"same"},"a":{"name":"same"}}`, rows(bunWorkspaceTestRecord("", value("same"), absent), bunWorkspaceTestRecord("a", value("same"), absent), bunWorkspaceTestRecord("z", value("same"), absent))},
		{"C05", `{".":{},"./":{},"":{}}`, rows(bunWorkspaceTestRecord("", absent, absent), bunWorkspaceTestRecord(".", absent, absent), bunWorkspaceTestRecord("./", absent, absent))},
		{"C06", `{"apps/a":{}}`, rows(bunWorkspaceTestRecord("apps/a", absent, absent))},
		{"C07", `{"nul\u0000\n":{},"file:///x":{},"C:\\private":{},"/abs":{},"../private":{}}`, rows(bunWorkspaceTestRecord("../private", absent, absent), bunWorkspaceTestRecord("/abs", absent, absent), bunWorkspaceTestRecord("C:\\private", absent, absent), bunWorkspaceTestRecord("file:///x", absent, absent), bunWorkspaceTestRecord("nul\x00\n", absent, absent))},
		{"C08", `{"":{"name":"","version":""}}`, rows(bunWorkspaceTestRecord("", value(""), value("")))},
		{"C09", `{"":{"name":null,"version":null}}`, rows(bunWorkspaceTestRecord("", null, null))},
		{"C10", `{"":{"name":42,"version":false,"dependencies":{"x":"1"}}}`, rows(bunWorkspaceTestRecord("", invalid, invalid, group("dependencies", dep("x", "1"))))},
		{"C11", `{"":{"name":[],"version":{},"devDependencies":{"x":"2"}}}`, rows(bunWorkspaceTestRecord("", invalid, invalid, group("devDependencies", dep("x", "2"))))},
		{"C12", `{"":{"name":" Ω/@synthetic\n","version":"v1 /not-semver"}}`, rows(bunWorkspaceTestRecord("", value(" Ω/@synthetic\n"), value("v1 /not-semver")))},
		{"C13", `{"":{"dependencies":{},"devDependencies":{},"optionalDependencies":{},"peerDependencies":{}}}`, rows(bunWorkspaceTestRecord("", absent, absent, group("dependencies", []DeclaredDependency{}...), group("devDependencies", []DeclaredDependency{}...), group("optionalDependencies", []DeclaredDependency{}...), group("peerDependencies", []DeclaredDependency{}...)))},
		{"C14", `{"":{"dependencies":null,"devDependencies":null,"optionalDependencies":null,"peerDependencies":null}}`, rows(bunWorkspaceTestRecord("", absent, absent, DependencyGroup{Name: "dependencies", State: FieldNull}, DependencyGroup{Name: "devDependencies", State: FieldNull}, DependencyGroup{Name: "optionalDependencies", State: FieldNull}, DependencyGroup{Name: "peerDependencies", State: FieldNull}))},
		{"C15", `{"":{"dependencies":[],"devDependencies":false,"optionalDependencies":1,"peerDependencies":"x"}}`, rows(bunWorkspaceTestRecord("", absent, absent, DependencyGroup{Name: "dependencies", State: FieldInvalidType}, DependencyGroup{Name: "devDependencies", State: FieldInvalidType}, DependencyGroup{Name: "optionalDependencies", State: FieldInvalidType}, DependencyGroup{Name: "peerDependencies", State: FieldInvalidType}))},
		{"C16", `{"":{"dependencies":false,"devDependencies":{"x":"2"},"peerDependencies":null}}`, rows(bunWorkspaceTestRecord("", absent, absent, DependencyGroup{Name: "dependencies", State: FieldInvalidType}, group("devDependencies", dep("x", "2")), DependencyGroup{Name: "peerDependencies", State: FieldNull}))},
		{"C17", `{"":{"dependencies":{"z":"last","A":"first","a":"middle"}}}`, rows(bunWorkspaceTestRecord("", absent, absent, group("dependencies", dep("A", "first"), dep("a", "middle"), dep("z", "last"))))},
		{"C18", `{"":{"dependencies":{"x":""}}}`, rows(bunWorkspaceTestRecord("", absent, absent, group("dependencies", dep("x", ""))))},
		{"C19", `{"":{"dependencies":{"x":null}}}`, rows(bunWorkspaceTestRecord("", absent, absent, group("dependencies", DeclaredDependency{Name: "x", State: FieldNull})))},
		{"C20", `{"":{"dependencies":{"a":false,"b":[],"c":{},"d":7,"ok":"1"}}}`, rows(bunWorkspaceTestRecord("", absent, absent, group("dependencies", DeclaredDependency{Name: "a", State: FieldInvalidType}, DeclaredDependency{Name: "b", State: FieldInvalidType}, DeclaredDependency{Name: "c", State: FieldInvalidType}, DeclaredDependency{Name: "d", State: FieldInvalidType}, dep("ok", "1"))))},
		{"C21", `{"":{"dependencies":{"x":"1"},"optionalDependencies":{"x":"2"},"peerDependencies":{"x":"3"}}}`, rows(bunWorkspaceTestRecord("", absent, absent, group("dependencies", dep("x", "1")), group("optionalDependencies", dep("x", "2")), group("peerDependencies", dep("x", "3"))))},
		{"C22", `{"a":{"dependencies":{"x":"1"}},"b":{"dependencies":{"x":"2"}}}`, rows(bunWorkspaceTestRecord("a", absent, absent, group("dependencies", dep("x", "1"))), bunWorkspaceTestRecord("b", absent, absent, group("dependencies", dep("x", "2"))))},
		{"C23", `{"":{"dependencies":{"a":"npm:other@^1","b":"workspace:*","c":"catalog:","d":"file:../x","e":"git+ssh://synthetic.invalid/r"}}}`, rows(bunWorkspaceTestRecord("", absent, absent, group("dependencies", dep("a", "npm:other@^1"), dep("b", "workspace:*"), dep("c", "catalog:"), dep("d", "file:../x"), dep("e", "git+ssh://synthetic.invalid/r"))))},
		{"C24", `{"":{"peerDependencies":{"x":"1"},"peerDependenciesMeta":{"x":{"optional":true}}}}`, rows(bunWorkspaceTestRecord("", absent, absent, group("peerDependencies", dep("x", "1"))))},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			data := []byte(`{"lockfileVersion":1,"workspaces":` + tc.w + `,"packages":{}}`)
			doc, err := ParseBunLock(data)
			if err != nil {
				t.Fatal("invalid reference fixture")
			}
			bunWorkspaceTestExact(t, doc, data, tc.want)
		})
	}
	t.Run("C25", func(t *testing.T) {
		data := []byte(`{"lockfileVersion":1,"workspaces":{"x":{"unknown":18446744073709551616000}},"packages":{},"overrides":{"x":"repair"},"catalogs":{"x":"repair"},"trustedDependencies":["x"],"patchedDependencies":{"x":"private"}}`)
		doc, err := ParseBunLock(data)
		if err != nil {
			t.Fatal("invalid fixture")
		}
		bunWorkspaceTestExact(t, doc, data, rows(bunWorkspaceTestRecord("x", absent, absent)))
		if !bytes.Contains(doc.Workspaces["x"], []byte("18446744073709551616000")) {
			t.Fatal("unknown raw lost")
		}
	})
	t.Run("C26", func(t *testing.T) {
		data := []byte(`{"lockfileVersion":1,"workspaces":{"x":{}},"packages":{"x":["invented@1","",{}]}}`)
		doc, err := ParseBunLock(data)
		if err != nil {
			t.Fatal("invalid fixture")
		}
		bunWorkspaceTestExact(t, doc, data, rows(bunWorkspaceTestRecord("x", absent, absent)))
	})
	t.Run("C27", func(t *testing.T) {
		for _, v := range []string{"0", "1", "2", "3"} {
			t.Run(v, func(t *testing.T) {
				data := []byte(`{"lockfileVersion":` + v + `,"workspaces":{"x":{"name":"same","dependencies":{"x":"1"}}},"packages":{}}`)
				doc, err := ParseBunLock(data)
				if err != nil {
					t.Fatal("version fixture")
				}
				bunWorkspaceTestExact(t, doc, data, rows(bunWorkspaceTestRecord("x", value("same"), absent, group("dependencies", dep("x", "1")))))
			})
		}
	})
	t.Run("C28", func(t *testing.T) {
		for i, data := range [][]byte{
			[]byte(`{"lockfileVersion":1,"workspaces":{"x":{"name":"same"}},"packages":{}}`),
			[]byte("{ //synthetic comment\n \"lockfileVersion\":1,\"workspaces\":{\"x\":{\"name\":\"same\",},},\"packages\":{},}\n"),
		} {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				doc, err := ParseBunLock(data)
				if err != nil {
					t.Fatal("JSONC fixture")
				}
				bunWorkspaceTestExact(t, doc, data, rows(bunWorkspaceTestRecord("x", value("same"), absent)))
			})
		}
	})
	t.Run("C29", func(t *testing.T) {
		for i, w := range []string{
			`{"x":{},"\u0078":{}}`, `{"x":{"name":"1","na\u006de":"2"}}`, `{"x":{"dependencies":{"x":"1","\u0078":"2"}}}`,
		} {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				doc, err := ParseBunLock([]byte(`{"lockfileVersion":1,"workspaces":` + w + `,"packages":{}}`))
				pe, ok := err.(*ParseError)
				if !ok || pe == nil || pe.Code != "duplicate-key" || err.Error() != "inventory: duplicate-key" || !reflect.DeepEqual(doc, BunLockDocument{}) {
					t.Fatal("reader duplicate boundary")
				}
			})
		}
	})
	for _, id := range []string{"C30", "C31", "C32"} {
		t.Run(id, func(t *testing.T) {
			doc, _ := bunWorkspaceTestDocument(t, map[string]any{"a": map[string]any{"name": "same", "dependencies": map[string]any{"x": "1"}, "peerDependencies": map[string]any{"x": "2"}}, "z": map[string]any{"name": "same", "dependencies": map[string]any{"x": "3"}}})
			want := rows(bunWorkspaceTestRecord("a", value("same"), absent, group("dependencies", dep("x", "1")), group("peerDependencies", dep("x", "2"))), bunWorkspaceTestRecord("z", value("same"), absent, group("dependencies", dep("x", "3"))))
			got, err := ProjectBunWorkspaces(doc)
			if err != nil || !reflect.DeepEqual(got.Records, want) {
				t.Fatal("ownership initial projection")
			}
			digest := got.SourceSHA256
			switch id {
			case "C30":
				clear(doc.Workspaces["a"])
			case "C31":
				doc.Workspaces["a"] = json.RawMessage(`{}`)
				delete(doc.Workspaces, "z")
				for _, b := range doc.Fields {
					clear(b)
				}
			case "C32":
				got.Records[0].Requirements[0].Entries[0].Requirement = "changed"
				got.Records[0].Requirements[0].Entries = append(got.Records[0].Requirements[0].Entries, dep("extra", "changed"))
				if !reflect.DeepEqual(got.Records[0].Requirements[3], want[0].Requirements[3]) || !reflect.DeepEqual(got.Records[1], want[1]) {
					t.Fatal("sibling alias")
				}
				fresh, e := ProjectBunWorkspaces(doc)
				if e != nil || !reflect.DeepEqual(fresh.Records, want) {
					t.Fatal("output aliases document")
				}
				return
			}
			if got.SourceSHA256 != digest || !reflect.DeepEqual(got.Records, want) {
				t.Fatal("document aliases earlier output")
			}
		})
	}
	t.Run("C33", func(t *testing.T) {
		doc, _ := bunWorkspaceTestDocument(t, bunWorkspaceTestMembers(20_001, map[string]any{}))
		doc.Fields = nil
		bunWorkspaceTestFatal(t, doc, "invalid-shape")
	})
	t.Run("C34", func(t *testing.T) {
		doc, _ := bunWorkspaceTestDocument(t, map[string]any{})
		doc.Workspaces = nil
		bunWorkspaceTestFatal(t, doc, "invalid-shape")
	})
	t.Run("C35", func(t *testing.T) {
		for i, raw := range []json.RawMessage{nil, []byte(`null`), []byte(`[]`), []byte(`"synthetic-secret"`), []byte(`7`), []byte(`false`), []byte(`{"secret":`)} {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				doc, _ := bunWorkspaceTestDocument(t, map[string]any{"x": map[string]any{}})
				doc.Workspaces["x"] = raw
				bunWorkspaceTestFatal(t, doc, "invalid-shape")
			})
		}
	})
	t.Run("C36", func(t *testing.T) {
		doc, _ := bunWorkspaceTestDocument(t, map[string]any{"a": map[string]any{"name": "private"}, "z": map[string]any{}})
		doc.Workspaces["z"] = []byte(`null`)
		bunWorkspaceTestFatal(t, doc, "invalid-shape")
	})
	for _, id := range []string{"C37", "C38", "C39", "C40", "C41", "C42", "C43", "C44", "C45", "C46", "C47", "C48"} {
		t.Run(id, func(t *testing.T) {
			w := map[string]any{}
			code := ""
			wantRows := 1
			counts := [4]int{}
			switch id {
			case "C37", "C38", "C47":
				w[""] = map[string]any{}
				for i := 1; i < 20_000; i++ {
					w[fmt.Sprintf("w%05d", i)] = map[string]any{}
				}
				wantRows = 20_000
				if id == "C38" {
					w["z"] = map[string]any{}
					code = "limit-exceeded"
				}
				if id == "C47" {
					w[""] = map[string]any{"dependencies": bunWorkspaceTestMembers(20_000, "1")}
					counts[0] = 20_000
				}
			case "C39", "C40":
				n := 20_000
				if id == "C40" {
					n++
					code = "limit-exceeded"
				}
				w[""] = map[string]any{"dependencies": bunWorkspaceTestMembers(n, "1")}
				counts[0] = 20_000
			case "C41", "C42":
				n := 10_000
				if id == "C42" {
					n++
					code = "limit-exceeded"
				}
				w[""] = map[string]any{"dependencies": bunWorkspaceTestMembers(10_000, "1"), "optionalDependencies": bunWorkspaceTestMembers(n, "2")}
				counts[0], counts[2] = 10_000, 10_000
			case "C43", "C44", "C45", "C46", "C48":
				n := 10_000
				if id == "C44" || id == "C46" || id == "C48" {
					n++
					code = "limit-exceeded"
				}
				first, second := any("1"), any("2")
				secondGroup := "dependencies"
				if id == "C45" || id == "C46" {
					first, second = nil, false
					secondGroup = "peerDependencies"
				}
				if id == "C48" {
					first, second = "synthetic-secret", false
				}
				w["a-private"] = map[string]any{"name": false, "version": "synthetic-secret", "dependencies": bunWorkspaceTestMembers(10_000, first)}
				w["z"] = map[string]any{secondGroup: bunWorkspaceTestMembers(n, second)}
				wantRows = 2
				counts[0] = 10_000
			}
			if id == "C48" {
				w["a-private"].(map[string]any)["name"] = "synthetic-secret"
			}
			doc, data := bunWorkspaceTestDocument(t, w)
			if id == "C38" {
				doc.Workspaces["z"] = []byte(`null`)
			}
			if code != "" {
				bunWorkspaceTestFatal(t, doc, code)
				return
			}
			got, err := ProjectBunWorkspaces(doc)
			if err != nil || got.Records == nil || len(got.Records) != wantRows || got.SourceSHA256 != sha256.Sum256(data) {
				t.Fatal("independent exact bound")
			}
			for _, r := range got.Records {
				if len(r.Requirements) != 4 {
					t.Fatal("fixed groups lost")
				}
			}
			for g, n := range counts {
				if n > 0 && len(got.Records[0].Requirements[g].Entries) != n {
					t.Fatal("boundary memberships lost")
				}
			}
			if wantRows == 20_000 {
				if got.Records[0].Location != "" || got.Records[19_999].Location != "w19999" {
					t.Fatal("boundary row order/root")
				}
				for i, r := range got.Records[1:] {
					if !reflect.DeepEqual(r, bunWorkspaceTestRecord(fmt.Sprintf("w%05d", i+1), absent, absent)) {
						t.Fatal("empty boundary row states")
					}
				}
			}
			if id == "C39" || id == "C47" {
				e := got.Records[0].Requirements[0].Entries
				for i, entry := range e {
					if entry != dep(fmt.Sprintf("x%05d", i), "1") {
						t.Fatal("boundary entry order")
					}
				}
			}
			if id == "C43" || id == "C45" {
				g := 0
				if id == "C45" {
					g = 3
				}
				if len(got.Records[1].Requirements[g].Entries) != 10_000 {
					t.Fatal("second row count")
				}
				if id == "C45" {
					for _, e := range got.Records[0].Requirements[0].Entries {
						if e.State != FieldNull || e.Requirement != "" {
							t.Fatal("null membership lost")
						}
					}
					for _, e := range got.Records[1].Requirements[3].Entries {
						if e.State != FieldInvalidType || e.Requirement != "" {
							t.Fatal("invalid membership lost")
						}
					}
				}
			}
		})
	}
}

func TestProjectBunWorkspacesEmpty(t *testing.T) {
	doc, data := bunWorkspaceTestDocument(t, map[string]any{})
	got, err := ProjectBunWorkspaces(doc)
	if err != nil || got.Records == nil || len(got.Records) != 0 ||
		got.SourceSHA256 != sha256.Sum256(data) {
		t.Fatal("empty owned result missing")
	}
}

func TestProjectBunWorkspacesLocationsGroups(t *testing.T) {
	doc, data := bunWorkspaceTestDocument(t, map[string]any{
		"z": map[string]any{"name": "same"},
		"a": map[string]any{"name": "same"},
		"": map[string]any{
			"name": "same", "version": "", "dependencies": map[string]any{"x": "1"},
			"optionalDependencies": map[string]any{"x": "2"},
		},
	})
	before := append([]byte(nil), data...)
	got, err := ProjectBunWorkspaces(doc)
	if err != nil || len(got.Records) != 3 || got.SourceSHA256 != sha256.Sum256(before) {
		t.Fatal("source/rows missing")
	}
	for i, location := range []string{"", "a", "z"} {
		if got.Records[i].Location != location || got.Records[i].Name !=
			(LockField[string]{State: FieldValue, Value: "same"}) {
			t.Fatal("location sorted/repeated claim lost")
		}
	}
	want := []DependencyGroup{
		{Name: "dependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "x", Requirement: "1", State: FieldValue}}},
		{Name: "devDependencies"},
		{Name: "optionalDependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "x", Requirement: "2", State: FieldValue}}},
		{Name: "peerDependencies"},
	}
	if !reflect.DeepEqual(got.Records[0].Requirements, want) || got.Records[0].Version !=
		(LockField[string]{State: FieldValue}) {
		t.Fatal("groups/empty value conflated")
	}
	if !bytes.Equal(data, before) {
		t.Fatal("input bytes modified")
	}
}

func TestProjectBunWorkspacesFieldStates(t *testing.T) {
	variants := []struct {
		label   string
		present bool
		raw     any
		state   FieldState
		text    string
	}{
		{"absent", false, nil, FieldAbsent, ""}, {"null", true, nil, FieldNull, ""},
		{"empty", true, "", FieldValue, ""}, {"text", true, " Ω\x00\n", FieldValue, " Ω\x00\n"},
		{"number", true, 42, FieldInvalidType, ""}, {"bool", true, false, FieldInvalidType, ""},
		{"array", true, []any{}, FieldInvalidType, ""}, {"object", true, map[string]any{}, FieldInvalidType, ""},
	}
	for _, key := range []string{"name", "version"} {
		for _, v := range variants {
			t.Run(key+"/"+v.label, func(t *testing.T) {
				fields := map[string]any{"dependencies": map[string]any{"x": "1"}}
				if v.present {
					fields[key] = v.raw
				}
				doc, data := bunWorkspaceTestDocument(t, map[string]any{"x": fields})
				n, ver := LockField[string]{}, LockField[string]{}
				if key == "name" {
					n = LockField[string]{State: v.state, Value: v.text}
				} else {
					ver = LockField[string]{State: v.state, Value: v.text}
				}
				bunWorkspaceTestExact(t, doc, data, []BunWorkspaceRecord{bunWorkspaceTestRecord("x", n, ver, DependencyGroup{Name: "dependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "x", Requirement: "1", State: FieldValue}}})})
			})
		}
	}
	groupVariants := []struct {
		label   string
		present bool
		raw     any
		state   FieldState
		entries []DeclaredDependency
	}{
		{"absent", false, nil, FieldAbsent, nil}, {"null", true, nil, FieldNull, nil}, {"empty-object", true, map[string]any{}, FieldValue, []DeclaredDependency{}},
		{"number", true, 42, FieldInvalidType, nil}, {"bool", true, false, FieldInvalidType, nil}, {"array", true, []any{}, FieldInvalidType, nil}, {"string", true, "x", FieldInvalidType, nil},
	}
	for _, key := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		for _, v := range groupVariants {
			t.Run(key+"/"+v.label, func(t *testing.T) {
				fields := map[string]any{"name": "good", "unknown": map[string]any{"unused": true}}
				if v.present {
					fields[key] = v.raw
				}
				doc, data := bunWorkspaceTestDocument(t, map[string]any{"x": fields})
				bunWorkspaceTestExact(t, doc, data, []BunWorkspaceRecord{bunWorkspaceTestRecord("x", LockField[string]{State: FieldValue, Value: "good"}, LockField[string]{}, DependencyGroup{Name: key, State: v.state, Entries: v.entries})})
			})
		}
	}
	for _, v := range variants[1:] {
		t.Run("requirement/"+v.label, func(t *testing.T) {
			doc, data := bunWorkspaceTestDocument(t, map[string]any{"x": map[string]any{"dependencies": map[string]any{"member": v.raw}, "peerDependencies": map[string]any{"good": "kept"}}})
			bunWorkspaceTestExact(t, doc, data, []BunWorkspaceRecord{bunWorkspaceTestRecord("x", LockField[string]{}, LockField[string]{},
				DependencyGroup{Name: "dependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "member", Requirement: v.text, State: v.state}}},
				DependencyGroup{Name: "peerDependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "good", Requirement: "kept", State: FieldValue}}})})
		})
	}
	doc, _ := bunWorkspaceTestDocument(t, map[string]any{
		"": map[string]any{
			"name": nil, "version": false, "dependencies": false,
			"devDependencies": map[string]any{}, "optionalDependencies": nil,
			"peerDependencies": map[string]any{"a": nil, "b": false, "c": ""},
		},
	})
	got, err := ProjectBunWorkspaces(doc)
	if err != nil || len(got.Records) != 1 {
		t.Fatal("usable row missing")
	}
	r := got.Records[0]
	want := []DependencyGroup{
		{Name: "dependencies", State: FieldInvalidType},
		{Name: "devDependencies", State: FieldValue, Entries: []DeclaredDependency{}},
		{Name: "optionalDependencies", State: FieldNull},
		{Name: "peerDependencies", State: FieldValue, Entries: []DeclaredDependency{
			{Name: "a", State: FieldNull}, {Name: "b", State: FieldInvalidType},
			{Name: "c", State: FieldValue},
		}},
	}
	if r.Name != (LockField[string]{State: FieldNull}) || r.Version !=
		(LockField[string]{State: FieldInvalidType}) || !reflect.DeepEqual(r.Requirements, want) {
		t.Fatal("states/usable sibling/nil-empty evidence lost")
	}
}

func TestProjectBunWorkspacesBoundsPrecedence(t *testing.T) {
	for _, n := range []int{10_000, 10_001} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			doc, _ := bunWorkspaceTestDocument(t, map[string]any{
				"a": map[string]any{"dependencies": bunWorkspaceTestMembers(10_000, nil)},
				"z": map[string]any{"peerDependencies": bunWorkspaceTestMembers(n, false)},
			})
			if n == 10_001 {
				bunWorkspaceTestFatal(t, doc, "limit-exceeded")
				return
			}
			got, err := ProjectBunWorkspaces(doc)
			if err != nil || len(got.Records) != 2 ||
				len(got.Records[0].Requirements) != 4 || len(got.Records[1].Requirements) != 4 ||
				len(got.Records[0].Requirements[0].Entries) != 10_000 ||
				len(got.Records[1].Requirements[3].Entries) != 10_000 {
				t.Fatal("unusable memberships not retained/count-bounded")
			}
		})
	}
	t.Run("late-private-shape", func(t *testing.T) {
		doc, _ := bunWorkspaceTestDocument(t, map[string]any{
			"a-private": map[string]any{"name": "synthetic-secret"}, "z-private": map[string]any{},
		})
		doc.Workspaces["z-private"] = json.RawMessage(`null`)
		bunWorkspaceTestFatal(t, doc, "invalid-shape")
	})
}

func TestProjectBunWorkspacesOwnership(t *testing.T) {
	doc, data := bunWorkspaceTestDocument(t, map[string]any{
		"a": map[string]any{"name": "private", "dependencies": map[string]any{"x": "1"}},
		"z": map[string]any{"name": "private", "dependencies": map[string]any{"x": "1"}},
	})
	got, err := ProjectBunWorkspaces(doc)
	if err != nil || len(got.Records) != 2 || len(got.Records[0].Requirements) != 4 ||
		len(got.Records[1].Requirements) != 4 || len(got.Records[0].Requirements[0].Entries) != 1 ||
		len(got.Records[1].Requirements[0].Entries) != 1 {
		t.Fatal("owned evidence missing")
	}
	wantDigest := sha256.Sum256(data)
	clear(data)
	clear(doc.Workspaces["a"])
	clear(doc.Fields["workspaces"])
	delete(doc.Workspaces, "z")
	if got.SourceSHA256 != wantDigest || got.Records[0].Name.Value != "private" ||
		got.Records[1].Name.Value != "private" {
		t.Fatal("raw input aliases typed result")
	}
	got.Records[0].Requirements[0].Entries[0].Requirement = "changed"
	if got.Records[1].Requirements[0].Entries[0].Requirement != "1" {
		t.Fatal("output memberships alias")
	}
}

func TestProjectBunWorkspacesGuards(t *testing.T) {
	for _, mode := range []string{"fields", "workspaces"} {
		t.Run(mode, func(t *testing.T) {
			doc, _ := bunWorkspaceTestDocument(t, map[string]any{})
			if mode == "fields" {
				doc.Fields = nil
			} else {
				doc.Workspaces = nil
			}
			bunWorkspaceTestFatal(t, doc, "invalid-shape")
		})
	}
	t.Run("unused-packages-zero-digest-basic-guard", func(t *testing.T) {
		doc, _ := bunWorkspaceTestDocument(t, map[string]any{})
		doc.Packages, doc.SHA256 = nil, [32]byte{}
		got, err := ProjectBunWorkspaces(doc)
		if err != nil || got.Records == nil || len(got.Records) != 0 ||
			got.SourceSHA256 != ([32]byte{}) {
			t.Fatal("invented package/digest absence guard")
		}
		// A defensive mutated document is not reader-qualified/authenticated evidence.
	})
}

func TestProjectBunWorkspacesPrivacySeparation(t *testing.T) {
	t.Run("sensitive-inert-success", func(t *testing.T) {
		doc, _ := bunWorkspaceTestDocument(t, map[string]any{
			"file:///private\x00\n": map[string]any{
				"name": "synthetic-secret\x00\n", "version": "not-semver",
				"dependencies": map[string]any{"x": "https://synthetic-user:synthetic-secret@private.invalid/path"},
			},
		})
		got, err := ProjectBunWorkspaces(doc)
		if err != nil || len(got.Records) != 1 || len(got.Records[0].Requirements) != 4 ||
			len(got.Records[0].Requirements[0].Entries) != 1 {
			t.Fatal("inert row missing")
		}
		r := got.Records[0]
		if r.Location != "file:///private\x00\n" || r.Name !=
			(LockField[string]{State: FieldValue, Value: "synthetic-secret\x00\n"}) ||
			r.Version != (LockField[string]{State: FieldValue, Value: "not-semver"}) ||
			r.Requirements[0].Entries[0] != (DeclaredDependency{Name: "x", State: FieldValue,
				Requirement: "https://synthetic-user:synthetic-secret@private.invalid/path"}) {
			t.Fatal("sensitive internal evidence interpreted or lost")
		}
	})
	t.Run("owned-source-purity", func(t *testing.T) {
		file, err := parser.ParseFile(token.NewFileSet(), "bunlock_workspaces.go", nil, 0)
		if err != nil {
			t.Fatal("cannot inspect owned source")
		}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || (path != "maps" && path != "slices") {
				t.Fatal("out-of-scope import")
			}
		}
		for _, decl := range file.Decls {
			if d, ok := decl.(*ast.GenDecl); ok && d.Tok == token.VAR {
				t.Fatal("mutable singleton")
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok &&
					(id.Name == "print" || id.Name == "println" || id.Name == "panic") {
					t.Fatal("owned production side effect")
				}
			}
			return true
		})
	})
}
