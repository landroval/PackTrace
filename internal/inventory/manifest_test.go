package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestManifestDeclarationsRetainEvidence(t *testing.T) {
	src := []byte(`{
"name":null,"lockfileVersion":99,
"scripts":{"postinstall":"INERT_TEST_DATA"},
"peerDependenciesMeta":{"shared":{"optional":true}},
"unknown":{"huge":1e10000,"precise":9007199254740993},
"peerDependencies":{"shared":">=4"},
"optionalDependencies":{"shared":"file:../p"},
"devDependencies":{"shared":"~2"},
"dependencies":{"z-workspace":"workspace:*","shared":"^1","a-alias":"npm:real@~2","git":"git+https://example.invalid/r.git#deadbeef","url":"https://example.invalid/p.tgz"}
}`)
	wantDigest := sha256.Sum256(src)
	doc, err := ParseManifest(src)
	if err != nil {
		t.Fatal(err)
	}
	if doc.SHA256 != wantDigest || len(doc.Fields) != 9 ||
		string(doc.Fields["unknown"]) != `{"huge":1e10000,"precise":9007199254740993}` ||
		string(doc.Fields["scripts"]) != `{"postinstall":"INERT_TEST_DATA"}` ||
		string(doc.Fields["peerDependenciesMeta"]) != `{"shared":{"optional":true}}` ||
		string(doc.Fields["name"]) != `null` || string(doc.Fields["lockfileVersion"]) != `99` {
		t.Fatal("raw manifest evidence lost, changed, or interpreted")
	}
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for i := range src {
		src[i] = 'X'
	}
	after, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("manifest aliases caller bytes")
	}
	got, err := ProjectManifest(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := []DependencyGroup{
		{Name: "dependencies", State: FieldValue, Entries: []DeclaredDependency{
			{Name: "a-alias", Requirement: "npm:real@~2", State: FieldValue},
			{Name: "git", Requirement: "git+https://example.invalid/r.git#deadbeef", State: FieldValue},
			{Name: "shared", Requirement: "^1", State: FieldValue},
			{Name: "url", Requirement: "https://example.invalid/p.tgz", State: FieldValue},
			{Name: "z-workspace", Requirement: "workspace:*", State: FieldValue},
		}},
		{Name: "devDependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "shared", Requirement: "~2", State: FieldValue}}},
		{Name: "optionalDependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "shared", Requirement: "file:../p", State: FieldValue}}},
		{Name: "peerDependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "shared", Requirement: ">=4", State: FieldValue}}},
	}
	if got.SourceSHA256 != wantDigest || !reflect.DeepEqual(got.Groups, want) {
		t.Fatal("declarations reordered, resolved, merged, or lost")
	}
	after, err = json.Marshal(doc)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("projection modified raw manifest")
	}
	projectionBefore, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	doc.Fields["dependencies"][2] = 'X'
	delete(doc.Fields, "peerDependencies")
	doc.SHA256[0] ^= 0xff
	projectionAfter, err := json.Marshal(got)
	if err != nil || !bytes.Equal(projectionBefore, projectionAfter) {
		t.Fatal("projection aliases source data")
	}
}

func TestParseManifestRejectsInvalidInput(t *testing.T) {
	cases := []struct{ name, src, code string }{
		{"empty", ``, "invalid-json"},
		{"null", `null`, "invalid-shape"},
		{"array", `[]`, "invalid-shape"},
		{"scalar", `42`, "invalid-shape"},
		{"malformed", `{"secret":`, "invalid-json"},
		{"trailing-document", `{} {}`, "invalid-json"},
		{"trailing-garbage", `{} secret`, "invalid-json"},
		{"duplicate-root", `{"name":"a","name":"b"}`, "duplicate-key"},
		{"escaped-group", `{"dependencies":{},"\u0064ependencies":{}}`, "duplicate-key"},
		{"duplicate-requirement", `{"dependencies":{"s":"1","\u0073":"2"}}`, "duplicate-key"},
		{"duplicate-unknown", `{"unknown":[{"x":1,"x":2}]}`, "duplicate-key"},
		{"high-surrogate", `{"dependencies":{"x":"\uD800"}}`, "invalid-json"},
		{"low-surrogate-key", `{"\udfff":1}`, "invalid-json"},
		{"bad-pair", `{"x":"\uD800\u0041"}`, "invalid-json"},
		{"invalid-utf8", "{\"secret\":\"\xff\"}", "invalid-json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertManifestParseError(t, []byte(tc.src), tc.code)
		})
	}
}

func TestParseManifestBoundaries(t *testing.T) {
	t.Run("size", func(t *testing.T) {
		const limit = 2 << 20
		src := bytes.Repeat([]byte{' '}, limit+1)
		copy(src, `{}`)
		doc, err := ParseManifest(src[:limit])
		if err != nil || doc.Fields == nil || doc.SHA256 != sha256.Sum256(src[:limit]) {
			t.Fatal("exact manifest byte bound rejected", err)
		}
		assertManifestParseError(t, src, "limit-exceeded")
	})
	t.Run("depth", func(t *testing.T) {
		for _, depth := range []int{128, 129} {
			src := []byte(`{"unknown":` + strings.Repeat("[", depth-1) + "0" + strings.Repeat("]", depth-1) + "}")
			if depth == 129 {
				assertManifestParseError(t, src, "limit-exceeded")
			} else if _, err := ParseManifest(src); err != nil {
				t.Fatal("exact depth bound rejected", err)
			}
		}
	})
}

func TestProjectManifestGroupStates(t *testing.T) {
	cases := []struct {
		name, suffix string
		state        FieldState
		nilEntries   bool
	}{
		{"absent", ``, FieldAbsent, true},
		{"null", `,"dependencies":null`, FieldNull, true},
		{"number", `,"dependencies":42`, FieldInvalidType, true},
		{"string", `,"dependencies":"null"`, FieldInvalidType, true},
		{"bool", `,"dependencies":false`, FieldInvalidType, true},
		{"array", `,"dependencies":[]`, FieldInvalidType, true},
		{"empty-object", `,"dependencies":{}`, FieldValue, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := manifestFixture(t, `{"devDependencies":{"kept":"^1"}`+tc.suffix+`}`)
			got, err := ProjectManifest(doc)
			if err != nil || len(got.Groups) != 4 {
				t.Fatal("missing groups", err)
			}
			g := got.Groups[0]
			if g.Name != "dependencies" || g.State != tc.state || len(g.Entries) != 0 || (g.Entries == nil) != tc.nilEntries {
				t.Fatal("group state collapsed")
			}
			wantSibling := DependencyGroup{Name: "devDependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "kept", Requirement: "^1", State: FieldValue}}}
			if !reflect.DeepEqual(got.Groups[1], wantSibling) {
				t.Fatal("bad or absent group erased usable sibling")
			}
		})
	}
}

func TestProjectManifestRequirementStates(t *testing.T) {
	cases := []struct {
		name, raw, value string
		state            FieldState
	}{
		{"empty-string", `""`, "", FieldValue},
		{"range", `"^1"`, "^1", FieldValue},
		{"null", `null`, "", FieldNull},
		{"number", `42`, "", FieldInvalidType},
		{"bool", `false`, "", FieldInvalidType},
		{"array", `[]`, "", FieldInvalidType},
		{"object", `{}`, "", FieldInvalidType},
		{"unicode", `"\ud83d\ude00"`, "😀", FieldValue},
		{"literal-escape", `"\\uD800"`, `\uD800`, FieldValue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := manifestFixture(t, `{"dependencies":{"\u0061":`+tc.raw+`,"z":"usable"}}`)
			got, err := ProjectManifest(doc)
			if err != nil || len(got.Groups) != 4 || len(got.Groups[0].Entries) != 2 {
				t.Fatal("requirement erased its declaration", err)
			}
			entries := got.Groups[0].Entries
			if entries[0] != (DeclaredDependency{Name: "a", Requirement: tc.value, State: tc.state}) ||
				entries[1] != (DeclaredDependency{Name: "z", Requirement: "usable", State: FieldValue}) {
				t.Fatal("requirement coerced or usable sibling changed")
			}
		})
	}
}

func TestProjectManifestEmptyAndNil(t *testing.T) {
	assertManifestProjectionError(t, ManifestDocument{}, "invalid-shape")
	doc := manifestFixture(t, `{}`)
	got, err := ProjectManifest(doc)
	want := []DependencyGroup{{Name: "dependencies"}, {Name: "devDependencies"}, {Name: "optionalDependencies"}, {Name: "peerDependencies"}}
	if err != nil || got.SourceSHA256 != doc.SHA256 || !reflect.DeepEqual(got.Groups, want) {
		t.Fatal("empty manifest must retain four absent groups and source evidence", err)
	}
}

func TestProjectManifestDeclarationLimit(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			var src strings.Builder
			src.WriteByte('{')
			for group, name := range []string{"dependencies", "devDependencies"} {
				if group != 0 {
					src.WriteByte(',')
				}
				fmt.Fprintf(&src, `"%s":{`, name)
				for i := 0; i < 10_000; i++ {
					if i != 0 {
						src.WriteByte(',')
					}
					value := "null"
					if group == 1 {
						value = "42"
					}
					fmt.Fprintf(&src, `"p%05d":%s`, i, value)
				}
				src.WriteByte('}')
			}
			if extra {
				src.WriteString(`,"optionalDependencies":{"one":"*"}`)
			}
			src.WriteByte('}')
			doc := manifestFixture(t, src.String())
			if extra {
				assertManifestProjectionError(t, doc, "limit-exceeded")
				return
			}
			got, err := ProjectManifest(doc)
			if err != nil || len(got.Groups) != 4 || len(got.Groups[0].Entries) != 10_000 || len(got.Groups[1].Entries) != 10_000 {
				t.Fatal("exact bound must count and retain repeated, null, and invalid declarations", err)
			}
			for group, state := range []FieldState{FieldNull, FieldInvalidType} {
				for i, entry := range got.Groups[group].Entries {
					if entry.Name != fmt.Sprintf("p%05d", i) || entry.State != state || entry.Requirement != "" {
						t.Fatal("declarations dropped, reordered, or converted")
					}
				}
			}
		})
	}
}

func manifestFixture(t *testing.T, src string) ManifestDocument {
	t.Helper()
	doc, err := ParseManifest([]byte(src))
	if err != nil {
		t.Fatal("invalid synthetic fixture", err)
	}
	return doc
}

func assertManifestParseError(t *testing.T, src []byte, code string) {
	t.Helper()
	doc, err := ParseManifest(src)
	assertInventoryError(t, err, code)
	if doc.SHA256 != ([32]byte{}) || doc.Fields != nil {
		t.Fatal("parse error returned a partial document")
	}
}

func assertManifestProjectionError(t *testing.T, doc ManifestDocument, code string) {
	t.Helper()
	got, err := ProjectManifest(doc)
	assertInventoryError(t, err, code)
	if got.SourceSHA256 != ([32]byte{}) || got.Groups != nil {
		t.Fatal("projection error returned partial evidence")
	}
}

func assertInventoryError(t *testing.T, err error, code string) {
	t.Helper()
	var parsed *ParseError
	if !errors.As(err, &parsed) || parsed.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	if err.Error() != "inventory: "+code {
		t.Fatal("error must contain only the controlled prefix and category")
	}
}
