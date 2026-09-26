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

func TestProjectNPMLockEvidenceAndOrder(t *testing.T) {
	const fixture = `{"lockfileVersion":3,"unknown":{"keep":9007199254740993},"dependencies":{"same":{"version":"9.0.0"}},"packages":{
"node_modules/z":{"name":"same","version":"1.0.0"},
"packages/ws":{"name":"workspace"},
"node_modules/ws":{"link":true,"resolved":"packages/ws"},
"node_modules/alias":{"name":"real","version":"2.0.0"},
"":{"name":"root"},
"node_modules/a":{"name":"same","version":"1.0.0"},
"../outside":{"version":">=1","resolved":"not-a-validated-url","integrity":"unvalidated-digest"}
}}`
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			src := strings.Replace(fixture, `"lockfileVersion":3`, `"lockfileVersion":`+version, 1)
			doc := parseProjectionInput(t, src)
			before, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ProjectNPMLock(doc)
			if err != nil {
				t.Fatal(err)
			}
			wantLocations := []string{"", "../outside", "node_modules/a", "node_modules/alias", "node_modules/ws", "node_modules/z", "packages/ws"}
			if len(got.Records) != len(wantLocations) {
				t.Fatal("lost, merged, or fabricated records")
			}
			for i, want := range wantLocations {
				if got.Records[i].Location != want {
					t.Fatal("locations must be exact and sorted")
				}
			}
			if got.SourceSHA256 != sha256.Sum256([]byte(src)) {
				t.Fatal("source digest lost")
			}
			if got.Records[0].Name != (LockField[string]{State: FieldValue, Value: "root"}) ||
				got.Records[2].Name.Value != "same" || got.Records[5].Name.Value != "same" ||
				got.Records[3].Name.Value != "real" || got.Records[6].Name.Value != "workspace" {
				t.Fatal("explicit identities changed")
			}
			if got.Records[2].Version.Value != "1.0.0" || got.Records[5].Version.Value != "1.0.0" {
				t.Fatal("legacy version overwrote location-based evidence")
			}
			link := got.Records[4]
			if link.Link != (LockField[bool]{State: FieldValue, Value: true}) ||
				link.Resolved.Value != "packages/ws" || link.Name.State != FieldAbsent || link.Version.State != FieldAbsent {
				t.Fatal("link followed or given an inferred identity")
			}
			odd := got.Records[1]
			if odd.Name.State != FieldAbsent || odd.Version.Value != ">=1" ||
				odd.Resolved.Value != "not-a-validated-url" || odd.Integrity.Value != "unvalidated-digest" {
				t.Fatal("interpreted strings instead of retaining explicit claims")
			}
			after, err := json.Marshal(doc)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("projection modified raw evidence")
			}
			projectionBefore, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			doc.Packages["node_modules/a"]["name"][1] = 'X'
			doc.Packages["node_modules/ws"]["link"] = json.RawMessage(`false`)
			delete(doc.Packages, "packages/ws")
			doc.SHA256[0] ^= 0xff
			projectionAfter, err := json.Marshal(got)
			if err != nil || !bytes.Equal(projectionBefore, projectionAfter) {
				t.Fatal("returned projection aliases input data")
			}
		})
	}
}

func TestProjectNPMLockFieldStates(t *testing.T) {
	cases := []struct {
		name, text, link string
		wantText         LockField[string]
		wantLink         LockField[bool]
	}{
		{"absent", "", "", LockField[string]{State: FieldAbsent}, LockField[bool]{State: FieldAbsent}},
		{"null", `null`, `null`, LockField[string]{State: FieldNull}, LockField[bool]{State: FieldNull}},
		{"empty-false", `""`, `false`, LockField[string]{State: FieldValue}, LockField[bool]{State: FieldValue}},
		{"value-true", `"text"`, `true`, LockField[string]{State: FieldValue, Value: "text"}, LockField[bool]{State: FieldValue, Value: true}},
		{"unicode", `"\ud83d\ude00"`, `true`, LockField[string]{State: FieldValue, Value: "😀"}, LockField[bool]{State: FieldValue, Value: true}},
		{"number-string", `42`, `"false"`, LockField[string]{State: FieldInvalidType}, LockField[bool]{State: FieldInvalidType}},
		{"bool-number", `true`, `0`, LockField[string]{State: FieldInvalidType}, LockField[bool]{State: FieldInvalidType}},
		{"array", `[]`, `[]`, LockField[string]{State: FieldInvalidType}, LockField[bool]{State: FieldInvalidType}},
		{"object", `{}`, `{}`, LockField[string]{State: FieldInvalidType}, LockField[bool]{State: FieldInvalidType}},
	}
	for _, version := range []string{"2", "3"} {
		for _, tc := range cases {
			t.Run(version+"/"+tc.name, func(t *testing.T) {
				fields := ""
				if tc.text != "" {
					fields = fmt.Sprintf(`"name":%s,"version":%s,"resolved":%s,"integrity":%s,"link":%s`, tc.text, tc.text, tc.text, tc.text, tc.link)
				}
				doc := parseProjectionInput(t, `{"lockfileVersion":`+version+`,"packages":{"node_modules/p":{`+fields+`}}}`)
				got, err := ProjectNPMLock(doc)
				if err != nil || len(got.Records) != 1 {
					t.Fatal("field state must not discard its record", err)
				}
				r := got.Records[0]
				if r.Name != tc.wantText || r.Version != tc.wantText || r.Resolved != tc.wantText || r.Integrity != tc.wantText || r.Link != tc.wantLink {
					t.Fatal("field state/value changed or coerced")
				}
			})
		}
	}
}

func TestProjectNPMLockInvalidFieldKeepsSiblings(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			doc := parseProjectionInput(t, `{"lockfileVersion":`+version+`,"packages":{"node_modules/not-an-inferred-name":{"name":42,"version":"1.2.3","resolved":"recorded-source","integrity":"recorded-digest","link":false}}}`)
			got, err := ProjectNPMLock(doc)
			if err != nil || len(got.Records) != 1 {
				t.Fatal("invalid field discarded the record", err)
			}
			r := got.Records[0]
			if r.Name != (LockField[string]{State: FieldInvalidType}) ||
				r.Version != (LockField[string]{State: FieldValue, Value: "1.2.3"}) ||
				r.Resolved != (LockField[string]{State: FieldValue, Value: "recorded-source"}) ||
				r.Integrity != (LockField[string]{State: FieldValue, Value: "recorded-digest"}) ||
				r.Link != (LockField[bool]{State: FieldValue, Value: false}) {
				t.Fatal("invalid name replaced or valid siblings lost")
			}
		})
	}
}

func TestProjectNPMLockEmpty(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			doc := parseProjectionInput(t, `{"lockfileVersion":`+version+`,"packages":{}}`)
			got, err := ProjectNPMLock(doc)
			if err != nil || got.Records == nil || len(got.Records) != 0 || got.SourceSHA256 != doc.SHA256 {
				t.Fatal("empty parsed document must produce an empty evidence-linked slice", err)
			}
		})
	}
}

func TestProjectNPMLockRejectsNilShapes(t *testing.T) {
	cases := []struct {
		name string
		doc  Document
	}{
		{"zero", Document{}},
		{"nil-fields", Document{Packages: map[string]map[string]json.RawMessage{}}},
		{"nil-packages", Document{Fields: map[string]json.RawMessage{}}},
		{"late-nil-record", Document{Fields: map[string]json.RawMessage{}, Packages: map[string]map[string]json.RawMessage{"a-valid": {}, "z-secret-key": nil}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertProjectionError(t, tc.doc, "invalid-shape")
		})
	}
}

func TestProjectNPMLockRecordLimit(t *testing.T) {
	for _, count := range []int{20_000, 20_001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var src strings.Builder
			src.WriteString(`{"lockfileVersion":3,"packages":{"":{}`)
			for i := 1; i < count; i++ {
				fmt.Fprintf(&src, `,"p%05d":{}`, i)
			}
			src.WriteString(`}}`)
			doc := parseProjectionInput(t, src.String())
			if count == 20_001 {
				assertProjectionError(t, doc, "limit-exceeded")
				return
			}
			got, err := ProjectNPMLock(doc)
			if err != nil || len(got.Records) != count {
				t.Fatal("exact record bound must not reject or truncate", err)
			}
			if got.Records[0].Location != "" || got.Records[count-1].Location != "p19999" {
				t.Fatal("root omitted or record order changed")
			}
		})
	}
}

func TestProjectNPMLockRequirements(t *testing.T) {
	const fixture = `{"lockfileVersion":3,"unknown":{"keep":true},"dependencies":{"same":{"version":"99"},"legacy-only":{"version":"9"}},"packages":{
"node_modules/b":{"dependencies":{"same":"~3"},"devDependencies":42},
"packages/ws":{"dependencies":{"local":"workspace:*"}},
"node_modules/ws":{"link":true,"resolved":"packages/ws"},
"node_modules/a":{"name":"a","dependencies":{"same":null,"kept":"*","bad":false},"optionalDependencies":{},"peerDependencies":null,"peerDependenciesMeta":{"same":{"optional":true}}},
"":{"dependencies":{"same":"^1","alias":"npm:real@^2"}}
}}`
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			doc := parseProjectionInput(t, strings.Replace(fixture, `"lockfileVersion":3`, `"lockfileVersion":`+version, 1))
			before, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ProjectNPMLock(doc)
			if err != nil || len(got.Records) != 5 || got.SourceSHA256 != doc.SHA256 {
				t.Fatal("records or evidence lost", err)
			}
			for i, location := range []string{"", "node_modules/a", "node_modules/b", "node_modules/ws", "packages/ws"} {
				r := got.Records[i]
				if r.Location != location || len(r.Requirements) != 4 {
					t.Fatal("four requirement groups per exact sorted location required")
				}
				for j, name := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
					if r.Requirements[j].Name != name {
						t.Fatal("group order changed")
					}
				}
			}
			wantRoot := DependencyGroup{Name: "dependencies", State: FieldValue, Entries: []DeclaredDependency{
				{Name: "alias", Requirement: "npm:real@^2", State: FieldValue},
				{Name: "same", Requirement: "^1", State: FieldValue},
			}}
			if !reflect.DeepEqual(got.Records[0].Requirements[0], wantRoot) {
				t.Fatal("root requirements interpreted or legacy data merged")
			}
			wantA := []DependencyGroup{
				{Name: "dependencies", State: FieldValue, Entries: []DeclaredDependency{
					{Name: "bad", State: FieldInvalidType},
					{Name: "kept", Requirement: "*", State: FieldValue},
					{Name: "same", State: FieldNull},
				}},
				{Name: "devDependencies"},
				{Name: "optionalDependencies", State: FieldValue, Entries: []DeclaredDependency{}},
				{Name: "peerDependencies", State: FieldNull},
			}
			if !reflect.DeepEqual(got.Records[1].Requirements, wantA) || got.Records[1].Name.Value != "a" {
				t.Fatal("field/group state collapsed or usable data erased")
			}
			wantB := []DependencyGroup{
				{Name: "dependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "same", Requirement: "~3", State: FieldValue}}},
				{Name: "devDependencies", State: FieldInvalidType},
				{Name: "optionalDependencies"},
				{Name: "peerDependencies"},
			}
			if !reflect.DeepEqual(got.Records[2].Requirements, wantB) || got.Records[2].Version.State != FieldAbsent {
				t.Fatal("requirements merged across records or resolved into versions")
			}
			absent := []DependencyGroup{{Name: "dependencies"}, {Name: "devDependencies"}, {Name: "optionalDependencies"}, {Name: "peerDependencies"}}
			workspace := DependencyGroup{Name: "dependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "local", Requirement: "workspace:*", State: FieldValue}}}
			if !reflect.DeepEqual(got.Records[3].Requirements, absent) || !got.Records[3].Link.Value ||
				!reflect.DeepEqual(got.Records[4].Requirements[0], workspace) {
				t.Fatal("workspace/link requirements followed, resolved, or invented")
			}
			after, err := json.Marshal(doc)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("raw lockfile changed during projection")
			}
			projectionBefore, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			doc.Packages[""]["dependencies"][2] = 'X'
			doc.Packages["node_modules/a"]["dependencies"] = json.RawMessage(`{}`)
			delete(doc.Fields, "dependencies")
			projectionAfter, err := json.Marshal(got)
			if err != nil || !bytes.Equal(projectionBefore, projectionAfter) {
				t.Fatal("returned requirements alias raw source")
			}
			got.Records[0].Requirements[0].Name = "changed"
			got.Records[0].Requirements[0].Entries[1].Requirement = "changed"
			if !reflect.DeepEqual(got.Records[1].Requirements, wantA) || !reflect.DeepEqual(got.Records[2].Requirements, wantB) {
				t.Fatal("different records share mutable requirement data")
			}
		})
	}
}

func TestProjectNPMLockRequirementsLimit(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			var src strings.Builder
			src.WriteString(`{"lockfileVersion":3,"packages":{`)
			for record, location := range []string{"a", "b", "c"} {
				if record != 0 {
					src.WriteByte(',')
				}
				fmt.Fprintf(&src, `"%s":{`, location)
				groups := []string{"dependencies"}
				if record == 1 {
					groups = []string{"devDependencies", "optionalDependencies"}
				}
				for group, name := range groups {
					if group != 0 {
						src.WriteByte(',')
					}
					fmt.Fprintf(&src, `"%s":{`, name)
					count, value := 10_000, "null"
					if record == 1 {
						count, value = 5_000, "false"
					} else if record == 2 {
						count = 0
						if extra {
							count = 1
						}
					}
					for i := 0; i < count; i++ {
						if i != 0 {
							src.WriteByte(',')
						}
						fmt.Fprintf(&src, `"p%05d":%s`, i, value)
					}
					src.WriteByte('}')
				}
				src.WriteByte('}')
			}
			src.WriteString(`}}`)
			doc := parseProjectionInput(t, src.String())
			if extra {
				assertProjectionError(t, doc, "limit-exceeded")
				return
			}
			got, err := ProjectNPMLock(doc)
			if err != nil || len(got.Records) != 3 {
				t.Fatal("exact requirement bound must succeed", err)
			}
			for _, r := range got.Records {
				if len(r.Requirements) != 4 {
					t.Fatal("per-record groups missing")
				}
			}
			for _, scope := range []struct {
				record, group, count int
				state                FieldState
			}{
				{0, 0, 10_000, FieldNull}, {1, 1, 5_000, FieldInvalidType}, {1, 2, 5_000, FieldInvalidType},
			} {
				entries := got.Records[scope.record].Requirements[scope.group].Entries
				if len(entries) != scope.count {
					t.Fatal("repeated/null/invalid memberships lost or truncated")
				}
				for i, entry := range entries {
					if entry.Name != fmt.Sprintf("p%05d", i) || entry.Requirement != "" || entry.State != scope.state {
						t.Fatal("membership order, value, or state changed")
					}
				}
			}
			last := got.Records[2].Requirements[0]
			if last.State != FieldValue || last.Entries == nil || len(last.Entries) != 0 {
				t.Fatal("zero remaining allowance must still permit empty groups")
			}
		})
	}
}

func parseProjectionInput(t *testing.T, src string) Document {
	t.Helper()
	doc, err := ParseNPMLock([]byte(src))
	if err != nil {
		t.Fatal("invalid synthetic fixture", err)
	}
	return doc
}

func assertProjectionError(t *testing.T, doc Document, code string) {
	t.Helper()
	got, err := ProjectNPMLock(doc)
	var parsed *ParseError
	if !errors.As(err, &parsed) || parsed.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	if got.SourceSHA256 != ([32]byte{}) || got.Records != nil {
		t.Fatal("error returned a partial projection")
	}
	if err.Error() != "inventory: "+code {
		t.Fatal("error leaked source content")
	}
}
