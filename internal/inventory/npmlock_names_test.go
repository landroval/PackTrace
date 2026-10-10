package inventory

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func namesProjection(t *testing.T, packages string) NPMLockProjection {
	t.Helper()
	d, e := ParseNPMLock([]byte(`{"lockfileVersion":3,"packages":{` + packages + `}}`))
	if e != nil {
		t.Fatal(e)
	}
	p, e := ProjectNPMLock(d)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestNPMLockNames(t *testing.T) {
	for _, tc := range []struct{ name, location, record, selected, source, qualification string }{
		{"direct", "node_modules/example-package", `{"version":"1.2.3"}`, "example-package", "locator-profile", "installation-claim"},
		{"scoped", "node_modules/@scope/example-package", `{}`, "@scope/example-package", "locator-profile", "installation-claim"},
		{"nested", "node_modules/a/node_modules/@scope/b", `{}`, "@scope/b", "locator-profile", "installation-claim"},
		{"explicit-same", "node_modules/a", `{"name":"a"}`, "a", "record-name", "explicit-claim"},
		{"explicit-alias", "node_modules/alias", `{"name":"real"}`, "real", "record-name", "explicit-claim"},
		{"null-name", "node_modules/a", `{"name":null}`, "", "unavailable", "explicit-unusable"},
		{"empty-name", "node_modules/a", `{"name":""}`, "", "unavailable", "explicit-unusable"},
		{"invalid-name", "node_modules/a", `{"name":4}`, "", "unavailable", "explicit-unusable"},
		{"link", "node_modules/a", `{"link":true}`, "", "unavailable", "link-unqualified"},
		{"null-link", "node_modules/a", `{"link":null}`, "", "unavailable", "link-unqualified"},
		{"invalid-link", "node_modules/a", `{"link":"false"}`, "", "unavailable", "link-unqualified"},
		{"false-link", "node_modules/a", `{"link":false}`, "a", "locator-profile", "installation-claim"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := namesProjection(t, fmt.Sprintf(`%q:%s`, tc.location, tc.record))
			before := fmt.Sprintf("%#v", p)
			got, e := ProjectNPMLockNames(p)
			if e != nil || got.SourceSHA256 != p.SourceSHA256 || len(got.Entries) != 1 || got.Entries[0].Index != 0 || got.Entries[0].Location != tc.location || got.Entries[0].DeclaredName != p.Records[0].Name || got.Entries[0].SelectedName != tc.selected || got.Entries[0].Source != tc.source || got.Entries[0].Qualification != tc.qualification || before != fmt.Sprintf("%#v", p) {
				t.Fatal("name evidence forged/mixed", got, e)
			}
		})
	}
}
func TestNPMLockNameLocatorBoundaries(t *testing.T) {
	for _, loc := range []string{"", "a", "/node_modules/a", "C:/node_modules/a", `node_modules\a`, "node_modules//a", "node_modules/a/", "node_modules/.", "node_modules/..", "node_modules/%61", "node_modules/A", "node_modules/_a", "node_modules/.a", "node_modules/a space", "packages/x/node_modules/a", "node_modules/@scope", "node_modules/@scope/", "node_modules/@scope/a/extra", "node_modules/a/not_modules/b", "node_modules/é", "node_modules/" + strings.Repeat("a", 215)} {
		p := namesProjection(t, fmt.Sprintf(`%q:{}`, loc))
		got, e := ProjectNPMLockNames(p)
		if e != nil || got.Entries[0].SelectedName != "" || got.Entries[0].Qualification != "locator-outside-profile" {
			t.Fatal("unsupported locator inferred", loc, got, e)
		}
	}
	for _, loc := range []string{"node_modules/" + strings.Repeat("a", 214), "node_modules/a-._9", "node_modules/@a/b"} {
		got, e := ProjectNPMLockNames(namesProjection(t, fmt.Sprintf(`%q:{}`, loc)))
		if e != nil || got.Entries[0].Source != "locator-profile" {
			t.Fatal("boundary rejected", e)
		}
	}
}
func TestNPMLockNameDeclarationBlockers(t *testing.T) {
	for _, tc := range []struct{ name, decl, qualification string }{
		{"alias", `{"dependencies":{"a":"npm:real@^1.0.0"}}`, "alias-declaration"},
		{"malformed-alias", `{"dependencies":{"a":" npm:"}}`, "alias-declaration"},
		{"null-requirement", `{"dependencies":{"a":null}}`, "alias-declaration"},
		{"invalid-requirement", `{"dependencies":{"a":3}}`, "alias-declaration"},
		{"null-group", `{"dependencies":null}`, "uninspectable-declarations"},
		{"invalid-group", `{"dependencies":7}`, "uninspectable-declarations"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := namesProjection(t, `"":`+tc.decl+`,"node_modules/a":{},"node_modules/x/node_modules/a":{}`)
			got, e := ProjectNPMLockNames(p)
			if e != nil {
				t.Fatal(e)
			}
			for _, n := range got.Entries {
				if n.Location != "" && (n.SelectedName != "" || n.Qualification != tc.qualification) {
					t.Fatal("alias guessed canonical", n)
				}
			}
			p.Records[1].Name = LockField[string]{State: FieldValue, Value: "real"}
			got, e = ProjectNPMLockNames(p)
			if e != nil || got.Entries[1].SelectedName != "real" {
				t.Fatal("explicit alias target lost")
			}
		})
	}
	got, e := ProjectNPMLockNames(namesProjection(t, `"":{"dependencies":{"other":"npm:real@1"}},"node_modules/a":{}`))
	if e != nil || got.Entries[1].SelectedName != "a" {
		t.Fatal("unrelated key blocked")
	}
}
func TestNPMLockNamesZeroFailureAndIndependence(t *testing.T) {
	got, e := ProjectNPMLockNames(NPMLockProjection{})
	if e == nil || !reflect.DeepEqual(got, NPMLockNames{}) {
		t.Fatal("forged zero accepted")
	}
	p := namesProjection(t, `"node_modules/a":{}`)
	a, e := ProjectNPMLockNames(p)
	if e != nil {
		t.Fatal(e)
	}
	a.Entries[0].SelectedName = "mutated"
	b, e := ProjectNPMLockNames(p)
	if e != nil || b.Entries[0].SelectedName != "a" {
		t.Fatal("shared mutable name state")
	}
}
