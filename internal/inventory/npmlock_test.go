package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseNPMLockPreservesFields(t *testing.T) {
	const fixture = `
{
  "name":"app", "version":"0.0.0", "lockfileVersion":3, "requires":true,
  "unknown":{"huge":1e10000,"precise":9007199254740993},
  "packages":{
    "":{"name":"app","dependencies":{"a":"^1"}},
    "node_modules/a":{
      "name":"a","version":"1.2.3","resolved":"https://example.invalid/a.tgz",
      "integrity":"sha512-test","dependencies":{"b":"^2"},
      "devDependencies":{"d":"~1"},"optionalDependencies":{"o":"*"},
      "peerDependencies":{"p":">=1"},"peerDependenciesMeta":{"p":{"optional":true}},
      "dev":true,"optional":false,"devOptional":true,"inBundle":false,
      "hasInstallScript":true,"future":null
    },
    "node_modules/a/node_modules/a":{"version":"2.0.0"},
    "node_modules/alias":{"name":"real","version":"2.1.0","resolved":"npm:real@2.1.0"},
    "node_modules/ws":{"link":true,"resolved":"packages/ws"}
  }
}`
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			src := []byte(strings.Replace(fixture, `"lockfileVersion":3`, `"lockfileVersion":`+version, 1))
			doc, err := ParseNPMLock(src)
			if err != nil {
				t.Fatal(err)
			}
			if doc.SHA256 != sha256.Sum256(src) {
				t.Fatal("digest must identify original bytes, not re-encoded JSON")
			}
			if len(doc.Fields) != 6 || len(doc.Packages) != 5 {
				t.Fatal("top-level fields or physical-location records lost")
			}
			if string(doc.Fields["unknown"]) != `{"huge":1e10000,"precise":9007199254740993}` {
				t.Fatal("unknown or precise numeric values changed")
			}
			want := map[string]string{
				"name": `"a"`, "version": `"1.2.3"`, "resolved": `"https://example.invalid/a.tgz"`,
				"integrity": `"sha512-test"`, "dependencies": `{"b":"^2"}`,
				"devDependencies": `{"d":"~1"}`, "optionalDependencies": `{"o":"*"}`,
				"peerDependencies": `{"p":">=1"}`, "peerDependenciesMeta": `{"p":{"optional":true}}`,
				"dev": `true`, "optional": `false`, "devOptional": `true`, "inBundle": `false`,
				"hasInstallScript": `true`, "future": `null`,
			}
			if len(doc.Packages["node_modules/a"]) != len(want) {
				t.Fatal("package fields added or dropped")
			}
			for key, value := range want {
				if string(doc.Packages["node_modules/a"][key]) != value {
					t.Errorf("field %s was not retained", key)
				}
			}
			for path, fields := range map[string]map[string]string{
				"":                              {"name": `"app"`, "dependencies": `{"a":"^1"}`},
				"node_modules/a/node_modules/a": {"version": `"2.0.0"`},
				"node_modules/alias":            {"name": `"real"`, "resolved": `"npm:real@2.1.0"`},
				"node_modules/ws":               {"link": `true`, "resolved": `"packages/ws"`},
			} {
				for field, value := range fields {
					if string(doc.Packages[path][field]) != value {
						t.Errorf("lost field %s in %s", field, path)
					}
				}
			}
			if _, present := doc.Packages["node_modules/a/node_modules/a"]["name"]; present {
				t.Fatal("invented missing name")
			}
			before, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			for i := range src {
				src[i] = 'x'
			}
			after, err := json.Marshal(doc)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("returned data aliases the caller's bytes")
			}
		})
	}
}

func TestParseNPMLockUnicodeAndOpaquePaths(t *testing.T) {
	const fixture = `{"lockfileVersion":3,"packages":{"\ud83d\ude00":{"literal":"\\uD800","text":"\uD83D\uDE00","slash":"\/","quote":"\""},"../outside":{},"/absolute":{},"a/../b":{},"b":{}},"replacement":"\uFFFD"}`
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			src := []byte(strings.Replace(fixture, `"lockfileVersion":3`, `"lockfileVersion":`+version, 1))
			doc, err := ParseNPMLock(src)
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Packages) != 5 || string(doc.Packages["😀"]["literal"]) != `"\\uD800"` {
				t.Fatal("valid Unicode or literal escape altered")
			}
			for _, key := range []string{"../outside", "/absolute", "a/../b", "b"} {
				if _, ok := doc.Packages[key]; !ok {
					t.Fatal("package path normalized instead of retained as opaque evidence")
				}
			}
		})
	}
}

func TestParseNPMLockRejectsInvalidDocuments(t *testing.T) {
	cases := []struct{ name, input, code string }{
		{"empty", ``, "invalid-json"},
		{"malformed", `{"secret":`, "invalid-json"},
		{"trailing-document", `{"lockfileVersion":3,"packages":{}} {}`, "invalid-json"},
		{"trailing-garbage", `{"lockfileVersion":3,"packages":{}} secret`, "invalid-json"},
		{"root-null", `null`, "invalid-shape"},
		{"root-array", `[]`, "invalid-shape"},
		{"root-scalar", `true`, "invalid-shape"},
		{"missing-version", `{"packages":{}}`, "invalid-shape"},
		{"string-version", `{"lockfileVersion":"3","packages":{}}`, "invalid-shape"},
		{"string-v2-version", `{"lockfileVersion":"2","packages":{}}`, "invalid-shape"},
		{"null-version", `{"lockfileVersion":null,"packages":{}}`, "invalid-shape"},
		{"fractional-version", `{"lockfileVersion":3.5,"packages":{}}`, "invalid-shape"},
		{"decimal-version", `{"lockfileVersion":3.0,"packages":{}}`, "invalid-shape"},
		{"exponent-version", `{"lockfileVersion":3e0,"packages":{}}`, "invalid-shape"},
		{"old-version", `{"lockfileVersion":1,"packages":{}}`, "unsupported-version"},
		{"new-version", `{"lockfileVersion":4,"packages":{}}`, "unsupported-version"},
		{"negative-version", `{"lockfileVersion":-3,"packages":{}}`, "unsupported-version"},
		{"huge-version", `{"lockfileVersion":999999999999999999999999,"packages":{}}`, "unsupported-version"},
		{"missing-packages", `{"lockfileVersion":3}`, "invalid-shape"},
		{"null-packages", `{"lockfileVersion":3,"packages":null}`, "invalid-shape"},
		{"array-packages", `{"lockfileVersion":3,"packages":[]}`, "invalid-shape"},
		{"null-record", `{"lockfileVersion":3,"packages":{"secret":null}}`, "invalid-shape"},
		{"array-record", `{"lockfileVersion":3,"packages":{"secret":[]}}`, "invalid-shape"},
		{"scalar-record", `{"lockfileVersion":3,"packages":{"secret":true}}`, "invalid-shape"},
		{"duplicate-root", `{"lockfileVersion":3,"packages":{},"packages":{}}`, "duplicate-key"},
		{"escaped-duplicate", `{"lockfileVersion":3,"packages":{},"\u0070ackages":{}}`, "duplicate-key"},
		{"duplicate-record", `{"lockfileVersion":3,"packages":{"secret":{},"secret":{}}}`, "duplicate-key"},
		{"duplicate-field", `{"lockfileVersion":3,"packages":{"secret":{"x":1,"x":2}}}`, "duplicate-key"},
		{"duplicate-in-array", `{"lockfileVersion":3,"packages":{},"unknown":[{"x":1,"\u0078":2}]}`, "duplicate-key"},
		{"high-surrogate", `{"lockfileVersion":3,"packages":{},"secret":"\uD800"}`, "invalid-json"},
		{"low-surrogate", `{"lockfileVersion":3,"packages":{},"secret":"\uDFFF"}`, "invalid-json"},
		{"bad-surrogate-pair", `{"lockfileVersion":3,"packages":{},"secret":"\uD800\u0041"}`, "invalid-json"},
		{"separated-surrogate", `{"lockfileVersion":3,"packages":{},"secret":"\uD800x\uDC00"}`, "invalid-json"},
		{"surrogate-key", `{"lockfileVersion":3,"packages":{"\uD800":{}}}`, "invalid-json"},
		{"invalid-utf8", "{\"lockfileVersion\":3,\"packages\":{},\"secret\":\"\xff\"}", "invalid-json"},
		{"legacy-no-packages", `{"lockfileVersion":3,"dependencies":{"a":{"version":"1.0.0"}}}`, "invalid-shape"},
		{"legacy-null-packages", `{"lockfileVersion":3,"packages":null,"dependencies":{"a":{"version":"1.0.0"}}}`, "invalid-shape"},
		{"legacy-array-packages", `{"lockfileVersion":3,"packages":[],"dependencies":{"a":{"version":"1.0.0"}}}`, "invalid-shape"},
		{"legacy-duplicate", `{"lockfileVersion":3,"packages":{},"dependencies":{"a":{"dependencies":{"b":{},"\u0062":{}}}}}`, "duplicate-key"},
		{"legacy-surrogate", `{"lockfileVersion":3,"packages":{},"dependencies":{"a":{"version":"\uD800"}}}`, "invalid-json"},
	}
	for _, version := range []string{"2", "3"} {
		for _, tc := range cases {
			t.Run(version+"/"+tc.name, func(t *testing.T) {
				src := strings.Replace(tc.input, `"lockfileVersion":3`, `"lockfileVersion":`+version, 1)
				assertParseError(t, []byte(src), tc.code)
			})
		}
	}
}

func TestParseNPMLockSizeBoundary(t *testing.T) {
	const limit = 64 << 20
	src := bytes.Repeat([]byte{' '}, limit+1)
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			copy(src, `{"lockfileVersion":`+version+`,"packages":{}}`)
			doc, err := ParseNPMLock(src[:limit])
			if err != nil || doc.Packages == nil || len(doc.Packages) != 0 {
				t.Fatal("exact size limit and empty packages must be accepted", err)
			}
			assertParseError(t, src, "limit-exceeded")
		})
	}
}

func TestParseNPMLockDepthBoundary(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			for _, depth := range []int{128, 129} {
				src := []byte(`{"lockfileVersion":` + version + `,"packages":{},"deep":` + strings.Repeat("[", depth-1) + "0" + strings.Repeat("]", depth-1) + "}")
				if depth == 129 {
					assertParseError(t, src, "limit-exceeded")
				} else if _, err := ParseNPMLock(src); err != nil {
					t.Fatal("exact nesting limit must be accepted", err)
				}
			}
		})
	}
}

func TestParseNPMLockV2PreservesLegacy(t *testing.T) {
	const legacy = `{"a":{"version":"9.0.0","resolved":"legacy-source","integrity":"legacy-digest","dependencies":{"b":{"version":"2.0.0"}}},"legacy-only":{"version":"4.0.0"}}`
	src := []byte(`{"lockfileVersion":2,"packages":{"node_modules/a":{"version":"1.0.0","resolved":"package-source","integrity":"package-digest"},"node_modules/packages-only":{}},"dependencies":` + legacy + `}`)
	doc, err := ParseNPMLock(src)
	if err != nil {
		t.Fatal(err)
	}
	if string(doc.Fields["dependencies"]) != legacy {
		t.Fatal("legacy tree changed")
	}
	if len(doc.Packages) != 2 || string(doc.Packages["node_modules/a"]["version"]) != `"1.0.0"` {
		t.Fatal("legacy tree merged into packages")
	}
	if _, ok := doc.Packages["node_modules/packages-only"]; !ok {
		t.Fatal("package-only entry lost")
	}
	if string(doc.Packages["node_modules/a"]["resolved"]) != `"package-source"` ||
		string(doc.Packages["node_modules/a"]["integrity"]) != `"package-digest"` {
		t.Fatal("legacy tree overwrote package evidence")
	}
	if doc.SHA256 != sha256.Sum256(src) {
		t.Fatal("digest changed")
	}
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for i := range src {
		src[i] = 'x'
	}
	after, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("input aliases result")
	}
}

func TestParseNPMLockPreservesOpaqueLegacy(t *testing.T) {
	cases := []struct {
		name, suffix, want string
		present            bool
	}{
		{"absent", ``, ``, false},
		{"null", `,"dependencies":null`, `null`, true},
		{"array", `,"dependencies":[]`, `[]`, true},
		{"number", `,"dependencies":42`, `42`, true},
	}
	for _, version := range []string{"2", "3"} {
		for _, tc := range cases {
			t.Run(version+"/"+tc.name, func(t *testing.T) {
				src := []byte(`{"lockfileVersion":` + version + `,"packages":{}` + tc.suffix + `}`)
				doc, err := ParseNPMLock(src)
				if err != nil {
					t.Fatal(err)
				}
				raw, present := doc.Fields["dependencies"]
				if present != tc.present || string(raw) != tc.want || len(doc.Packages) != 0 {
					t.Fatal("opaque legacy data changed or fabricated package records")
				}
			})
		}
	}
}

func assertParseError(t *testing.T, src []byte, code string) {
	t.Helper()
	doc, err := ParseNPMLock(src)
	var parsed *ParseError
	if !errors.As(err, &parsed) || parsed.Code != code {
		t.Fatalf("want error %s, got %v", code, err)
	}
	if doc.SHA256 != ([32]byte{}) || doc.Fields != nil || doc.Packages != nil {
		t.Fatal("failed parsing returned a partial document")
	}
	if err.Error() != "inventory: "+code {
		t.Fatal("error must contain category only, not input content")
	}
}
