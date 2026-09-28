package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseBunLockPreservesFields(t *testing.T) {
	const fixture = `{
// header comment
"lockfileVersion":1,
"configVersion":1,
"workspaces":{
"":{"name":"root-app","dependencies":{"a":"^1.0.0"}},
"packages/a":{"name":"a","version":"1.0.0"},
},
"packages":{
"a":["a@1.0.0","",{},"sha512-synthetic"],
"b":["b@git+https://example.invalid/b.git#abc123",{},"abc123"],
"c":["c@github:owner/repo#abc123",{},"owner-repo-abc123"],
"d":["d@file:./local/d",{}],
"link-e":["link-e@link:packages/e",{}],
"ws-a":["ws-a@workspace:packages/a"],
"root":["root@root:",{}]
},
"overrides":{"x":"1.0.0"},
"catalogs":{"default":{"x":"1.0.0"}},
"trustedDependencies":["a"],
"patchedDependencies":{"a@1.0.0":"patches/a.patch"},
}`

	for _, version := range []string{"0", "1", "2", "3"} {
		t.Run(version, func(t *testing.T) {
			src := []byte(strings.Replace(fixture, `"lockfileVersion":1,`, `"lockfileVersion":`+version+`,`, 1))
			doc, err := ParseBunLock(src)
			if err != nil {
				t.Fatal(err)
			}
			if doc.SHA256 != sha256.Sum256(src) {
				t.Fatal("digest must identify original bytes, not normalized JSON")
			}
			if len(doc.Fields) != 8 {
				t.Fatalf("top-level fields lost or invented: got %d", len(doc.Fields))
			}
			if len(doc.Workspaces) != 2 {
				t.Fatalf("workspace records lost or invented: got %d", len(doc.Workspaces))
			}
			if len(doc.Packages) != 7 {
				t.Fatalf("package records lost or invented: got %d", len(doc.Packages))
			}

			wantFields := map[string]string{
				"configVersion":       `1`,
				"overrides":           `{"x":"1.0.0"}`,
				"catalogs":            `{"default":{"x":"1.0.0"}}`,
				"trustedDependencies": `["a"]`,
				"patchedDependencies": `{"a@1.0.0":"patches/a.patch"}`,
			}
			for key, want := range wantFields {
				if got := string(doc.Fields[key]); got != want {
					t.Errorf("field %s: got %s, want %s", key, got, want)
				}
			}

			wantWorkspaces := map[string]string{
				"":           `{"name":"root-app","dependencies":{"a":"^1.0.0"}}`,
				"packages/a": `{"name":"a","version":"1.0.0"}`,
			}
			for key, want := range wantWorkspaces {
				if got := string(doc.Workspaces[key]); got != want {
					t.Errorf("workspace %q: got %s, want %s", key, got, want)
				}
			}

			wantPackages := map[string]string{
				"a":      `["a@1.0.0","",{},"sha512-synthetic"]`,
				"b":      `["b@git+https://example.invalid/b.git#abc123",{},"abc123"]`,
				"c":      `["c@github:owner/repo#abc123",{},"owner-repo-abc123"]`,
				"d":      `["d@file:./local/d",{}]`,
				"link-e": `["link-e@link:packages/e",{}]`,
				"ws-a":   `["ws-a@workspace:packages/a"]`,
				"root":   `["root@root:",{}]`,
			}
			for key, want := range wantPackages {
				if got := string(doc.Packages[key]); got != want {
					t.Errorf("package %q: got %s, want %s", key, got, want)
				}
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
				t.Fatal("returned raw values alias the caller's mutated bytes")
			}
		})
	}
}

func TestParseBunLockRejectsInvalidDocuments(t *testing.T) {
	cases := []struct{ name, input, code string }{
		{"empty", ``, "invalid-json"},
		{"malformed", `{"secret":`, "invalid-json"},
		{"trailing-document", `{"lockfileVersion":1,"workspaces":{},"packages":{}} {}`, "invalid-json"},
		{"trailing-garbage", `{"lockfileVersion":1,"workspaces":{},"packages":{}} secret`, "invalid-json"},
		{"invalid-jsonc-double-comma", `{"lockfileVersion":1,"workspaces":{},"packages":{},,}`, "invalid-json"},
		{"invalid-jsonc-unterminated-comment", `{"lockfileVersion":1,"workspaces":{},"packages":{}} /* open`, "invalid-json"},
		{"invalid-jsonc-lone-slash", `{"lockfileVersion":1,"workspaces":{},"packages":{}} /`, "invalid-json"},
		{"root-null", `null`, "invalid-shape"},
		{"root-array", `[]`, "invalid-shape"},
		{"root-scalar", `true`, "invalid-shape"},
		{"missing-version", `{"workspaces":{},"packages":{}}`, "invalid-shape"},
		{"string-version", `{"lockfileVersion":"1","workspaces":{},"packages":{}}`, "invalid-shape"},
		{"null-version", `{"lockfileVersion":null,"workspaces":{},"packages":{}}`, "invalid-shape"},
		{"fractional-version", `{"lockfileVersion":1.5,"workspaces":{},"packages":{}}`, "invalid-shape"},
		{"decimal-version", `{"lockfileVersion":1.0,"workspaces":{},"packages":{}}`, "invalid-shape"},
		{"exponent-version", `{"lockfileVersion":1e0,"workspaces":{},"packages":{}}`, "invalid-shape"},
		{"negative-version", `{"lockfileVersion":-1,"workspaces":{},"packages":{}}`, "unsupported-version"},
		{"unsupported-version", `{"lockfileVersion":4,"workspaces":{},"packages":{}}`, "unsupported-version"},
		{"huge-version", `{"lockfileVersion":999999999999999999999999,"workspaces":{},"packages":{}}`, "unsupported-version"},
		{"missing-workspaces", `{"lockfileVersion":1,"packages":{}}`, "invalid-shape"},
		{"null-workspaces", `{"lockfileVersion":1,"workspaces":null,"packages":{}}`, "invalid-shape"},
		{"array-workspaces", `{"lockfileVersion":1,"workspaces":[],"packages":{}}`, "invalid-shape"},
		{"scalar-workspaces", `{"lockfileVersion":1,"workspaces":true,"packages":{}}`, "invalid-shape"},
		{"null-workspace-record", `{"lockfileVersion":1,"workspaces":{"a":null},"packages":{}}`, "invalid-shape"},
		{"array-workspace-record", `{"lockfileVersion":1,"workspaces":{"a":[]},"packages":{}}`, "invalid-shape"},
		{"scalar-workspace-record", `{"lockfileVersion":1,"workspaces":{"a":true},"packages":{}}`, "invalid-shape"},
		{"missing-packages", `{"lockfileVersion":1,"workspaces":{}}`, "invalid-shape"},
		{"null-packages", `{"lockfileVersion":1,"workspaces":{},"packages":null}`, "invalid-shape"},
		{"array-packages", `{"lockfileVersion":1,"workspaces":{},"packages":[]}`, "invalid-shape"},
		{"scalar-packages", `{"lockfileVersion":1,"workspaces":{},"packages":true}`, "invalid-shape"},
		{"null-package-entry", `{"lockfileVersion":1,"workspaces":{},"packages":{"a":null}}`, "invalid-shape"},
		{"object-package-entry", `{"lockfileVersion":1,"workspaces":{},"packages":{"a":{}}}`, "invalid-shape"},
		{"scalar-package-entry", `{"lockfileVersion":1,"workspaces":{},"packages":{"a":true}}`, "invalid-shape"},
		{"duplicate-root", `{"lockfileVersion":1,"workspaces":{},"packages":{},"packages":{}}`, "duplicate-key"},
		{"escaped-duplicate", `{"lockfileVersion":1,"workspaces":{},"packages":{},"\u0070ackages":{}}`, "duplicate-key"},
		{"duplicate-hidden-by-comment", `{"lockfileVersion":1,"workspaces":{},"packages":{},/* dup */"packages":{}}`, "duplicate-key"},
		{"duplicate-workspace-record", `{"lockfileVersion":1,"workspaces":{"a":{},"a":{}},"packages":{}}`, "duplicate-key"},
		{"duplicate-package-record", `{"lockfileVersion":1,"workspaces":{},"packages":{"a":[],"a":[]}}`, "duplicate-key"},
		{"high-surrogate", `{"lockfileVersion":1,"workspaces":{},"packages":{},"secret":"\uD800"}`, "invalid-json"},
		{"low-surrogate", `{"lockfileVersion":1,"workspaces":{},"packages":{},"secret":"\uDFFF"}`, "invalid-json"},
		{"bad-surrogate-pair", `{"lockfileVersion":1,"workspaces":{},"packages":{},"secret":"\uD800A"}`, "invalid-json"},
		{"invalid-utf8", "{\"lockfileVersion\":1,\"workspaces\":{},\"packages\":{},\"secret\":\"\xff\"}", "invalid-json"},
	}
	for _, version := range []string{"0", "1", "2", "3"} {
		for _, tc := range cases {
			t.Run(version+"/"+tc.name, func(t *testing.T) {
				src := strings.Replace(tc.input, `"lockfileVersion":1`, `"lockfileVersion":`+version, 1)
				assertBunParseError(t, []byte(src), tc.code)
			})
		}
	}
}

func TestParseBunLockAcceptsEveryKnownVersion(t *testing.T) {
	for _, version := range []string{"0", "1", "2", "3"} {
		t.Run(version, func(t *testing.T) {
			src := []byte(`{"lockfileVersion":` + version + `,"workspaces":{},"packages":{}}`)
			if _, err := ParseBunLock(src); err != nil {
				t.Fatalf("version %s must be supported: %v", version, err)
			}
		})
	}
}

func TestParseBunLockSizeBoundary(t *testing.T) {
	const limit = 64 << 20
	src := bytes.Repeat([]byte{' '}, limit+1)
	for _, version := range []string{"0", "1", "2", "3"} {
		t.Run(version, func(t *testing.T) {
			copy(src, `{"lockfileVersion":`+version+`,"workspaces":{},"packages":{}}`)
			doc, err := ParseBunLock(src[:limit])
			if err != nil {
				t.Fatal("exact size limit must be accepted", err)
			}
			if len(doc.Workspaces) != 0 || len(doc.Packages) != 0 {
				t.Fatal("empty workspaces and packages must be representable")
			}
			assertBunParseError(t, src, "limit-exceeded")
		})
	}
}

func TestParseBunLockDepthBoundary(t *testing.T) {
	for _, version := range []string{"0", "1", "2", "3"} {
		t.Run(version, func(t *testing.T) {
			for _, depth := range []int{128, 129} {
				src := []byte(`{"lockfileVersion":` + version + `,"workspaces":{},"packages":{},"deep":` +
					strings.Repeat("[", depth-1) + "0" + strings.Repeat("]", depth-1) + "}")
				if depth == 129 {
					assertBunParseError(t, src, "limit-exceeded")
					continue
				}
				if _, err := ParseBunLock(src); err != nil {
					t.Fatal("exact nesting limit must be accepted", err)
				}
			}
		})
	}
}

func assertBunParseError(t *testing.T, src []byte, code string) {
	t.Helper()
	doc, err := ParseBunLock(src)
	var parsed *ParseError
	if !errors.As(err, &parsed) || parsed.Code != code {
		t.Fatalf("want error %s, got %v", code, err)
	}
	if doc.SHA256 != ([32]byte{}) || doc.Fields != nil || doc.Workspaces != nil || doc.Packages != nil {
		t.Fatal("failed parsing returned a partial document")
	}
	if err.Error() != "inventory: "+code {
		t.Fatal("error must contain category only, not input content")
	}
}
