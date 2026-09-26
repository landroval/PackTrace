package intel

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

func TestParseOSVRecordEvidence(t *testing.T) {
	src := []byte(` {
"\u0069d":"TEST-\u0031",
"modified":"2026-01-01T00:00:00Z",
"schema_version":"future",
"published":null,
"withdrawn":"2025-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"npm","name":"synthetic"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}],"versions":["1.0.0"],"ecosystem_specific":{"future":true}}],
"aliases":["TEST-ALIAS"],
"references":[{"type":"WEB","url":"https://example.invalid/not-fetched"}],
"severity":[{"type":"UNKNOWN","score":"uninterpreted"}],
"database_specific":{"future":9007199254740993,"exponent":1e400},
"unicode":"☃\ud83d\ude00",
"future": [ null, false, 1.00 ]
} `)
	original := bytes.Clone(src)
	got, err := ParseOSVRecord(src)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]json.RawMessage
	if err := json.Unmarshal(original, &want); err != nil {
		t.Fatal(err)
	}
	if got.SHA256 != sha256.Sum256(original) || !reflect.DeepEqual(got.Fields, want) {
		t.Fatal("original digest/raw fields changed")
	}
	if string(got.Fields["id"]) != `"TEST-\u0031"` || string(got.Fields["database_specific"]) != `{"future":9007199254740993,"exponent":1e400}` || string(got.Fields["future"]) != `[ null, false, 1.00 ]` {
		t.Fatal("raw spelling/precision/whitespace lost")
	}
	for i := range src {
		src[i] = 'x'
	}
	if got.SHA256 != sha256.Sum256(original) || !reflect.DeepEqual(got.Fields, want) {
		t.Fatal("returned evidence aliases caller bytes")
	}
}

func TestParseOSVRecordUninterpreted(t *testing.T) {
	for _, src := range []string{
		`{"id":"TEST","modified":"not-a-date"}`,
		`{"id":" ","modified":" "}`,
		`{"id":"../not-a-path","modified":"invalid","schema_version":999,"affected":null,"withdrawn":false}`,
		`{"id":"TEST","modified":"invalid","schema_version":null,"affected":false,"aliases":{},"references":"not-a-list"}`,
	} {
		t.Run(src, func(t *testing.T) {
			got, err := ParseOSVRecord([]byte(src))
			var want map[string]json.RawMessage
			if e := json.Unmarshal([]byte(src), &want); e != nil {
				t.Fatal(e)
			}
			if err != nil || got.SHA256 != sha256.Sum256([]byte(src)) || !reflect.DeepEqual(got.Fields, want) {
				t.Fatal("reader performed semantic validation or discarded evidence", err)
			}
		})
	}
}

func TestParseOSVRecordEnvelope(t *testing.T) {
	for _, key := range []string{"id", "modified"} {
		for _, value := range []string{"", `null`, `""`, `false`, `42`, `[]`, `{}`} {
			t.Run(key+"/"+value, func(t *testing.T) {
				fields := map[string]json.RawMessage{"id": json.RawMessage(`"private-marker"`), "modified": json.RawMessage(`"date-text"`)}
				if value == "" {
					delete(fields, key)
				} else {
					fields[key] = json.RawMessage(value)
				}
				src, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				assertOSVError(t, src, "invalid-shape")
			})
		}
	}
}

func TestParseOSVRecordInvalidInput(t *testing.T) {
	cases := []struct{ name, src, code string }{
		{"empty", "", "invalid-json"},
		{"whitespace", " \n\t", "invalid-json"},
		{"empty-object", `{}`, "invalid-shape"},
		{"array", `[]`, "invalid-shape"},
		{"null", `null`, "invalid-shape"},
		{"string", `"private-marker"`, "invalid-shape"},
		{"number", `1e400`, "invalid-shape"},
		{"boolean", `false`, "invalid-shape"},
		{"truncated", `{"id":"private-marker"`, "invalid-json"},
		{"trailing", `{"id":"x","modified":"y"} {}`, "invalid-json"},
		{"garbage", `{"id":"x","modified":"y"} secret`, "invalid-json"},
		{"comment", `{"id":"x","modified":"y"/* comment */}`, "invalid-json"},
		{"comma", `{"id":"x","modified":"y",}`, "invalid-json"},
		{"array-comma", `{"id":"x","modified":"y","extra":[1,]}`, "invalid-json"},
		{"invalid-utf8", "{\"id\":\"\xff\",\"modified\":\"y\"}", "invalid-json"},
		{"bom", "\xef\xbb\xbf{}", "invalid-json"},
		{"duplicate", `{"id":"private-marker","id":"other","modified":"y"}`, "duplicate-key"},
		{"escaped-duplicate", `{"id":"x","\u0069d":"y","modified":"y"}`, "duplicate-key"},
		{"nested-duplicate", `{"id":"x","modified":"y","affected":[{"events":{"fixed":"1","fixed":"2"}}]}`, "duplicate-key"},
		{"high-surrogate", `{"id":"x","modified":"y","extra":"\ud800"}`, "invalid-json"},
		{"low-surrogate", `{"id":"x","modified":"y","extra":"\udc00"}`, "invalid-json"},
		{"wrong-pair", `{"id":"x","modified":"y","extra":"\ud800\u0061"}`, "invalid-json"},
		{"surrogate-key", `{"id":"x","modified":"y","\ud800":1}`, "invalid-json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertOSVError(t, []byte(tc.src), tc.code) })
	}
}

func TestParseOSVRecordLimits(t *testing.T) {
	const base = `{"id":"TEST","modified":"uninterpreted"}`
	t.Run("exact-bytes", func(t *testing.T) {
		src := []byte(base + strings.Repeat(" ", (4<<20)-len(base)))
		if len(src) != 4<<20 {
			t.Fatal("incorrect size fixture")
		}
		got, err := ParseOSVRecord(src)
		if err != nil || got.SHA256 != sha256.Sum256(src) {
			t.Fatal("exact byte bound rejected or whitespace not hashed", err)
		}
	})
	t.Run("over-bytes", func(t *testing.T) {
		src := []byte(base + strings.Repeat(" ", (4<<20)+1-len(base)))
		assertOSVError(t, src, "limit-exceeded")
		src[0] = 0xff // Byte rejection still precedes UTF-8/JSON validation.
		assertOSVError(t, src, "limit-exceeded")
	})
	for _, arrays := range []int{127, 128, 10_001} {
		t.Run(fmt.Sprintf("arrays-%d", arrays), func(t *testing.T) {
			src := []byte(`{"id":"TEST","modified":"x","extra":` + strings.Repeat("[", arrays) + "0" + strings.Repeat("]", arrays) + "}")
			if arrays > 127 {
				assertOSVError(t, src, "limit-exceeded")
				return
			}
			got, err := ParseOSVRecord(src)
			if err != nil || got.SHA256 != sha256.Sum256(src) {
				t.Fatal("128 containers rejected", err)
			}
		})
	}
}

func assertOSVError(t *testing.T, src []byte, code string) {
	t.Helper()
	got, err := ParseOSVRecord(src)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != code || err.Error() != "intel: "+code || !reflect.DeepEqual(got, OSVDocument{}) {
		t.Fatalf("want zero result and %s; got %#v, %v", code, got, err)
	}
}
