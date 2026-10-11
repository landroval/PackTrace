package intel

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const snapshotTestEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func snapshotTestBase() map[string]any {
	blocks := make([]any, 256)
	for i := range blocks {
		blocks[i] = map[string]any{"index": i, "sha256": snapshotTestEmpty, "bytes": 0, "records": 0}
	}
	return map[string]any{
		"schemaVersion": "1.0", "source": map[string]any{"id": "packtrace-synthetic-i21"},
		"originals": map[string]any{"sha256": snapshotTestEmpty, "bytes": 0, "records": 0}, "blocks": blocks,
	}
}

func snapshotTestBytes(t *testing.T, input map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal("invalid fixture construction")
	}
	return data
}

func snapshotTestRef(input map[string]any, index int) map[string]any {
	if index < 0 {
		return input["originals"].(map[string]any)
	}
	return input["blocks"].([]any)[index].(map[string]any)
}

func snapshotTestPositive(input map[string]any, index int, digest string, size, count uint64) {
	ref := snapshotTestRef(input, index)
	ref["sha256"], ref["bytes"], ref["records"] = strings.Repeat(digest, 64), size, count
}

func TestParseSnapshotManifestExplicitV11(t *testing.T) {
	oneOne := snapshotTestBase()
	oneOne["schemaVersion"] = "1.1"
	data := snapshotTestBytes(t, oneOne)

	got10, err10 := ParseSnapshotManifest(data)
	pe10, ok10 := err10.(*ParseError)
	if !ok10 || pe10.Code != "unsupported-version" ||
		!reflect.DeepEqual(got10, SnapshotManifest{}) {
		t.Fatal("1.0 entry point silently accepted 1.1")
	}

	got11, err11 := ParseSnapshotManifestV11(data)
	if err11 != nil || got11.SchemaVersion != "1.1" ||
		got11.Source.ID != "packtrace-synthetic-i21" || len(got11.Blocks) != 256 {
		t.Fatal("explicit 1.1 manifest result missing")
	}

	oneZero := snapshotTestBase()
	gotWrong, errWrong := ParseSnapshotManifestV11(snapshotTestBytes(t, oneZero))
	peWrong, okWrong := errWrong.(*ParseError)
	if !okWrong || peWrong.Code != "unsupported-version" ||
		!reflect.DeepEqual(gotWrong, SnapshotManifest{}) {
		t.Fatal("1.1 entry point silently accepted 1.0")
	}

	oneOne["unknown"] = json.RawMessage(`{"dup":0,"\u0064up":1}`)
	gotBad, errBad := ParseSnapshotManifestV11(snapshotTestBytes(t, oneOne))
	peBad, okBad := errBad.(*ParseError)
	if !okBad || peBad.Code != "duplicate-key" ||
		!reflect.DeepEqual(gotBad, SnapshotManifest{}) {
		t.Fatal("1.1 bypassed the shared envelope validator")
	}
}

func snapshotTestError(t *testing.T, data []byte, code string) {
	t.Helper()
	got, err := ParseSnapshotManifest(data)
	pe, ok := err.(*ParseError)
	if !ok || pe == nil || pe.Code != code || err.Error() != "intel: "+code || !reflect.DeepEqual(got, SnapshotManifest{}) {
		t.Fatal("missing exact controlled whole-zero error")
	}
}

func snapshotTestSuccess(t *testing.T, data []byte) SnapshotManifest {
	t.Helper()
	before := append([]byte(nil), data...)
	got, err := ParseSnapshotManifest(data)
	if err != nil || got.SchemaVersion != "1.0" || got.Source.ID == "" || len(got.Blocks) != 256 || got.Fields == nil || got.Source.Fields == nil || got.Originals.Fields == nil {
		t.Fatal("complete owned structural result missing")
	}
	if got.SHA256 != sha256.Sum256(before) || !bytes.Equal(data, before) {
		t.Fatal("original bytes/digest changed")
	}
	for i, block := range got.Blocks {
		if block.Index != i || block.Reference.Fields == nil {
			t.Fatal("positional reference missing")
		}
	}
	return got
}

// Each ID pins an independently authored contract example, not an implementation-derived oracle.
func TestParseSnapshotManifestReference(t *testing.T) {
	cases := []struct {
		id, code string
		change   func(map[string]any)
		raw      func([]byte) []byte
	}{
		{"C01", "", nil, nil},
		{"C02", "", func(m map[string]any) {
			m["unknown"] = json.RawMessage(`18446744073709551616000`)
			m["source"].(map[string]any)["extra"] = true
			snapshotTestRef(m, -1)["extra"] = "original"
			snapshotTestRef(m, 0)["extra"] = "block"
		}, nil},
		{"C03", "", nil, func(b []byte) []byte { return append([]byte(" \n"), b...) }},
		{"C04", "", nil, nil},
		{"C05", "", nil, func(b []byte) []byte { return append(b, bytes.Repeat([]byte(" "), (1<<20)-len(b))...) }},
		{"C06", "limit-exceeded", nil, func(b []byte) []byte { return append(b, bytes.Repeat([]byte(" "), (1<<20)+1-len(b))...) }},
		{"C07", "limit-exceeded", func(m map[string]any) {
			m["unknown"] = json.RawMessage(strings.Repeat("[", 128) + "0" + strings.Repeat("]", 128))
		}, nil},
		{"C08", "invalid-json", nil, func(b []byte) []byte { return append(b, []byte("{}")...) }},
		{"C09", "duplicate-key", func(m map[string]any) { m["unknown"] = json.RawMessage(`{"dup":0,"\u0064up":1}`) }, nil},
		{"C10", "invalid-shape", nil, func([]byte) []byte { return []byte("null") }},
		{"C11", "invalid-shape", func(m map[string]any) { delete(m, "schemaVersion") }, nil},
		{"C12", "unsupported-version", func(m map[string]any) { m["schemaVersion"] = "1.0.0" }, nil},
		{"C13", "unsupported-version", func(m map[string]any) { m["schemaVersion"], m["originals"] = "2.0", nil }, nil},
		{"C14", "invalid-shape", func(m map[string]any) { m["source"] = nil }, nil},
		{"C15", "limit-exceeded", func(m map[string]any) { m["source"].(map[string]any)["id"] = strings.Repeat("a", 257) }, nil},
		{"C16", "", func(m map[string]any) { m["source"].(map[string]any)["id"] = " URI://Ω/private " }, nil},
		{"C17", "invalid-shape", func(m map[string]any) { delete(snapshotTestRef(m, -1), "sha256") }, nil},
		{"C18", "invalid-shape", func(m map[string]any) { m["blocks"] = m["blocks"].([]any)[:255] }, nil},
		{"C19", "limit-exceeded", func(m map[string]any) { m["blocks"] = append(m["blocks"].([]any), nil) }, nil},
		{"C20", "invalid-shape", func(m map[string]any) { m["blocks"].([]any)[0] = nil }, nil},
		{"C21", "invalid-shape", func(m map[string]any) { b := m["blocks"].([]any); b[0], b[1] = b[1], b[0] }, nil},
		{"C22", "invalid-shape", func(m map[string]any) { snapshotTestRef(m, -1)["sha256"] = strings.ToUpper(snapshotTestEmpty) }, nil},
		{"C23", "invalid-shape", func(m map[string]any) { snapshotTestRef(m, -1)["bytes"] = json.RawMessage(`-0`) }, nil},
		{"C24", "invalid-json", nil, func(b []byte) []byte { return bytes.Replace(b, []byte(`"bytes":0`), []byte(`"bytes":01`), 1) }},
		{"C25", "limit-exceeded", func(m map[string]any) { snapshotTestRef(m, -1)["bytes"] = json.RawMessage(`18446744073709551616`) }, nil},
		{"C26", "limit-exceeded", func(m map[string]any) { snapshotTestPositive(m, -1, "a", 1, 2_000_001) }, nil},
		{"C27", "limit-exceeded", func(m map[string]any) {
			snapshotTestPositive(m, 0, "a", 1, 1_000_001)
			snapshotTestPositive(m, 1, "b", 1, 1_000_000)
		}, nil},
		{"C28", "limit-exceeded", func(m map[string]any) { snapshotTestPositive(m, 0, "a", (32<<30)+1, 0) }, nil},
		{"C29", "limit-exceeded", func(m map[string]any) {
			snapshotTestPositive(m, 0, "a", 20<<30, 0)
			snapshotTestPositive(m, 1, "b", (12<<30)+1, 0)
		}, nil},
		{"C30", "", func(m map[string]any) {
			snapshotTestPositive(m, 0, "a", 20<<30, 1)
			snapshotTestPositive(m, 1, "a", 20<<30, 1)
		}, nil},
		{"C31", "invalid-shape", func(m map[string]any) { snapshotTestPositive(m, -1, "a", 1, 0); snapshotTestPositive(m, 0, "a", 2, 0) }, nil},
		{"C32", "invalid-shape", func(m map[string]any) { snapshotTestPositive(m, 0, "a", 1, 1); snapshotTestPositive(m, 1, "a", 1, 2) }, nil},
		{"C33", "", func(m map[string]any) { snapshotTestPositive(m, -1, "a", 1, 1); snapshotTestPositive(m, 0, "a", 1, 2) }, nil},
		{"C34", "invalid-shape", func(m map[string]any) { snapshotTestRef(m, -1)["records"] = 1 }, nil},
		{"C35", "", func(m map[string]any) { snapshotTestPositive(m, 0, "a", 1, 0) }, nil},
		{"C36", "", func(m map[string]any) { snapshotTestPositive(m, -1, "a", 1, 3); snapshotTestPositive(m, 0, "b", 1, 1) }, nil},
		{"C37", "", func(m map[string]any) { m["source"].(map[string]any)["acquisitionMethod"] = "import" }, nil},
		{"C38", "", func(m map[string]any) { m["source"].(map[string]any)["lastSuccessfulCheck"] = nil }, nil},
		{"C39", "", func(m map[string]any) { m["source"].(map[string]any)["lastSuccessfulCheck"] = "2026-10-02T00:00:00Z" }, nil},
		{"C40", "", func(m map[string]any) { m["source"].(map[string]any)["lastSuccessfulCheck"] = "0001-01-01T00:00:00Z" }, nil},
		{"C41", "", func(m map[string]any) {
			m["source"].(map[string]any)["lastSuccessfulCheck"] = "2026-10-02T00:00:00.1234567890Z"
		}, nil},
		{"C42", "", func(m map[string]any) {
			s := m["source"].(map[string]any)
			s["lastSuccessfulCheck"], s["lastFullReconciliation"] = "2026-01-01T00:00:00Z", "2026-10-02T00:00:00Z"
		}, nil},
		{"C43", "", func(m map[string]any) { m["source"].(map[string]any)["lastSuccessfulCheck"] = "2099-01-01T00:00:00Z" }, nil},
		{"C44", "", func(m map[string]any) {
			s := m["source"].(map[string]any)
			s["lastSuccessfulCheck"], s["lastFullReconciliation"], s["acquiredAt"], s["acquisitionMethod"] = "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "import"
		}, nil},
		{"C45", "", func(m map[string]any) {
			m["source"].(map[string]any)["locator"] = "https://synthetic-user:synthetic-secret@private.invalid/path\x00\n"
		}, nil},
		{"C46", "invalid-shape", func(m map[string]any) {
			s := m["source"].(map[string]any)
			s["lastSuccessfulCheck"] = "private-marker"
			snapshotTestRef(m, -1)["bytes"] = "private-marker"
		}, nil},
		{"C47", "", func(m map[string]any) {
			snapshotTestPositive(m, 0, "a", 1, 0)
			snapshotTestRef(m, 0)["path"] = "file:///missing/private/target"
		}, nil},
		{"C48", "", func(m map[string]any) {
			m["activate"], m["fresh"], m["coverage"] = true, true, map[string]any{"complete": true}
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			input := snapshotTestBase()
			if tc.change != nil {
				tc.change(input)
			}
			data := snapshotTestBytes(t, input)
			if tc.raw != nil {
				data = tc.raw(data)
			}
			if tc.code != "" {
				snapshotTestError(t, data, tc.code)
				return
			}
			got := snapshotTestSuccess(t, data)
			if tc.id == "C02" && (string(got.Fields["unknown"]) != "18446744073709551616000" || string(got.Source.Fields["extra"]) != "true" || string(got.Originals.Fields["extra"]) != `"original"` || string(got.Blocks[0].Reference.Fields["extra"]) != `"block"`) {
				t.Fatal("unknown precision/nested evidence lost")
			}
			if tc.id == "C16" && got.Source.ID != " URI://Ω/private " {
				t.Fatal("source ID normalized")
			}
			if tc.id == "C30" && (got.Blocks[0].Reference.Bytes != 20<<30 || got.Blocks[1].Reference.Records != 1) {
				t.Fatal("shared claims lost")
			}
		})
	}
}

func TestParseSnapshotManifestEnvelope(t *testing.T) {
	for _, n := range []int{127, 128} {
		t.Run("depth-"+strconv.Itoa(n+1), func(t *testing.T) {
			m := snapshotTestBase()
			m["unknown"] = json.RawMessage(strings.Repeat("[", n) + "0" + strings.Repeat("]", n))
			data := snapshotTestBytes(t, m)
			if n == 127 {
				snapshotTestSuccess(t, data)
			} else {
				snapshotTestError(t, data, "limit-exceeded")
			}
		})
	}
	for name, raw := range map[string][]byte{"utf8": {0xff}, "surrogate": []byte(`{"x":"\ud800"}`), "malformed": []byte("{"), "array": []byte("[]"), "number": []byte("1")} {
		t.Run(name, func(t *testing.T) {
			code := "invalid-json"
			if name == "array" || name == "number" {
				code = "invalid-shape"
			}
			snapshotTestError(t, raw, code)
		})
	}
	for _, place := range []string{"root", "source", "originals", "block"} {
		t.Run("duplicate-"+place, func(t *testing.T) {
			m := snapshotTestBase()
			bad := json.RawMessage(`{"dup":0,"\u0064up":1}`)
			switch place {
			case "root":
				m["extra"] = bad
			case "source":
				m["source"].(map[string]any)["extra"] = bad
			case "originals":
				snapshotTestRef(m, -1)["extra"] = bad
			case "block":
				snapshotTestRef(m, 255)["extra"] = bad
			}
			m["schemaVersion"] = "2.0"
			snapshotTestError(t, snapshotTestBytes(t, m), "duplicate-key")
		})
	}
	for _, v := range []any{nil, false, 1, ""} {
		t.Run("bad-schema-"+strconv.Itoa(len(snapshotTestBytes(t, map[string]any{"v": v}))), func(t *testing.T) {
			m := snapshotTestBase()
			m["schemaVersion"] = v
			snapshotTestError(t, snapshotTestBytes(t, m), "invalid-shape")
		})
	}
	for _, v := range []string{"1", "01.0", "1.0.0", "1.1", "2.0", "1.0\n"} {
		t.Run("schema-"+v, func(t *testing.T) {
			m := snapshotTestBase()
			m["schemaVersion"] = v
			m["originals"] = nil
			snapshotTestError(t, snapshotTestBytes(t, m), "unsupported-version")
		})
	}
}

func TestParseSnapshotManifestCore(t *testing.T) {
	for _, field := range []string{"source", "originals", "blocks"} {
		t.Run("missing-"+field, func(t *testing.T) {
			m := snapshotTestBase()
			delete(m, field)
			snapshotTestError(t, snapshotTestBytes(t, m), "invalid-shape")
		})
	}
	t.Run("missing-source-id", func(t *testing.T) {
		m := snapshotTestBase()
		delete(m["source"].(map[string]any), "id")
		snapshotTestError(t, snapshotTestBytes(t, m), "invalid-shape")
	})
	for _, id := range []string{strings.Repeat("a", 256), strings.Repeat("é", 128), " Ω/path ", "http://private.invalid"} {
		t.Run("id-valid-"+strconv.Itoa(len(id)), func(t *testing.T) {
			m := snapshotTestBase()
			m["source"].(map[string]any)["id"] = id
			got := snapshotTestSuccess(t, snapshotTestBytes(t, m))
			if got.Source.ID != id {
				t.Fatal("id altered")
			}
		})
	}
	for _, id := range []any{nil, 1, "", "nul\x00", strings.Repeat("é", 128) + "a"} {
		t.Run("id-invalid-"+strconv.Itoa(len(snapshotTestBytes(t, map[string]any{"v": id}))), func(t *testing.T) {
			m := snapshotTestBase()
			m["source"].(map[string]any)["id"] = id
			code := "invalid-shape"
			if id == strings.Repeat("é", 128)+"a" {
				code = "limit-exceeded"
			}
			snapshotTestError(t, snapshotTestBytes(t, m), code)
		})
	}
	for _, location := range []string{"source", "originals", "blocks"} {
		for j, v := range []any{nil, false, "text", 1} {
			t.Run(location+"-shape-"+strconv.Itoa(j), func(t *testing.T) {
				m := snapshotTestBase()
				m[location] = v
				snapshotTestError(t, snapshotTestBytes(t, m), "invalid-shape")
				if location == "blocks" {
					m = snapshotTestBase()
					m["blocks"].([]any)[255] = v
					snapshotTestError(t, snapshotTestBytes(t, m), "invalid-shape")
				}
			})
		}
	}
	for _, index := range []int{-1, 0, 255} {
		for _, field := range []string{"sha256", "bytes", "records"} {
			for j, v := range []any{nil, false, map[string]any{}} {
				t.Run("type-"+strconv.Itoa(index)+field+strconv.Itoa(j), func(t *testing.T) {
					m := snapshotTestBase()
					snapshotTestRef(m, index)[field] = v
					snapshotTestError(t, snapshotTestBytes(t, m), "invalid-shape")
				})
			}
			t.Run("missing-"+strconv.Itoa(index)+field, func(t *testing.T) {
				m := snapshotTestBase()
				delete(snapshotTestRef(m, index), field)
				snapshotTestError(t, snapshotTestBytes(t, m), "invalid-shape")
			})
		}
		for j, d := range []string{strings.ToUpper(snapshotTestEmpty), strings.Repeat("a", 63), strings.Repeat("a", 65), "0x" + strings.Repeat("a", 64), strings.Repeat("g", 64), " " + snapshotTestEmpty, snapshotTestEmpty + "\n"} {
			t.Run("digest-"+strconv.Itoa(index)+"-"+strconv.Itoa(j), func(t *testing.T) {
				m := snapshotTestBase()
				snapshotTestRef(m, index)["sha256"] = d
				snapshotTestError(t, snapshotTestBytes(t, m), "invalid-shape")
			})
		}
		for _, field := range []string{"bytes", "records"} {
			for j, n := range []string{`-0`, `-1`, `1.0`, `1e0`, `"1"`, `true`, `null`} {
				t.Run("integer-"+strconv.Itoa(index)+field+strconv.Itoa(j), func(t *testing.T) {
					m := snapshotTestBase()
					snapshotTestRef(m, index)[field] = json.RawMessage(n)
					snapshotTestError(t, snapshotTestBytes(t, m), "invalid-shape")
				})
			}
			t.Run("huge-"+strconv.Itoa(index)+field, func(t *testing.T) {
				m := snapshotTestBase()
				snapshotTestRef(m, index)[field] = json.RawMessage(`18446744073709551616`)
				snapshotTestError(t, snapshotTestBytes(t, m), "limit-exceeded")
			})
		}
	}
	for j, v := range []any{nil, false, "0", json.RawMessage(`-0`), json.RawMessage(`-1`), json.RawMessage(`0.0`), json.RawMessage(`0e0`), json.RawMessage(`18446744073709551616`), 1, 256} {
		t.Run("index-"+strconv.Itoa(j), func(t *testing.T) {
			m := snapshotTestBase()
			snapshotTestRef(m, 0)["index"] = v
			snapshotTestError(t, snapshotTestBytes(t, m), "invalid-shape")
		})
	}
	t.Run("missing-index", func(t *testing.T) {
		m := snapshotTestBase()
		delete(snapshotTestRef(m, 0), "index")
		snapshotTestError(t, snapshotTestBytes(t, m), "invalid-shape")
	})
}

func TestParseSnapshotManifestLimitsSharing(t *testing.T) {
	cases := []struct {
		name, code string
		edit       func(map[string]any)
	}{
		{"original-limit", "", func(m map[string]any) { snapshotTestPositive(m, -1, "a", 1, 2_000_000) }},
		{"logical-limit", "", func(m map[string]any) {
			snapshotTestPositive(m, 0, "a", 1, 1_000_000)
			snapshotTestPositive(m, 1, "b", 1, 1_000_000)
		}},
		{"single-size", "", func(m map[string]any) { snapshotTestPositive(m, 0, "a", 32<<30, 0) }},
		{"aggregate-size", "", func(m map[string]any) {
			snapshotTestPositive(m, 0, "a", 20<<30, 0)
			snapshotTestPositive(m, 1, "b", 12<<30, 0)
		}},
		{"repeated-logical-limit", "", func(m map[string]any) {
			for i := 0; i < 4; i++ {
				snapshotTestPositive(m, i, "a", 1, 500_000)
			}
		}},
		{"repeated-logical-excess", "limit-exceeded", func(m map[string]any) {
			for i := 0; i < 5; i++ {
				snapshotTestPositive(m, i, "a", 1, 500_000)
			}
		}},
		{"cross-role-count", "", func(m map[string]any) { snapshotTestPositive(m, -1, "a", 1, 1); snapshotTestPositive(m, 0, "a", 1, 2) }},
		{"cross-role-length", "invalid-shape", func(m map[string]any) { snapshotTestPositive(m, -1, "a", 1, 0); snapshotTestPositive(m, 0, "a", 2, 0) }},
		{"block-length", "invalid-shape", func(m map[string]any) { snapshotTestPositive(m, 0, "a", 1, 0); snapshotTestPositive(m, 1, "a", 2, 0) }},
		{"block-count", "invalid-shape", func(m map[string]any) { snapshotTestPositive(m, 0, "a", 1, 1); snapshotTestPositive(m, 1, "a", 1, 2) }},
		{"empty-digest", "invalid-shape", func(m map[string]any) { snapshotTestPositive(m, -1, "a", 0, 0) }},
		{"empty-count", "invalid-shape", func(m map[string]any) { snapshotTestRef(m, -1)["records"] = 1 }},
		{"positive-zero-count", "", func(m map[string]any) { snapshotTestPositive(m, -1, "a", 1, 0) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := snapshotTestBase()
			tc.edit(m)
			data := snapshotTestBytes(t, m)
			if tc.code != "" {
				snapshotTestError(t, data, tc.code)
			} else {
				snapshotTestSuccess(t, data)
			}
		})
	}
}

func TestParseSnapshotManifestClaims(t *testing.T) {
	for _, field := range []string{"locator", "acquisitionMethod", "attribution"} {
		for j, tc := range []struct {
			v    any
			want OSVString
		}{{nil, OSVString{State: OSVFieldNull}}, {false, OSVString{State: OSVFieldInvalidType}}, {"", OSVString{State: OSVFieldValue}}, {"import", OSVString{State: OSVFieldValue, Value: "import"}}, {"synthetic-secret\x00\n/private", OSVString{State: OSVFieldValue, Value: "synthetic-secret\x00\n/private"}}} {
			t.Run(field+strconv.Itoa(j), func(t *testing.T) {
				m := snapshotTestBase()
				m["source"].(map[string]any)[field] = tc.v
				got := snapshotTestSuccess(t, snapshotTestBytes(t, m))
				values := map[string]OSVString{"locator": got.Source.Locator, "acquisitionMethod": got.Source.AcquisitionMethod, "attribution": got.Source.Attribution}
				if values[field] != tc.want {
					t.Fatal("string claim lost")
				}
			})
		}
		t.Run(field+"absent", func(t *testing.T) {
			got := snapshotTestSuccess(t, snapshotTestBytes(t, snapshotTestBase()))
			values := map[string]OSVString{"locator": got.Source.Locator, "acquisitionMethod": got.Source.AcquisitionMethod, "attribution": got.Source.Attribution}
			if values[field] != (OSVString{State: OSVFieldAbsent}) {
				t.Fatal("absent became unavailable")
			}
		})
	}
	times := []struct {
		text  string
		state TimestampState
		value time.Time
	}{
		{"", TimestampUninterpretable, time.Time{}}, {"2026-10-02", TimestampUninterpretable, time.Time{}}, {" 2026-10-02T00:00:00Z", TimestampUninterpretable, time.Time{}}, {"2026-10-02T00:00:00Z\n", TimestampUninterpretable, time.Time{}}, {"2026-10-02t00:00:00z", TimestampUninterpretable, time.Time{}},
		{"2026-10-02T02:30:00+02:30", TimestampValue, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)},
		{"2026-10-02T00:00:00.1200Z", TimestampValue, time.Date(2026, 10, 2, 0, 0, 0, 120_000_000, time.UTC)},
		{"2026-10-02T00:00:00.123456789Z", TimestampValue, time.Date(2026, 10, 2, 0, 0, 0, 123456789, time.UTC)},
		{"2026-10-02T00:00:00-00:00", TimestampValue, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)},
		{"0000-01-01T00:00:00Z", TimestampValue, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"0001-01-01T00:00:00Z", TimestampValue, time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"2099-01-01T00:00:00Z", TimestampValue, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"2026-10-02T00:00:00.1234567890Z", TimestampUninterpretable, time.Time{}}, {"2016-12-31T23:59:60Z", TimestampUninterpretable, time.Time{}}, {"2023-02-29T00:00:00Z", TimestampUninterpretable, time.Time{}}, {"2026-10-02T00:00:00+24:00", TimestampUninterpretable, time.Time{}}, {"0000-01-01T00:00:00+00:01", TimestampUninterpretable, time.Time{}}, {"9999-12-31T23:59:59-00:01", TimestampUninterpretable, time.Time{}},
	}
	for _, field := range []string{"acquiredAt", "exportedAt", "lastSuccessfulCheck", "lastFullReconciliation"} {
		for j, tc := range times {
			t.Run(field+strconv.Itoa(j), func(t *testing.T) {
				m := snapshotTestBase()
				m["source"].(map[string]any)[field] = tc.text
				got := snapshotTestSuccess(t, snapshotTestBytes(t, m))
				values := []OSVTimestamp{got.Source.AcquiredAt, got.Source.ExportedAt, got.Source.LastSuccessfulCheck, got.Source.LastFullReconciliation}
				var value OSVTimestamp
				switch field {
				case "acquiredAt":
					value = values[0]
				case "exportedAt":
					value = values[1]
				case "lastSuccessfulCheck":
					value = values[2]
				default:
					value = values[3]
				}
				if value.State != tc.state || value.Text != tc.text || !value.Value.Equal(tc.value) || (tc.state == TimestampValue && value.Value.Location() != time.UTC) {
					t.Fatal("exact temporal claim/UTC lost")
				}
			})
		}
		for j, tc := range []struct {
			v     any
			state TimestampState
		}{{nil, TimestampNull}, {false, TimestampInvalidType}, {map[string]any{}, TimestampInvalidType}} {
			t.Run(field+"type"+strconv.Itoa(j), func(t *testing.T) {
				m := snapshotTestBase()
				m["source"].(map[string]any)[field] = tc.v
				got := snapshotTestSuccess(t, snapshotTestBytes(t, m))
				values := map[string]OSVTimestamp{"acquiredAt": got.Source.AcquiredAt, "exportedAt": got.Source.ExportedAt, "lastSuccessfulCheck": got.Source.LastSuccessfulCheck, "lastFullReconciliation": got.Source.LastFullReconciliation}
				if values[field].State != tc.state || values[field].Text != "" || !values[field].Value.IsZero() {
					t.Fatal("unusable claim state lost")
				}
			})
		}
		t.Run(field+"absent", func(t *testing.T) {
			got := snapshotTestSuccess(t, snapshotTestBytes(t, snapshotTestBase()))
			values := map[string]OSVTimestamp{"acquiredAt": got.Source.AcquiredAt, "exportedAt": got.Source.ExportedAt, "lastSuccessfulCheck": got.Source.LastSuccessfulCheck, "lastFullReconciliation": got.Source.LastFullReconciliation}
			if !reflect.DeepEqual(values[field], OSVTimestamp{State: TimestampAbsent}) {
				t.Fatal("absent time fabricated")
			}
		})
	}
	for _, method := range []string{"import", "copy", "failed", "unknown"} {
		t.Run("preserve-"+method, func(t *testing.T) {
			m := snapshotTestBase()
			s := m["source"].(map[string]any)
			s["acquisitionMethod"], s["acquiredAt"], s["exportedAt"], s["lastSuccessfulCheck"], s["lastFullReconciliation"] = method, "2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "2026-10-02T02:30:00+02:30"
			got := snapshotTestSuccess(t, snapshotTestBytes(t, m))
			if got.Source.LastSuccessfulCheck.State != TimestampValue || got.Source.LastSuccessfulCheck.Text != "0001-01-01T00:00:00Z" || !got.Source.LastSuccessfulCheck.Value.IsZero() || got.Source.LastFullReconciliation.Text != "2026-10-02T02:30:00+02:30" {
				t.Fatal("original check/reconciliation renewed or chronologically repaired")
			}
		})
	}
}

func TestParseSnapshotManifestOwnership(t *testing.T) {
	for _, actor := range []string{"input", "root-source", "root-originals", "root-blocks", "nested-source", "original-digest", "block-digest", "typed"} {
		t.Run(actor, func(t *testing.T) {
			m := snapshotTestBase()
			m["unknown"] = json.RawMessage(`18446744073709551616000`)
			data := snapshotTestBytes(t, m)
			original := append([]byte(nil), data...)
			got := snapshotTestSuccess(t, data)
			rootSource := append([]byte(nil), got.Fields["source"]...)
			sourceID := append([]byte(nil), got.Source.Fields["id"]...)
			orig := append([]byte(nil), got.Originals.Fields["sha256"]...)
			sibling := append([]byte(nil), got.Blocks[1].Reference.Fields["sha256"]...)
			typedSHA := got.Originals.SHA256
			switch actor {
			case "input":
				clear(data)
			case "root-source":
				clear(got.Fields["source"])
			case "root-originals":
				clear(got.Fields["originals"])
			case "root-blocks":
				clear(got.Fields["blocks"])
			case "nested-source":
				clear(got.Source.Fields["id"])
			case "original-digest":
				clear(got.Originals.Fields["sha256"])
			case "block-digest":
				clear(got.Blocks[0].Reference.Fields["sha256"])
			case "typed":
				got.Blocks[0].Reference.Records = 99
			}
			if got.Source.ID != "packtrace-synthetic-i21" || got.Originals.SHA256 != typedSHA || !bytes.Equal(got.Blocks[1].Reference.Fields["sha256"], sibling) || got.Blocks[1].Reference.Records != 0 || string(got.Fields["unknown"]) != "18446744073709551616000" {
				t.Fatal("typed/sibling/unknown evidence aliases mutation")
			}
			if actor != "nested-source" && !bytes.Equal(got.Source.Fields["id"], sourceID) {
				t.Fatal("parent or input aliases source fields")
			}
			if actor != "original-digest" && !bytes.Equal(got.Originals.Fields["sha256"], orig) {
				t.Fatal("parent aliases originals")
			}
			if actor != "root-source" && !bytes.Equal(got.Fields["source"], rootSource) {
				t.Fatal("nested source aliases parent")
			}
			fresh := snapshotTestSuccess(t, original)
			if fresh.Source.ID != "packtrace-synthetic-i21" || fresh.Blocks[0].Reference.Records != 0 {
				t.Fatal("calls share mutable data")
			}
		})
	}
	t.Run("byte-identity", func(t *testing.T) {
		data := snapshotTestBytes(t, snapshotTestBase())
		a := snapshotTestSuccess(t, data)
		b := snapshotTestSuccess(t, append([]byte(" \n"), data...))
		if a.SHA256 == b.SHA256 {
			t.Fatal("manifest silently canonicalized")
		}
		reordered := bytes.Replace(data,
			[]byte(`{"bytes":0,"records":0,"sha256":"`+snapshotTestEmpty+`"}`),
			[]byte(`{"sha256":"`+snapshotTestEmpty+`","records":0,"bytes":0}`), 1)
		c := snapshotTestSuccess(t, reordered)
		if bytes.Equal(data, reordered) || a.SHA256 == c.SHA256 || !reflect.DeepEqual(a.Originals, c.Originals) {
			t.Fatal("original reference order lost byte identity or changed typed evidence")
		}
	})
}

func TestParseSnapshotManifestPrecedencePrivacySeparation(t *testing.T) {
	cases := []struct {
		name, code string
		edit       func(map[string]any)
	}{
		{"original-before-list", "invalid-shape", func(m map[string]any) { m["originals"] = nil; m["blocks"] = append(m["blocks"].([]any), nil) }},
		{"id-before-size", "invalid-shape", func(m map[string]any) { m["source"].(map[string]any)["id"] = strings.Repeat("a", 300) + "\x00" }},
		{"index-before-digest", "invalid-shape", func(m map[string]any) { r := snapshotTestRef(m, 0); r["index"], r["sha256"] = 1, "bad" }},
		{"digest-before-bytes", "invalid-shape", func(m map[string]any) {
			r := snapshotTestRef(m, 0)
			r["sha256"], r["bytes"] = "bad", json.RawMessage(`18446744073709551616`)
		}},
		{"bytes-before-records", "limit-exceeded", func(m map[string]any) {
			r := snapshotTestRef(m, 0)
			r["bytes"], r["records"] = json.RawMessage(`18446744073709551616`), "private-marker"
		}},
		{"records-before-empty", "limit-exceeded", func(m map[string]any) { snapshotTestRef(m, 0)["records"] = 2_000_001 }},
		{"conflict-before-cumulative", "invalid-shape", func(m map[string]any) {
			snapshotTestPositive(m, 0, "a", 32<<30, 1_000_000)
			snapshotTestPositive(m, 1, "a", 1, 1_000_001)
		}},
		{"core-before-claims", "invalid-shape", func(m map[string]any) {
			s := m["source"].(map[string]any)
			s["locator"], s["lastSuccessfulCheck"] = "private-marker", "private-marker"
			snapshotTestRef(m, 255)["records"] = "private-marker"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := snapshotTestBase()
			tc.edit(m)
			snapshotTestError(t, snapshotTestBytes(t, m), tc.code)
		})
	}
	t.Run("inert-claims", func(t *testing.T) {
		m := snapshotTestBase()
		m["activate"], m["fresh"], m["complete"] = true, true, true
		m["source"].(map[string]any)["locator"] = "file:///not-authorized-target"
		got := snapshotTestSuccess(t, snapshotTestBytes(t, m))
		if got.Source.Locator != (OSVString{State: OSVFieldValue, Value: "file:///not-authorized-target"}) || string(got.Fields["activate"]) != "true" {
			t.Fatal("inert data lost")
		}
	})
	t.Run("owned-source-purity", func(t *testing.T) {
		file, err := parser.ParseFile(token.NewFileSet(), "snapshot_manifest.go", nil, 0)
		if err != nil {
			t.Fatal("cannot inspect owned source")
		}
		allowed := map[string]bool{"bytes": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true, "strconv": true, "strings": true, "packtrace/internal/jsoninput": true}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || !allowed[path] {
				t.Fatal("IO/clock/environment/consumer import outside pure reader scope")
			}
		}
		for _, decl := range file.Decls {
			if d, ok := decl.(*ast.GenDecl); ok && d.Tok == token.VAR {
				t.Fatal("mutable production singleton")
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && (id.Name == "print" || id.Name == "println" || id.Name == "panic") {
					t.Fatal("production side effect")
				}
			}
			return true
		})
	})
}
