package intel

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestProjectOSVHeaderSchemaProfile(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		field     OSVString
		schema    OSVHeaderSchemaState
	}{
		{"absent", "", OSVString{State: OSVFieldAbsent}, OSVHeaderSchemaV1Implicit},
		{"null", `null`, OSVString{State: OSVFieldNull}, OSVHeaderSchemaUnknown},
		{"boolean", `true`, OSVString{State: OSVFieldInvalidType}, OSVHeaderSchemaUnknown},
		{"number", `1.0`, OSVString{State: OSVFieldInvalidType}, OSVHeaderSchemaUnknown},
		{"huge-number", `1e400`, OSVString{State: OSVFieldInvalidType}, OSVHeaderSchemaUnknown},
		{"object", `{}`, OSVString{State: OSVFieldInvalidType}, OSVHeaderSchemaUnknown},
		{"array", `[]`, OSVString{State: OSVFieldInvalidType}, OSVHeaderSchemaUnknown},
		{"explicit-default", `"1.0.0"`, OSVString{State: OSVFieldValue, Value: "1.0.0"}, OSVHeaderSchemaV1Declared},
		{"reviewed-version", `"1.9.1"`, OSVString{State: OSVFieldValue, Value: "1.9.1"}, OSVHeaderSchemaV1Declared},
		{"future-minor-patch", `"1.999.123"`, OSVString{State: OSVFieldValue, Value: "1.999.123"}, OSVHeaderSchemaV1Declared},
		{"major-zero", `"0.0.0"`, OSVString{State: OSVFieldValue, Value: "0.0.0"}, OSVHeaderSchemaUnsupported},
		{"major-two", `"2.0.0"`, OSVString{State: OSVFieldValue, Value: "2.0.0"}, OSVHeaderSchemaUnsupported},
		{"major-ten", `"10.0.0"`, OSVString{State: OSVFieldValue, Value: "10.0.0"}, OSVHeaderSchemaUnsupported},
		{"empty", `""`, OSVString{State: OSVFieldValue}, OSVHeaderSchemaUnknown},
		{"space", `" "`, OSVString{State: OSVFieldValue, Value: " "}, OSVHeaderSchemaUnknown},
		{"prefix", `"v1.0.0"`, OSVString{State: OSVFieldValue, Value: "v1.0.0"}, OSVHeaderSchemaUnknown},
		{"zero-major", `"01.0.0"`, OSVString{State: OSVFieldValue, Value: "01.0.0"}, OSVHeaderSchemaUnknown},
		{"zero-minor", `"1.01.0"`, OSVString{State: OSVFieldValue, Value: "1.01.0"}, OSVHeaderSchemaUnknown},
		{"zero-patch", `"1.0.00"`, OSVString{State: OSVFieldValue, Value: "1.0.00"}, OSVHeaderSchemaUnknown},
		{"short", `"1.0"`, OSVString{State: OSVFieldValue, Value: "1.0"}, OSVHeaderSchemaUnknown},
		{"extra-component", `"1.0.0.0"`, OSVString{State: OSVFieldValue, Value: "1.0.0.0"}, OSVHeaderSchemaUnknown},
		{"empty-component", `"1..0"`, OSVString{State: OSVFieldValue, Value: "1..0"}, OSVHeaderSchemaUnknown},
		{"trailing-space", `"1.0.0 "`, OSVString{State: OSVFieldValue, Value: "1.0.0 "}, OSVHeaderSchemaUnknown},
		{"leading-space", `" 1.0.0"`, OSVString{State: OSVFieldValue, Value: " 1.0.0"}, OSVHeaderSchemaUnknown},
		{"trailing-lf", `"1.0.0\n"`, OSVString{State: OSVFieldValue, Value: "1.0.0\n"}, OSVHeaderSchemaUnknown},
		{"trailing-crlf", `"1.0.0\r\n"`, OSVString{State: OSVFieldValue, Value: "1.0.0\r\n"}, OSVHeaderSchemaUnknown},
		{"major-sign", `"+1.0.0"`, OSVString{State: OSVFieldValue, Value: "+1.0.0"}, OSVHeaderSchemaUnknown},
		{"minor-sign", `"1.-1.0"`, OSVString{State: OSVFieldValue, Value: "1.-1.0"}, OSVHeaderSchemaUnknown},
		{"patch-sign", `"1.0.+1"`, OSVString{State: OSVFieldValue, Value: "1.0.+1"}, OSVHeaderSchemaUnknown},
		{"unicode-major", `"١.0.0"`, OSVString{State: OSVFieldValue, Value: "١.0.0"}, OSVHeaderSchemaUnknown},
		{"unicode-minor", `"1.０.0"`, OSVString{State: OSVFieldValue, Value: "1.０.0"}, OSVHeaderSchemaUnknown},
		{"exponent", `"1.1e2.0"`, OSVString{State: OSVFieldValue, Value: "1.1e2.0"}, OSVHeaderSchemaUnknown},
		{"prerelease", `"1.0.0-rc.1"`, OSVString{State: OSVFieldValue, Value: "1.0.0-rc.1"}, OSVHeaderSchemaUnknown},
		{"build", `"1.0.0+build"`, OSVString{State: OSVFieldValue, Value: "1.0.0+build"}, OSVHeaderSchemaUnknown},
		{"major-two-prerelease", `"2.0.0-rc.1"`, OSVString{State: OSVFieldValue, Value: "2.0.0-rc.1"}, OSVHeaderSchemaUnknown},
		{"major-two-build", `"2.0.0+build"`, OSVString{State: OSVFieldValue, Value: "2.0.0+build"}, OSVHeaderSchemaUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"id":"TEST","modified":"uninterpreted"`
			if tc.raw != "" {
				src += `,"schema_version":` + tc.raw
			}
			doc, err := ParseOSVRecord([]byte(src + "}"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ProjectOSVHeader(doc)
			want := OSVHeader{SourceSHA256: doc.SHA256, ID: OSVString{State: OSVFieldValue, Value: "TEST"}, SchemaVersion: tc.field, Schema: tc.schema}
			if err != nil || got != want {
				t.Fatal("schema state/profile or exact ID evidence lost", got, err)
			}
		})
	}
}

func TestProjectOSVHeaderIDIsUnqualified(t *testing.T) {
	for _, id := range []string{" ", "../not-a-path", "unknown DB", "x_CUSTOM-0001", "☃"} {
		t.Run(id, func(t *testing.T) {
			raw, err := json.Marshal(id)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := ParseOSVRecord([]byte(`{"id":` + string(raw) + `,"modified":"invalid","schema_version":"2.0.0"}`))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ProjectOSVHeader(doc)
			if err != nil || got.SourceSHA256 != doc.SHA256 || got.ID != (OSVString{State: OSVFieldValue, Value: id}) || got.Schema != OSVHeaderSchemaUnsupported {
				t.Fatal("ID interpreted/erased by unsupported schema", err)
			}
		})
	}
}

func TestProjectOSVHeaderEvidenceAndOwnership(t *testing.T) {
	src := []byte(` {
"\u0069d":"TEST-\u0031",
"modified":"not-a-date",
"\u0073chema_version":"\u0031.9.1",
"withdrawn":null,
"affected":{"unusable":true},
"database_specific":{"future":1e400}
} `)
	doc, err := ParseOSVRecord(src)
	if err != nil {
		t.Fatal(err)
	}
	sourceBefore, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProjectOSVHeader(doc)
	want := OSVHeader{SourceSHA256: sha256.Sum256(src), ID: OSVString{State: OSVFieldValue, Value: "TEST-1"}, SchemaVersion: OSVString{State: OSVFieldValue, Value: "1.9.1"}, Schema: OSVHeaderSchemaV1Declared}
	if err != nil || got != want {
		t.Fatal("exact decoded evidence/digest lost", err)
	}
	sourceAfter, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(sourceBefore, sourceAfter) {
		t.Fatal("projection modified raw sibling data")
	}
	snapshot, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "schema_version"} {
		for i := range doc.Fields[key] {
			doc.Fields[key][i] = 'X'
		}
		delete(doc.Fields, key)
	}
	doc.SHA256[0] ^= 255
	for i := range src {
		src[i] = 'X'
	}
	after, err := json.Marshal(got)
	if err != nil || !bytes.Equal(snapshot, after) {
		t.Fatal("returned header aliases source")
	}
	sourceBefore, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got.ID.Value = "changed"
	got.SchemaVersion.Value = "2.0.0"
	got.SourceSHA256[0] ^= 255
	sourceAfter, err = json.Marshal(doc)
	if err != nil || !bytes.Equal(sourceBefore, sourceAfter) {
		t.Fatal("output mutation changed source")
	}
}

func TestProjectOSVHeaderLargeComponents(t *testing.T) {
	large := strings.Repeat("9", 10_000)
	for _, tc := range []struct {
		name, value string
		schema      OSVHeaderSchemaState
	}{
		{"major", large + ".0.0", OSVHeaderSchemaUnsupported},
		{"minor", "1." + large + ".0", OSVHeaderSchemaV1Declared},
		{"patch", "1.0." + large, OSVHeaderSchemaV1Declared},
		{"leading-zero", "1.0." + "0" + large, OSVHeaderSchemaUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := ParseOSVRecord([]byte(`{"id":"TEST","modified":"invalid","schema_version":"` + tc.value + `"}`))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ProjectOSVHeader(doc)
			if err != nil || got.SourceSHA256 != doc.SHA256 || got.Schema != tc.schema || got.SchemaVersion != (OSVString{State: OSVFieldValue, Value: tc.value}) {
				t.Fatal("component overflow/truncation/coercion", err)
			}
		})
	}
}

func TestProjectOSVHeaderExactReaderByteBound(t *testing.T) {
	const prefix = `{"id":"TEST","modified":"invalid","schema_version":"1.`
	const suffix = `.0"}`
	minor := strings.Repeat("9", (4<<20)-len(prefix)-len(suffix))
	src := []byte(prefix + minor + suffix)
	if len(src) != 4<<20 {
		t.Fatal("incorrect size fixture")
	}
	doc, err := ParseOSVRecord(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProjectOSVHeader(doc)
	if err != nil || got.Schema != OSVHeaderSchemaV1Declared || got.SourceSHA256 != sha256.Sum256(src) || got.SchemaVersion.Value != "1."+minor+".0" {
		t.Fatal("largest reader-valid scalar rejected/truncated", err)
	}
	// The reader's existing limit remains authoritative; projection does not widen it.
	assertOSVError(t, append(src, ' '), "limit-exceeded")
}

func TestProjectOSVHeaderNilFields(t *testing.T) {
	got, err := ProjectOSVHeader(OSVDocument{SHA256: [32]byte{1}})
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != "invalid-shape" || err.Error() != "intel: invalid-shape" || !reflect.DeepEqual(got, OSVHeader{}) {
		t.Fatal("controlled error/zero result required", got, err)
	}
}
