package intel

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestProjectOSVTimesStates(t *testing.T) {
	cases := []struct {
		name  string
		value any
		state TimestampState
		text  string
	}{
		{"absent", nil, TimestampAbsent, ""},
		{"null", nil, TimestampNull, ""},
		{"boolean", false, TimestampInvalidType, ""},
		{"number", 42, TimestampInvalidType, ""},
		{"array", []string{}, TimestampInvalidType, ""},
		{"object", map[string]string{}, TimestampInvalidType, ""},
		{"empty", "", TimestampUninterpretable, ""},
		{"unsupported", "private-marker", TimestampUninterpretable, "private-marker"},
		{"valid-zero", "0001-01-01T00:00:00Z", TimestampValue, "0001-01-01T00:00:00Z"},
	}
	for _, key := range []string{"published", "withdrawn"} {
		for _, tc := range cases {
			t.Run(key+"/"+tc.name, func(t *testing.T) {
				fields := map[string]any{"id": "TEST", "modified": "not-a-date"}
				if tc.name != "absent" {
					fields[key] = tc.value
				}
				doc := temporalDocument(t, fields)
				got, err := ProjectOSVTimes(doc)
				if err != nil || got.SourceSHA256 != doc.SHA256 || got.Modified.State != TimestampUninterpretable || got.Modified.Text != "not-a-date" || !got.Modified.Value.IsZero() {
					t.Fatal("invalid sibling lost evidence", err)
				}
				field, other := got.Published, got.Withdrawn
				wantWithdrawal := WithdrawalNotDeclared
				if key == "withdrawn" {
					field, other = got.Withdrawn, got.Published
					switch tc.state {
					case TimestampAbsent:
						wantWithdrawal = WithdrawalNotDeclared
					case TimestampValue:
						wantWithdrawal = WithdrawalReported
					default:
						wantWithdrawal = WithdrawalUnknown
					}
				}
				want := OSVTimestamp{State: tc.state, Text: tc.text}
				if !reflect.DeepEqual(field, want) || other != (OSVTimestamp{}) || got.Withdrawal != wantWithdrawal {
					t.Fatalf("states/withdrawal: %#v", got)
				}
			})
		}
	}
}

func TestProjectOSVTimesAcceptedProfile(t *testing.T) {
	cases := []struct {
		text                            string
		year                            int
		month                           time.Month
		day, hour, minute, second, nano int
	}{
		{"2026-09-27T01:02:03Z", 2026, 9, 27, 1, 2, 3, 0},
		{"2026-09-27T01:02:03.000Z", 2026, 9, 27, 1, 2, 3, 0},
		{"2026-09-27T01:02:03.1200Z", 2026, 9, 27, 1, 2, 3, 120000000},
		{"2026-09-27T01:02:03.123456789Z", 2026, 9, 27, 1, 2, 3, 123456789},
		{"2026-09-27T01:02:03+00:00", 2026, 9, 27, 1, 2, 3, 0},
		{"2026-09-27T01:02:03-00:00", 2026, 9, 27, 1, 2, 3, 0},
		{"2026-01-01T00:15:00+01:30", 2025, 12, 31, 22, 45, 0, 0},
		{"2026-01-01T23:30:00-02:30", 2026, 1, 2, 2, 0, 0, 0},
		{"2026-01-02T00:00:00+23:59", 2026, 1, 1, 0, 1, 0, 0},
		{"2026-01-01T00:00:00-23:59", 2026, 1, 1, 23, 59, 0, 0},
		{"2024-02-29T12:00:00Z", 2024, 2, 29, 12, 0, 0, 0},
		{"2000-02-29T12:00:00Z", 2000, 2, 29, 12, 0, 0, 0},
		{"0000-02-29T00:00:00Z", 0, 2, 29, 0, 0, 0, 0},
		{"0000-01-01T00:00:00Z", 0, 1, 1, 0, 0, 0, 0},
		{"0001-01-01T00:00:00Z", 1, 1, 1, 0, 0, 0, 0},
		{"9999-12-31T23:59:59.999999999Z", 9999, 12, 31, 23, 59, 59, 999999999},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			doc := temporalDocument(t, map[string]any{"id": "TEST", "modified": tc.text, "published": tc.text, "withdrawn": tc.text, "schema_version": "future"})
			got, err := ProjectOSVTimes(doc)
			if err != nil || got.SourceSHA256 != doc.SHA256 || got.Withdrawal != WithdrawalReported {
				t.Fatal("valid/future withdrawal not retained", err)
			}
			want := time.Date(tc.year, tc.month, tc.day, tc.hour, tc.minute, tc.second, tc.nano, time.UTC)
			for _, field := range []OSVTimestamp{got.Modified, got.Published, got.Withdrawn} {
				if field.State != TimestampValue || field.Text != tc.text || !field.Value.Equal(want) || field.Value.Location() != time.UTC {
					t.Fatalf("profile/text/UTC instant: %#v; want %v", field, want)
				}
			}
		})
	}
}

func TestProjectOSVTimesUninterpretableProfile(t *testing.T) {
	for _, text := range []string{
		"2026-09-27t01:02:03Z", "2026-09-27T01:02:03z", "2026-09-27 01:02:03Z",
		" 2026-09-27T01:02:03Z", "2026-09-27T01:02:03Z ", "2026-09-27T01:02:03Z\n",
		"2026-09-27T01:02:03", "2026-09-27T01:02:03UTC", "2026-09-27T01:02:03+01", "2026-09-27T01:02:03+0100",
		"2026-09-27T01:02:03+24:00", "2026-09-27T01:02:03-24:00", "2026-09-27T01:02:03+00:60",
		"2026-09-27T01:02:03,1Z", "2026-09-27T01:02:03.Z", "2026-09-27T01:02:03.1234567890Z",
		"2026-09-27T1:02:03Z", "2026-9-27T01:02:03Z", "2026-09-7T01:02:03Z",
		"2026-09-27T24:00:00Z", "2026-09-27T01:60:00Z", "2016-12-31T23:59:60Z",
		"2023-02-29T00:00:00Z", "1900-02-29T00:00:00Z", "2026-04-31T00:00:00Z",
		"2026-00-01T00:00:00Z", "2026-13-01T00:00:00Z", "2026-01-00T00:00:00Z",
		"10000-01-01T00:00:00Z", "-001-01-01T00:00:00Z", "２０２６-01-01T00:00:00Z",
		"0000-01-01T00:00:00+00:01", "9999-12-31T23:59:59-00:01",
	} {
		t.Run(text, func(t *testing.T) {
			doc := temporalDocument(t, map[string]any{"id": "TEST", "modified": text, "published": text, "withdrawn": text})
			got, err := ProjectOSVTimes(doc)
			if err != nil || got.SourceSHA256 != doc.SHA256 || got.Withdrawal != WithdrawalUnknown {
				t.Fatal("unsupported timestamp became usable or fatal", err)
			}
			want := OSVTimestamp{State: TimestampUninterpretable, Text: text}
			for _, field := range []OSVTimestamp{got.Modified, got.Published, got.Withdrawn} {
				if !reflect.DeepEqual(field, want) {
					t.Fatal("rejected spelling/precision lost or silently normalized", field)
				}
			}
		})
	}
}

func TestProjectOSVTimesEvidenceAndIndependence(t *testing.T) {
	text := "2026-01-01T00:00:00.1200+01:30"
	doc := temporalDocument(t, map[string]any{"id": "TEST", "modified": text, "published": text, "withdrawn": "0001-01-01T00:00:00Z", "unknown": map[string]any{"keep": true}})
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProjectOSVTimes(doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.SourceSHA256 != doc.SHA256 || got.Withdrawal != WithdrawalReported || got.Withdrawn.State != TimestampValue || !got.Withdrawn.Value.IsZero() {
		t.Fatal("chronology inferred or zero time misclassified")
	}
	after, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("projection mutated raw evidence")
	}
	saved := got
	doc.Fields["modified"][1] = 'X'
	doc.Fields["published"] = json.RawMessage(`"changed"`)
	delete(doc.Fields, "withdrawn")
	doc.SHA256[0] ^= 255
	if !reflect.DeepEqual(got, saved) {
		t.Fatal("projection aliases source")
	}
	got.Modified.Text = "changed"
	got.Modified.Value = time.Time{}
	if got.Published != saved.Published || got.Withdrawn != saved.Withdrawn {
		t.Fatal("fields alias each other")
	}
}

func TestProjectOSVTimesNilFields(t *testing.T) {
	got, err := ProjectOSVTimes(OSVDocument{})
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != "invalid-shape" || err.Error() != "intel: invalid-shape" || !reflect.DeepEqual(got, OSVTimes{}) || got.Withdrawal != WithdrawalUnknown {
		t.Fatal("nil guard/error privacy/default uncertainty", got, err)
	}
}

func temporalDocument(t *testing.T, fields map[string]any) OSVDocument {
	t.Helper()
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseOSVRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
