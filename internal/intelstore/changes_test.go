package intelstore

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTimestampTieAndTimezoneHaveDeterministicCursor(t *testing.T) {
	raw := "2026-11-01T01:00:00+01:00,npm/GHSA-2345-6789-cfgh\n2026-11-01T00:00:00Z,[EMPTY]/MAL-2026-1\n2026-10-31T23:59:59Z,PyPI/PYSEC-2020-1\n"
	var rows []changeRow
	point, e := walkChanges(context.Background(), strings.NewReader(raw), time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), func(row changeRow) error { rows = append(rows, row); return nil })
	if e != nil || len(rows) != 3 || point.Modified != "2026-11-01T00:00:00Z" || point.ID != "MAL-2026-1" {
		t.Fatal("timestamp tie lost", point, e)
	}
	if rows[0].Modified != rows[1].Modified || rows[1].Directory != "[EMPTY]" {
		t.Fatal("source disposition lost")
	}
}
func TestChangeCSVRejectsUnusableSchemaWithoutAdvancing(t *testing.T) {
	for _, raw := range []string{
		"modified,id\n",
		"2026-11-01T00:00:00.1234567891Z,npm/GHSA-2345-6789-cfgh\n",
		"2026-11-01T00:00:00+24:00,npm/GHSA-2345-6789-cfgh\n",
		"2026-11-03T00:00:00Z,npm/GHSA-2345-6789-cfgh\n",
		"2026-11-01T00:00:00Z,npm/../escape\n",
		"2026-10-31T00:00:00Z,npm/MAL-2026-1\n2026-11-01T00:00:00Z,npm/MAL-2026-2\n",
	} {
		if _, e := walkChanges(context.Background(), strings.NewReader(raw), time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), func(changeRow) error { return nil }); e == nil {
			t.Fatal("unqualified list admitted", raw)
		}
	}
}
func TestCursorDoesNotAdvanceOnFailedCandidate(t *testing.T) {
	old := cursorPoint{Modified: "2026-11-01T00:00:00Z", ID: "GHSA-2345-6789-cfgh"}
	candidate := cursorPoint{Modified: "2026-11-02T00:00:00Z", ID: "MAL-2026-1"}
	if got := committedCursor(old, candidate, false); got != old {
		t.Fatal("failed operation advanced cursor")
	}
}
