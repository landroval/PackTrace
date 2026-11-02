package intelstore

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestChangeRunsDeduplicateEquivalentRowsAndKeepOutsideNPM(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	raw := "2026-11-01T00:00:00Z,npm/MAL-2026-2\n2026-11-01T00:00:00Z,PyPI/MAL-2026-2\n2026-11-01T00:00:00Z,npm/MAL-2026-2\n2026-10-31T00:00:00Z,[EMPTY]/GHSA-2345-6789-cfgh\n"
	ref, point, e := collectChanges(ctx, tx, strings.NewReader(raw), time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), time.Time{})
	if e != nil {
		t.Fatal(e)
	}
	data, e := s.readRef(ctx, ref, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || point.ID != "MAL-2026-2" {
		t.Fatal("rows dropped or duplicated", len(lines), point)
	}
	var first, last changeGroup
	if json.Unmarshal([]byte(lines[0]), &first) != nil || json.Unmarshal([]byte(lines[1]), &last) != nil || !first.Empty || !last.NPM || !last.Other {
		t.Fatal("known-ID disposition evidence lost")
	}
}
func TestChangeRunsRejectConflictingIDTimes(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	raw := "2026-11-01T00:00:00Z,npm/MAL-2026-1\n2026-10-31T00:00:00Z,npm/MAL-2026-1\n"
	if _, _, e := collectChanges(ctx, tx, strings.NewReader(raw), time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), time.Time{}); e == nil {
		t.Fatal("conflicting source row used last-key-wins")
	}
}
