package intelstore

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGlobalSpacedIDSurvivesGroupingAndCursorWithoutFetchAuthority(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	const id = "SUSE-SU-403 Forbidden-1"
	const raw = "2026-11-01T00:00:00Z,SUSE/" + id + "\n2026-10-31T23:59:59Z,npm/MAL-2026-1\n"
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	groups, point, e := collectChanges(ctx, tx, strings.NewReader(raw), now, now.Add(-48*time.Hour))
	if e != nil || point.ID != id || point.Modified != "2026-11-01T00:00:00Z" {
		t.Fatal("unrelated public listing ID blocked collection or changed cursor", point, e)
	}
	input, e := s.objectReader(ctx, groups)
	if e != nil {
		t.Fatal(e)
	}
	var actions []updateAction
	e = joinSourceChanges(ctx, strings.NewReader(""), input, func(a updateAction) error {
		actions = append(actions, a)
		return nil
	})
	closeErr := input.Close()
	if e != nil || closeErr != nil || len(actions) != 1 || actions[0].ID != "MAL-2026-1" || !actions[0].Fetch {
		t.Fatal("unrelated group acquired fetch authority or blocked npm", actions, e, closeErr)
	}
	cursor := sourceCursor{Version: 1, Point: point}
	encoded, e := json.Marshal(cursor)
	if e != nil {
		t.Fatal(e)
	}
	ref, e := tx.put(ctx, bytes.NewReader(encoded), uint64(len(encoded)))
	if e != nil {
		t.Fatal(e)
	}
	read, e := s.readSourceCursor(ctx, ref)
	if e != nil || read.Point != point {
		t.Fatal("persisted global cursor did not retain exact ID", read.Point, e)
	}
	if _, e := (requestSpec{kind: requestRecord, id: id}).url(); e == nil {
		t.Fatal("global listing-only ID became HTTP authority")
	}
	forged, _ := json.Marshal(changeGroup{ID: id, Modified: point.Modified, NPM: true})
	if e := joinSourceChanges(ctx, strings.NewReader(""), bytes.NewReader(append(forged, '\n')), func(updateAction) error {
		t.Fatal("forged npm group reached fetch selection")
		return nil
	}); e == nil {
		t.Fatal("spaced group claimed npm authority")
	}
}

func TestGlobalIDSpaceAdmissionNeverRelaxesNPMControlsOrTraversal(t *testing.T) {
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	for _, name := range []string{
		"npm/SUSE-SU-403 Forbidden-1", "SUSE/ leading", "SUSE/trailing ",
		"SUSE/A\tB", "SUSE/A\x00B", "SUSE/A\\B", "SUSE/A?B", "SUSE/A#B", "SUSE/A%B",
		"SUSE/../escape", "SUSE/.", "SUSE/..", "SUSE/A\u00a0B", "SUSE/" + strings.Repeat("A", 241),
	} {
		_, e := walkChanges(context.Background(), strings.NewReader("2026-11-01T00:00:00Z,"+name+"\n"), now, func(changeRow) error { return nil })
		if e == nil {
			t.Fatalf("unsafe or npm-only ID admitted: %q", name)
		}
	}
}
