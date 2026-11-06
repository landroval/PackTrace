package intelstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestChangedOriginalReusesEmptyPartitionsButStillRequiresTheirActualObject(t *testing.T) {
	ctx := context.Background()
	tx, base, path := reuseFixture(t, "MAL-2026-2")
	prep := tx.prep.record
	raw, e := tx.store.readRef(ctx, prep.SourceIDs, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	old, e := parseSourceIDRow(bytes.TrimSpace(raw))
	if e != nil {
		t.Fatal(e)
	}
	body := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(ownedOSVRecord, "OWNED-1", old.ID), "left-pad", "right-pad"), "2026-11-01T00:00:00Z", "2026-11-01T01:00:00Z")
	if sha256.Sum256([]byte("left-pad"))[0] == sha256.Sum256([]byte("right-pad"))[0] {
		t.Fatal("fixture must move the membership to a different partition")
	}
	walk := func(emit func(indexUpdateAction) error) error {
		return emit(indexUpdateAction{updateAction: updateAction{ID: old.ID, Old: &old, Fetch: true}, inBase: true})
	}
	calls := 0
	fetch := func(_ context.Context, _ *Budget, spec requestSpec, out io.Writer) (responseEvidence, error) {
		calls++
		if spec.id != old.ID {
			t.Fatal("unexpected advisory request")
		}
		n, e := io.WriteString(out, body)
		return responseEvidence{status: 200, bytes: uint64(n)}, e
	}
	before := tx.sequence
	actual, e := reuseIndexDraft(ctx, tx, base, prep, []ObjectRef{prep.SourceIDs}, walk, fetch)
	if e != nil || calls != 1 {
		t.Fatal("changed original projection", e, calls)
	}
	writes := tx.sequence - before
	t.Logf("changed-original staging objects=%d", writes)
	if writes > 32 {
		t.Fatal("rewrote empty partitions as durable staging objects", writes)
	}
	s, _ := transactionFixture(t)
	expectedTx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer expectedTx.Close()
	archive := ownedArchive(t, []archiveRecord{{old.ID + ".json", body, 0}})
	expected, e := prepareArchive(ctx, expectedTx, bytes.NewReader(archive), int64(len(archive)))
	if e != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatal("empty reuse skipped changed membership or altered canonical semantics", e)
	}
	empty := ObjectRef{SHA256: sha256.Sum256(nil)}
	found := false
	for _, ref := range actual.Objects {
		found = found || ref == empty
	}
	if !found {
		t.Fatal("empty partition original omitted from mandatory objects")
	}
	if e := tx.fence(ctx); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(path, objectPath(empty))); e != nil {
		t.Fatal(e)
	}
	if _, e := tx.seal(ctx, actual); e == nil {
		t.Fatal("empty reference was trusted without its actual mandatory original")
	}
}
