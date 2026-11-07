package intelstore

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"packtrace/internal/testfile"
)

func TestIncrementalReprojectsOnlyChangedOriginalsButPreservesWholeCatalog(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	base, closeBase := fullSourceFixture(t, "multiple-originals")
	defer closeBase()
	first, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, base)
	if e != nil {
		t.Fatal(e)
	}
	old, e := s.loadSourceState(ctx, first.Generation)
	if e != nil {
		t.Fatal(e)
	}
	updated, closeUpdate := fullSourceFixture(t, "success-update")
	defer closeUpdate()
	recordBytes := len(strings.ReplaceAll(ownedOSVRecord, "OWNED-1", "GHSA-2345-6789-cfgh"))
	budget := &Budget{StagingBytes: 16 << 20, ExpandedBytes: (8 << 30) - uint64(2*recordBytes+16)}
	result, e := s.syncIncremental(ctx, budget, updated, old)
	if e != nil {
		t.Fatal("unchanged advisory bodies consumed semantic processing allowance", e)
	}
	if result.Records != 4 || result.Memberships != 4 {
		t.Fatal("whole reused source catalog changed", result)
	}
	snapshot, e := s.ReadPinned(ctx, &result.Generation)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	evidence, e := snapshot.ReadIdentity(ctx, "left-pad")
	if e != nil || len(evidence.Records) != 4 {
		t.Fatal("unchanged original/index linkage lost", len(evidence.Records), e)
	}
	var bundle bytes.Buffer
	if e := s.Export(ctx, snapshot, &bundle); e != nil {
		t.Fatal(e)
	}
	input, _ := originalBundleInput(t, bundle.Bytes())
	other, _ := transactionFixture(t)
	received, e := other.Import(ctx, input, ImportOptions{})
	if e != nil || received.Generation != result.Generation {
		t.Fatal("reused metadata changed canonical semantic rebuild", received, e)
	}
	pin, e := s.Pin(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	ob, e := s.Observe(ctx, pin, time.Now(), nil)
	if e != nil || ob.Records != 4 {
		t.Fatal(ob, e)
	}
}

func reuseFixture(t *testing.T, ids ...string) (*Transaction, generationDraft, string) {
	t.Helper()
	ctx := context.Background()
	s, path := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { tx.Close() })
	var records []archiveRecord
	for _, id := range ids {
		records = append(records, archiveRecord{id + ".json", strings.ReplaceAll(ownedOSVRecord, "OWNED-1", id), 0})
	}
	archive := ownedArchive(t, records)
	draft, e := prepareArchive(ctx, tx, bytes.NewReader(archive), int64(len(archive)))
	if e != nil {
		t.Fatal(e)
	}
	return tx, draft, path
}
func TestIndexReuseBeforeMiddleAfterInsertionsAreCanonicalAndAllOriginalsRemainRequired(t *testing.T) {
	ctx := context.Background()
	tx, base, path := reuseFixture(t, "MAL-2026-2", "MAL-2026-4")
	prep := tx.prep.record
	csv := "2026-11-01T01:00:00Z,npm/MAL-2026-1\n2026-11-01T01:00:00Z,npm/MAL-2026-3\n2026-11-01T01:00:00Z,npm/MAL-2026-5\n"
	groups, _, e := collectChanges(ctx, tx, strings.NewReader(csv), time.Now(), time.Time{})
	if e != nil {
		t.Fatal(e)
	}
	walk := func(emit func(indexUpdateAction) error) error {
		return joinStoredChanges(ctx, tx, prep.SourceIDs, groups, func(a updateAction) error { return emit(indexUpdateAction{a, a.Old != nil}) })
	}
	calls := 0
	fetch := func(ctx context.Context, b *Budget, spec requestSpec, w io.Writer) (responseEvidence, error) {
		calls++
		body := strings.ReplaceAll(strings.ReplaceAll(ownedOSVRecord, "OWNED-1", spec.id), "2026-11-01T00:00:00Z", "2026-11-01T01:00:00Z")
		n, e := io.WriteString(w, body)
		return responseEvidence{status: 200, bytes: uint64(n)}, e
	}
	actual, e := reuseIndexDraft(ctx, tx, base, prep, []ObjectRef{prep.SourceIDs, groups}, walk, fetch)
	if e != nil || calls != 3 {
		t.Fatal(actual, e, calls)
	}
	s, _ := transactionFixture(t)
	expectedTx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer expectedTx.Close()
	var records []archiveRecord
	for _, id := range []string{"MAL-2026-1", "MAL-2026-2", "MAL-2026-3", "MAL-2026-4", "MAL-2026-5"} {
		body := strings.ReplaceAll(ownedOSVRecord, "OWNED-1", id)
		if id != "MAL-2026-2" && id != "MAL-2026-4" {
			body = strings.ReplaceAll(body, "2026-11-01T00:00:00Z", "2026-11-01T01:00:00Z")
		}
		records = append(records, archiveRecord{id + ".json", body, 0})
	}
	archive := ownedArchive(t, records)
	expected, e := prepareArchive(ctx, expectedTx, bytes.NewReader(archive), int64(len(archive)))
	if e != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatal("canonical original ordinals/index rows changed", e, actual.Manifest, expected.Manifest)
	}
	// Reusing the index does not excuse an unchanged original's corruption.
	raw, e := tx.store.readRef(ctx, prep.SourceIDs, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	old, e := parseSourceIDRow(bytes.Split(raw, []byte{'\n'})[0])
	if e != nil {
		t.Fatal(e)
	}
	damaged := bytes.Repeat([]byte{' '}, int(old.Original.Bytes))
	if e := testfile.Overwrite(filepath.Join(path, objectPath(old.Original)), damaged); e != nil {
		t.Fatal(e)
	}
	if _, e := tx.seal(ctx, actual); e == nil {
		t.Fatal("unchanged corrupt original escaped mandatory full object verification")
	}
}
func TestReusedSourceIDsEqualBytesReplacementCannotSupplyNetworkAuthority(t *testing.T) {
	ctx := context.Background()
	tx, base, _ := reuseFixture(t, "MAL-2026-2")
	prep := tx.prep.record
	raw, e := tx.store.readRef(ctx, prep.SourceIDs, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	row, e := parseSourceIDRow(bytes.TrimSpace(raw))
	if e != nil {
		t.Fatal(e)
	}
	passes, calls := 0, 0
	replaced := false
	walk := func(emit func(indexUpdateAction) error) error {
		passes++
		if passes == 2 {
			// Complete an actual same-byte slot replacement while the old
			// metadata original stays retained; failure to mutate is not proof.
			file, e := tx.store.owner.CopyExclusive(ctx, tx.path+"/test-replacement", bytes.NewReader(raw), uint64(len(raw)))
			if e != nil {
				t.Fatal("replacement fixture was not created", e)
			}
			defer file.Close()
			if e := tx.store.owner.Publish(ctx, file, objectPath(prep.SourceIDs), true); e != nil {
				t.Fatal("replacement fixture was not executed", e)
			}
			if e := file.Close(); e != nil {
				t.Fatal("replacement fixture did not close", e)
			}
			replaced = true
		}
		return emit(indexUpdateAction{updateAction: updateAction{ID: row.ID, Old: &row, Fetch: true}, inBase: true})
	}
	fetch := func(context.Context, *Budget, requestSpec, io.Writer) (responseEvidence, error) {
		calls++
		return responseEvidence{}, ErrUnavailable
	}
	if _, e := reuseIndexDraft(ctx, tx, base, prep, []ObjectRef{prep.SourceIDs}, walk, fetch); e == nil || calls != 0 || !replaced {
		t.Fatal("reopened checksum-equal name supplied network IDs or fixture did not replace", e, calls, replaced)
	}
	if _, e := tx.seal(ctx, base); e == nil {
		t.Fatal("metadata binding failure did not poison the transaction")
	}
}
