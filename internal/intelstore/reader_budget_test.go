package intelstore

import (
	"bytes"
	"context"
	"fmt"
	"packtrace/internal/intel"
	"strings"
	"testing"
)

func TestSnapshotIdentityOriginalBudgetDoesNotBecomeEmptySuccess(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 128 << 20})
	if e != nil {
		t.Fatal(e)
	}
	var records []archiveRecord
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("OWNED-%d", i)
		base := strings.ReplaceAll(ownedOSVRecord, "OWNED-1", id)
		base = base[:len(base)-1] + `,"padding":"`
		suffix := `"}`
		raw := base + strings.Repeat("x", (4<<20)-len(base)-len(suffix)) + suffix
		records = append(records, archiveRecord{id + ".json", raw, 0})
	}
	archive := ownedArchive(t, records)
	draft, e := prepareArchive(ctx, tx, bytes.NewReader(archive), int64(len(archive)))
	if e != nil {
		t.Fatal(e)
	}
	id, e := tx.seal(ctx, draft)
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.activate(ctx, id); e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	snapshot, e := s.ReadPinned(ctx, &id)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	got, e := snapshot.ReadIdentity(ctx, "left-pad")
	if e != nil {
		t.Fatal(e)
	}
	var retained uint64
	resource := false
	for _, record := range got.Records {
		retained += uint64(len(record.Raw))
		if record.Problem == intel.SnapshotOriginalProblemResource {
			resource = true
		}
	}
	if len(got.Records) != 6 || retained > 16<<20 || !resource {
		t.Fatal("identity original budget bypassed or lost uncertainty", len(got.Records), retained, resource)
	}
}
