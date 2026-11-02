package intelstore

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestPreparedUnchangedOriginalIsReusedWithoutDuplicateWrite(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	raw := []byte(ownedOSVRecord)
	ref, e := tx.put(ctx, bytes.NewReader(raw), uint64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	before := tx.written
	tx.prep = &preparationState{record: preparationRecord{Version: 1, Source: "caller-supplied"}}
	if e := prepareOriginal(ctx, tx, "OWNED-1", raw, &ref, sourceObserved); e != nil {
		t.Fatal(e)
	}
	if tx.written != before || tx.prep.record.Records != 1 || tx.prep.record.Memberships != 1 {
		t.Fatal("unchanged original rewritten or evidence lost")
	}
	if _, e := buildIndexes(ctx, tx); e != nil {
		t.Fatal(e)
	}
}
func TestPreparationExpandedBudgetDoesNotReset(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20, ExpandedBytes: (8 << 30) - 1})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	tx.prep = &preparationState{}
	if e := prepareOriginal(ctx, tx, "OWNED-1", []byte(ownedOSVRecord), nil, sourceObserved); !errors.Is(e, ErrLimit) || tx.prep.record.Records != 0 {
		t.Fatal("processed-advisory budget reset", e)
	}
}
