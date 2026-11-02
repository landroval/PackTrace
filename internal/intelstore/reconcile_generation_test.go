package intelstore

import (
	"context"
	"fmt"
	"testing"
)

func TestFullSourceGenerationCannotChangeItsAlreadyObservedBytes(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	initial, close := fullSourceFixture(t, "success")
	defer close()
	old, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, initial)
	if e != nil {
		t.Fatal(e)
	}
	replacement, closeNext := fullSourceFixture(t, "replacement-reused-generation")
	defer closeNext()
	if _, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, replacement); e == nil {
		t.Fatal("same source generation silently changed bytes")
	}
	selected, _, e := s.readSelection(ctx)
	if e != nil || selected.Current != fmt.Sprintf("%x", old.Generation) {
		t.Fatal("inconsistent reference activated", e)
	}
}
