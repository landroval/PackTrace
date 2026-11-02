package intelstore

import (
	"context"
	"testing"
)

func TestBootstrapSealsCursorOnlyAfterSourceCatchup(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fetch, close := fullSourceFixture(t, "success")
	defer close()
	result, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if e != nil {
		t.Fatal(e)
	}
	state, e := s.loadSourceState(ctx, result.Generation)
	if e != nil {
		t.Fatal(e)
	}
	if zeroRef(state.descriptor.Cursor) {
		t.Fatal("bootstrap published without a generation-bound, caught-up cursor")
	}
}
