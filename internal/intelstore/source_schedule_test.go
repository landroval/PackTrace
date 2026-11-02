package intelstore

import (
	"context"
	"io"
	"testing"
)

func TestSyncScheduleUsesQualifiedCursorWithoutFullFetch(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	initial, close := fullSourceFixture(t, "success")
	defer close()
	if _, e := s.sync(ctx, &Budget{StagingBytes: 16 << 20}, initial); e != nil {
		t.Fatal(e)
	}
	next, closeNext := fullSourceFixture(t, "outside-update")
	defer closeNext()
	fetch := func(ctx context.Context, b *Budget, spec requestSpec, out io.Writer) (responseEvidence, error) {
		if spec.kind == requestArchive || spec.kind == requestArchiveMeta {
			t.Fatal("qualified cursor ignored by actual scheduler")
		}
		return next(ctx, b, spec, out)
	}
	result, e := s.sync(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if e != nil {
		t.Fatal(e)
	}
	if result.Generation == (ID{}) || s.readers != 0 || s.active {
		t.Fatal("scheduled operation leaked pin/writer")
	}
}
