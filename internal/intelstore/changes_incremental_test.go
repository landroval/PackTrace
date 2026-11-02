package intelstore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
)

func TestIncrementalSourceUpdateKeepsOutsideAndUnresolvedEvidence(t *testing.T) {
	for _, mode := range []string{"outside-update", "unavailable-update", "wrong-id-update", "retry-fail-update"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, _ := transactionFixture(t)
			bootstrap, close := fullSourceFixture(t, "success")
			defer close()
			initial, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, bootstrap)
			if e != nil {
				t.Fatal(e)
			}
			old, e := s.loadSourceState(ctx, initial.Generation)
			if e != nil {
				t.Fatal(e)
			}
			next, closeNext := fullSourceFixture(t, mode)
			defer closeNext()
			fetch := func(ctx context.Context, b *Budget, spec requestSpec, out io.Writer) (responseEvidence, error) {
				if spec.kind == requestArchive || spec.kind == requestArchiveMeta {
					t.Fatal("incremental silently switched/reset to full")
				}
				return next(ctx, b, spec, out)
			}
			result, e := s.syncIncremental(ctx, &Budget{StagingBytes: 16 << 20}, fetch, old)
			if mode == "wrong-id-update" || mode == "retry-fail-update" {
				if e == nil {
					t.Fatal("mismatched ID advanced cursor")
				}
				selection, _, e := s.readSelection(ctx)
				if e != nil || selection.Current != fmt.Sprintf("%x", initial.Generation) {
					t.Fatal("failed update activated")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			state, e := s.loadSourceState(ctx, result.Generation)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := s.readRef(ctx, state.preparation.SourceIDs, 1<<20)
			if e != nil {
				t.Fatal(e)
			}
			var row sourceIDRow
			if json.Unmarshal(raw, &row) != nil {
				t.Fatal("source ID row")
			}
			want := sourceOutsideNPM
			if mode == "unavailable-update" {
				want = sourceUnresolved
			}
			if row.Disposition != want {
				t.Fatal("source evidence lost", row.Disposition, want)
			}
			cursor, e := s.readSourceCursor(ctx, state.descriptor.Cursor)
			if e != nil || cursor.Point.Modified != "2026-11-01T01:00:00Z" {
				t.Fatal("bound cursor not actually committed", e, cursor.Point)
			}
			if !state.receipt.ReconciledAt.Equal(old.receipt.ReconciledAt) {
				t.Fatal("incremental renewed full reconciliation")
			}
		})
	}
}
