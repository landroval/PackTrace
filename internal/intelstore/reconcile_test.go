package intelstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestFullReconciliationKeepsDisappearedIDWithSourceDisposition(t *testing.T) {
	for _, mode := range []string{"replacement-unresolved", "replacement-withdrawn", "replacement-outside"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, _ := transactionFixture(t)
			first, close := fullSourceFixture(t, "success")
			defer close()
			initial, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, first)
			if e != nil {
				t.Fatal(e)
			}
			old, e := s.loadSourceState(ctx, initial.Generation)
			if e != nil {
				t.Fatal(e)
			}
			next, closeNext := fullSourceFixture(t, mode)
			defer closeNext()
			result, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, next)
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
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			if len(lines) != 2 {
				t.Fatal("disappeared original silently dropped", len(lines))
			}
			var row sourceIDRow
			if json.Unmarshal([]byte(lines[0]), &row) != nil || row.ID != "GHSA-2345-6789-cfgh" {
				t.Fatal("known ID missing")
			}
			want := sourceUnresolved
			if mode == "replacement-withdrawn" {
				want = sourceWithdrawn
			}
			if mode == "replacement-outside" {
				want = sourceOutsideNPM
			}
			if row.Disposition != want {
				t.Fatal("absence mislabeled", row.Disposition, want)
			}
			if mode == "replacement-unresolved" && !state.receipt.ReconciledAt.Equal(old.receipt.ReconciledAt) {
				t.Fatal("unknown disappearance rejuvenated full reconciliation")
			}
			selected, _, e := s.readSelection(ctx)
			if e != nil || selected.Current != fmt.Sprintf("%x", result.Generation) {
				t.Fatal("reconciliation not activated", e)
			}
		})
	}
}
