package intelstore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestKnownIDOutsideOrUnavailableRetainsActualOriginalDisposition(t *testing.T) {
	for _, mode := range []string{"outside", "404", "wrong-id"} {
		t.Run(mode, func(t *testing.T) {
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
			tx.prep = &preparationState{}
			old := sourceIDRow{ID: "OWNED-1", Original: ref}
			a := updateAction{ID: "OWNED-1", Old: &old, Change: &changeGroup{ID: "OWNED-1", Modified: "2026-11-01T00:00:00Z", Other: true}, Fetch: true}
			fetch := func(ctx context.Context, b *Budget, s requestSpec, out io.Writer) (responseEvidence, error) {
				if s.kind != requestRecord || s.id != "OWNED-1" {
					t.Fatal("query not source-known public ID")
				}
				if mode == "404" {
					return responseEvidence{status: 404}, nil
				}
				body := strings.ReplaceAll(ownedOSVRecord, `"npm"`, `"PyPI"`)
				if mode == "wrong-id" {
					body = strings.ReplaceAll(body, "OWNED-1", "OTHER-1")
				}
				io.WriteString(out, body)
				return responseEvidence{status: 200, bytes: uint64(len(body))}, nil
			}
			e = applySourceAction(ctx, tx, a, fetch)
			if mode == "wrong-id" {
				if e == nil {
					t.Fatal("contradictory original ID accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			var got sourceIDRow
			if json.Unmarshal([]byte(strings.TrimSpace(tx.prep.idLines.String())), &got) != nil {
				t.Fatal("source row")
			}
			want := sourceOutsideNPM
			if mode == "404" {
				want = sourceUnresolved
				if got.Original != ref {
					t.Fatal("unresolved original dropped")
				}
			}
			if got.Disposition != want {
				t.Fatal("disappearance mislabeled", got.Disposition, want)
			}
		})
	}
}
