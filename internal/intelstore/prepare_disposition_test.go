package intelstore

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestPreparedSourceDispositionsRetainUnknownAndOutsideNPM(t *testing.T) {
	for _, tt := range []struct {
		name, raw    string
		forced, want sourceDisposition
	}{
		{"withdrawn", strings.Replace(ownedOSVRecord, `"affected":`, `"withdrawn":"2026-11-01T00:00:00Z","affected":`, 1), sourceObserved, sourceWithdrawn},
		{"outside", strings.ReplaceAll(ownedOSVRecord, `"npm"`, `"PyPI"`), sourceObserved, sourceOutsideNPM},
		{"unresolved404", ownedOSVRecord, sourceUnresolved, sourceUnresolved},
		{"null-withdrawal", strings.Replace(ownedOSVRecord, `"affected":`, `"withdrawn":null,"affected":`, 1), sourceObserved, sourceUnresolved},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			s, _ := transactionFixture(t)
			tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Close()
			tx.prep = &preparationState{}
			if e := prepareOriginal(ctx, tx, "OWNED-1", []byte(tt.raw), nil, tt.forced); e != nil {
				t.Fatal(e)
			}
			var row sourceIDRow
			if json.Unmarshal([]byte(strings.TrimSpace(tx.prep.idLines.String())), &row) != nil || row.Disposition != tt.want {
				t.Fatal("source disposition silently changed", row.Disposition, tt.want)
			}
		})
	}
}
