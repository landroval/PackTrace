package intelstore

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestChangeListingDoesNotAllocateABufferPageForEveryRow(t *testing.T) {
	const rows = 64
	input := strings.Repeat("2026-11-01T00:00:00Z,npm/GHSA-2345-6789-cfgh\n", rows)
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	var failure error
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, failure = walkChanges(context.Background(), strings.NewReader(input), now, func(changeRow) error { return nil })
			if failure != nil {
				break
			}
		}
	})
	if failure != nil {
		t.Fatal(failure)
	}
	if bytes := result.AllocedBytesPerOp(); bytes > rows*1024 {
		t.Fatalf("bounded CSV still allocates one 4KiB reader page per row: bytes/op=%d rows=%d", bytes, rows)
	}
}
