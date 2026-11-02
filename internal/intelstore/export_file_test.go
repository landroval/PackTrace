package intelstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExportFilePublishesBoundedPinnedTransportWithoutChangingSource(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	id := fixtureGeneration(t, s, "OWNED-1", "2026-11-01T00:00:00Z")
	snapshot, e := s.ReadPinned(ctx, &id)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	output := filepath.Join(filepath.Dir(path), "snapshot.bundle")
	n, e := s.ExportFile(ctx, snapshot, output)
	if e != nil || n == 0 {
		t.Fatal(e)
	}
	stat, e := os.Stat(output)
	if e != nil || uint64(stat.Size()) != n {
		t.Fatal("actual publication bytes not observed", e)
	}
	if _, e := s.explicitHeader(ctx, id); e != nil {
		t.Fatal("publication mutated source binding", e)
	}
}
