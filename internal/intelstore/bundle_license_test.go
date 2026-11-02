package intelstore

import (
	"bytes"
	"context"
	"testing"
)

func TestImportCannotActivateUnknownPublisherLicense(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fixtureGeneration(t, s, "OWNED-1", "2026-11-01T00:00:00Z")
	snapshot, e := s.ReadPinned(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	var data bytes.Buffer
	if e := s.Export(ctx, snapshot, &data); e != nil {
		t.Fatal(e)
	}
	input, _ := originalBundleInput(t, data.Bytes())
	other, _ := transactionFixture(t)
	if _, e := other.Import(ctx, input, ImportOptions{}); e == nil {
		t.Fatal("unknown source licensing activated from package text")
	}
}
