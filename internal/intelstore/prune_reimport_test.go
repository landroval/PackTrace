package intelstore

import (
	"bytes"
	"context"
	"testing"
)

func TestPruneExplicitVerifiedReimportCanRehydrateSameGeneration(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fetch, closeSource := fullSourceFixture(t, "success")
	defer closeSource()
	first, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := s.ReadPinned(ctx, &first.Generation)
	if e != nil {
		t.Fatal(e)
	}
	var bundle bytes.Buffer
	if e := s.Export(ctx, snapshot, &bundle); e != nil {
		t.Fatal(e)
	}
	snapshot.Close()
	fixtureGeneration(t, s, "SECOND-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "THIRD-1", "2026-11-01T00:00:00Z")
	preview, e := s.PreviewPrune(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.ApplyPrune(ctx, preview.Token); e != nil {
		t.Fatal(e)
	}
	input, _ := originalBundleInput(t, bundle.Bytes())
	restored, e := s.Import(ctx, input, ImportOptions{})
	if e != nil {
		t.Fatal("explicit verified input could not rehydrate pruned snapshot", e)
	}
	if restored.Generation != first.Generation {
		t.Fatal("original descriptor identity changed")
	}
	reader, e := s.ReadPinned(ctx, nil)
	if e != nil {
		t.Fatal("successful import left selected generation permanently retired", e)
	}
	defer reader.Close()
	evidence, e := reader.ReadIdentity(ctx, "left-pad")
	if e != nil || len(evidence.Records) != 1 {
		t.Fatal("rehydrated original unavailable", e)
	}
}
