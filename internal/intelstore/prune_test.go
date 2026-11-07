package intelstore

import (
	"context"
	"testing"
)

func TestZeroPreviewNeverAuthorizesDeletion(t *testing.T) {
	var s Store
	if _, e := s.ApplyPrune(context.Background(), ID{}); e == nil {
		t.Fatal("empty preview authorized cleanup")
	}
}
func TestPrunePreviewProtectsReadersPinsCurrentPreviousAndSharedBytes(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	first := fixtureGeneration(t, s, "FIRST-1", "2026-11-01T00:00:00Z")
	held, e := s.Pin(ctx, &first)
	if e != nil {
		t.Fatal(e)
	}
	fixtureGeneration(t, s, "SECOND-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "THIRD-1", "2026-11-01T00:00:00Z")
	preview, e := s.PreviewPrune(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if preview.Generations != 0 {
		t.Fatal("reader generation selected")
	}
	held.Close()
	if e := s.SetPinned(ctx, first, true); e != nil {
		t.Fatal(e)
	}
	preview, e = s.PreviewPrune(ctx)
	if e != nil || preview.Generations != 0 {
		t.Fatal("durable pin selected", e)
	}
	if e := s.SetPinned(ctx, first, false); e != nil {
		t.Fatal(e)
	}
	preview, e = s.PreviewPrune(ctx)
	if e != nil || preview.Generations != 1 {
		t.Fatal("unprotected historical generation not offered", e)
	}
	result, e := s.ApplyPrune(ctx, preview.Token)
	if e != nil {
		t.Fatal(e)
	}
	if result.Generations != 1 || result.RemovedBytes == 0 {
		t.Fatal("actual cleanup not observed")
	}
	if pin, e := s.Pin(ctx, &first); e == nil {
		pin.Close()
		t.Fatal("retired generation admitted new reader")
	}
	current, e := s.ReadPinned(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	evidence, e := current.ReadIdentity(ctx, "left-pad")
	if e != nil || len(evidence.Records) != 1 {
		t.Fatal("retained shared objects deleted", e)
	}
}
func TestPruneStalePreviewRejectsWholeApplyBeforeUnlink(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	first := fixtureGeneration(t, s, "FIRST-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "SECOND-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "THIRD-1", "2026-11-01T00:00:00Z")
	preview, e := s.PreviewPrune(ctx)
	if e != nil {
		t.Fatal(e)
	}
	held, e := s.Pin(ctx, &first)
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	if _, e := s.ApplyPrune(ctx, preview.Token); e == nil {
		t.Fatal("changed protection accepted")
	}
	if _, e := s.explicitHeader(ctx, first); e != nil {
		t.Fatal("stale confirmation deleted before complete preflight", e)
	}
}
