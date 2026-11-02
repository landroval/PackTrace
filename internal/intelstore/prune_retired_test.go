package intelstore

import (
	"bytes"
	"context"
	"fmt"
	"testing"
)

func TestPruneRetiredGenerationCannotAcquireNewDurablePin(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	id := fixtureGeneration(t, s, "FIRST-1", "2026-11-01T00:00:00Z")
	file, e := s.owner.CopyExclusive(ctx, fmt.Sprintf("generations/%x/retired", id), bytes.NewReader(nil), 0)
	if e != nil {
		t.Fatal(e)
	}
	file.Close()
	if e := s.SetPinned(ctx, id, true); e == nil {
		t.Fatal("new retention pin accepted already retired generation")
	}
}

func TestPruneEmptyRetiredStubsCannotExhaustNewGenerationBatch(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fixtureGeneration(t, s, "FIRST-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "SECOND-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "THIRD-1", "2026-11-01T00:00:00Z")
	for i := 1; i <= 128; i++ {
		dir := fmt.Sprintf("generations/%064x", i)
		if e := s.owner.Mkdir(ctx, dir); e != nil {
			t.Fatal(e)
		}
		for _, name := range []string{"read.lock", "retired"} {
			f, e := s.owner.CopyExclusive(ctx, dir+"/"+name, bytes.NewReader(nil), 0)
			if e != nil {
				t.Fatal(e)
			}
			f.Close()
		}
	}
	preview, e := s.PreviewPrune(ctx)
	if e != nil || preview.Generations != 1 {
		t.Fatal("retired empty directories permanently blocked future retention", preview.Generations, e)
	}
}
