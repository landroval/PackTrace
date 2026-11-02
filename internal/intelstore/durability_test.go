package intelstore

import (
	"bytes"
	"context"
	"testing"
)

func TestActivationRequiresPositiveDurabilityFence(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	g, e := tx.seal(ctx, storageDraft(t, tx, "activation-fence"))
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.durability.Close(); e != nil {
		t.Fatal(e)
	}
	if e := tx.activate(ctx, g); e == nil {
		t.Fatal("closed durability capability activated generation")
	}
}
func TestBulkDurabilityRolloverAndDedup(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 140; i++ {
		if _, e := tx.put(ctx, bytes.NewReader([]byte{byte(i % 80)}), 1); e != nil {
			t.Fatalf("object %d: %v", i, e)
		}
	}
	if e := tx.fence(ctx); e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestGenerationCannotSealOrActivateAfterDurabilityCapabilityCloses(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	draft := storageDraft(t, tx, "durability")
	if tx.durability == nil {
		t.Fatal("bulk writer lacks explicit durability authority")
	}
	if e := tx.durability.Close(); e != nil {
		t.Fatal(e)
	}
	if e := tx.writeImmutable(ctx, "generations/fence-canary", []byte("no")); e == nil {
		t.Fatal("generation control written without durability fence")
	}
	if _, e := tx.seal(ctx, draft); e == nil {
		t.Fatal("closed durability capability minted seal")
	}
}
