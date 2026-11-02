package intelstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func storageDraft(t *testing.T, tx *Transaction, payload string) generationDraft {
	t.Helper()
	ctx := context.Background()
	empty, e := tx.put(ctx, bytes.NewReader(nil), 0)
	if e != nil {
		t.Fatal(e)
	}
	extra, e := tx.put(ctx, bytes.NewBufferString(payload), uint64(len(payload)))
	if e != nil {
		t.Fatal(e)
	}
	refs := make([]any, 256)
	for i := range refs {
		refs[i] = map[string]any{"index": i, "sha256": hex.EncodeToString(empty.SHA256[:]), "bytes": 0, "records": 0}
	}
	raw, e := json.Marshal(map[string]any{"schemaVersion": "1.1", "source": map[string]any{"id": "owned-storage-fixture"}, "originals": map[string]any{"sha256": hex.EncodeToString(empty.SHA256[:]), "bytes": 0, "records": 0}, "blocks": refs})
	if e != nil {
		t.Fatal(e)
	}
	manifest, e := tx.put(ctx, bytes.NewReader(raw), uint64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	return generationDraft{Manifest: manifest, Objects: []ObjectRef{empty, extra, manifest}}
}
func TestPartialGenerationCannotActivate(t *testing.T) {
	var tx Transaction
	if e := tx.activate(context.Background(), ID{1}); !errors.Is(e, ErrCorrupt) {
		t.Fatal("unsealed activation admitted", e)
	}
}
func TestActivationPublishesSealedAndProtectsPrevious(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	var ids []ID
	for _, payload := range []string{"first", "second"} {
		tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
		if e != nil {
			t.Fatal(e)
		}
		id, e := tx.seal(ctx, storageDraft(t, tx, payload))
		if e != nil {
			t.Fatal(e)
		}
		if e := tx.activate(ctx, id); e != nil {
			t.Fatal(e)
		}
		if e := tx.Close(); e != nil {
			t.Fatal(e)
		}
		ids = append(ids, id)
	}
	record, fallback, e := s.readSelection(ctx)
	if e != nil || fallback || record.Current != hex.EncodeToString(ids[1][:]) || record.Previous != hex.EncodeToString(ids[0][:]) {
		t.Fatal("activation history", record, e)
	}
}
func TestActivationRejectsCorruptObjectAndForgedSeal(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	draft := storageDraft(t, tx, "data")
	sum := sha256.Sum256([]byte("data"))
	key := hex.EncodeToString(sum[:])
	if os.WriteFile(filepath.Join(path, "objects", key[:2], key), []byte("fake"), 0600) != nil {
		t.Fatal("owned corruption")
	}
	if _, e := tx.seal(ctx, draft); !errors.Is(e, ErrCorrupt) {
		t.Fatal("corrupt object admitted", e)
	}
	if e := tx.activate(ctx, ID{2}); !errors.Is(e, ErrCorrupt) {
		t.Fatal("forged token activated", e)
	}
}
func TestRecoveryFallbackNeverRewritesSelection(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	var first ID
	for i, payload := range []string{"first", "next"} {
		tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
		if e != nil {
			t.Fatal(e)
		}
		id, e := tx.seal(ctx, storageDraft(t, tx, payload))
		if e != nil {
			t.Fatal(e)
		}
		if e := tx.activate(ctx, id); e != nil {
			t.Fatal(e)
		}
		if e := tx.Close(); e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			first = id
		}
	}
	current := filepath.Join(path, "activation", "current.json")
	bad := []byte("corrupt")
	if os.WriteFile(current, bad, 0600) != nil {
		t.Fatal("owned selector corruption")
	}
	r, fallback, e := s.readSelection(ctx)
	if e != nil || !fallback || r.Current != hex.EncodeToString(first[:]) {
		t.Fatal("protected fallback unavailable", e)
	}
	after, _ := os.ReadFile(current)
	if !bytes.Equal(after, bad) {
		t.Fatal("readonly recovery rewrote current")
	}
	if os.WriteFile(filepath.Join(path, "activation", "previous.json"), bad, 0600) != nil {
		t.Fatal("previous corruption")
	}
	if _, _, e := s.readSelection(ctx); e == nil {
		t.Fatal("both corrupt selectors became empty success")
	}
}
