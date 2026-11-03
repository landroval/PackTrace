package intelstore

import (
	"context"
	"testing"
)

func TestLivePinBindingRequiresActualStoreAndOpenOriginalLease(t *testing.T) {
	ctx := context.Background()
	var bindings [2][32]byte
	var ids [2]ID
	for i := 0; i < 2; i++ {
		s, _ := transactionFixture(t)
		tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
		if e != nil {
			t.Fatal(e)
		}
		id, e := tx.seal(ctx, storageDraft(t, tx, "same-portable-data"))
		if e != nil {
			t.Fatal(e)
		}
		ids[i] = id
		if e := tx.activate(ctx, id); e != nil {
			t.Fatal(e)
		}
		if e := tx.Close(); e != nil {
			t.Fatal(e)
		}
		pin, e := s.Pin(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		bindings[i], e = pin.PhysicalBinding(ctx)
		if e != nil || bindings[i] == ([32]byte{}) {
			t.Fatal("original binding missing", e)
		}
		if e := pin.Close(); e != nil {
			t.Fatal(e)
		}
		if _, e := pin.PhysicalBinding(ctx); e == nil {
			t.Fatal("closed lease still grants binding")
		}
	}
	if ids[0] != ids[1] {
		t.Fatal("fixture not same portable descriptor")
	}
	if bindings[0] == bindings[1] {
		t.Fatal("same portable hash substituted physical store lease")
	}
}
