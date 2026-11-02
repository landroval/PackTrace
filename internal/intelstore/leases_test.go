package intelstore

import (
	"context"
	"encoding/hex"
	"errors"
	"packtrace/internal/nativefs"
	"testing"
)

func TestPinnedGenerationSurvivesActivationAndBlocksExclusiveLease(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
	if e != nil {
		t.Fatal(e)
	}
	first, e := tx.seal(ctx, storageDraft(t, tx, "first"))
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.activate(ctx, first); e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	pin, e := s.Pin(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	if pin.ID() != first {
		t.Fatal("wrong initial generation")
	}
	tx, e = s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
	if e != nil {
		t.Fatal(e)
	}
	second, e := tx.seal(ctx, storageDraft(t, tx, "second"))
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.activate(ctx, second); e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	later, e := s.Pin(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if later.ID() != second || pin.ID() != first {
		t.Fatal("snapshot changed midway")
	}
	later.Close()
	other, e := nativefs.OpenRoot(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	name := "generations/" + hex.EncodeToString(first[:]) + "/read.lock"
	if lock, e := other.TryOwnedLock(ctx, name, true); !errors.Is(e, nativefs.ErrBusy) || lock != nil {
		t.Fatal("active reader failed to protect generation", e)
	}
	if e := s.Close(); !errors.Is(e, ErrBusy) {
		t.Fatal("store closed with live reader")
	}
	if e := pin.Close(); e != nil {
		t.Fatal(e)
	}
	lock, e := other.TryOwnedLock(ctx, name, true)
	if e != nil {
		t.Fatal("generation lease did not release", e)
	}
	lock.Close()
	if pin.ID() != (ID{}) {
		t.Fatal("closed pin retained authority")
	}
}
func TestUnknownPinProtectionIsNotSuccessfulAbsence(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	if pinned, e := s.isPinned(ctx, ID{1}); e == nil || pinned {
		t.Fatal("closed/unobservable store became unpinned success")
	}
}

func TestClosedPinCannotSelect(t *testing.T) {
	p := &Pin{}
	if p.ID() != (ID{}) || p.Close() == nil {
		t.Fatal("zero pin admitted")
	}
}
func TestDurableGenerationPinSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
	if e != nil {
		t.Fatal(e)
	}
	id, e := tx.seal(ctx, storageDraft(t, tx, "first"))
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.activate(ctx, id); e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	if e := s.SetPinned(ctx, id, true); e != nil {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(ctx, path, CreateOwned)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if pinned, e := s.isPinned(ctx, id); e != nil || !pinned {
		t.Fatal("durable pin lost", e)
	}
	if e := s.SetPinned(ctx, id, false); e != nil {
		t.Fatal(e)
	}
	if pinned, e := s.isPinned(ctx, id); e != nil || pinned {
		t.Fatal("explicit unpin failed", e)
	}
	if e := s.SetPinned(ctx, ID{1}, true); e == nil {
		t.Fatal("unknown generation pinned")
	}
}
