package intelstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestLocalAcquisitionSealSurvivesReopenButCannotMoveStores(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	archive := ownedArchive(t, []archiveRecord{{"OWNED-1.json", ownedOSVRecord, 0}})
	draft, e := prepareArchive(ctx, tx, bytes.NewReader(archive), int64(len(archive)))
	if e != nil {
		t.Fatal(e)
	}
	id, e := tx.seal(ctx, draft)
	if e != nil {
		t.Fatal(e)
	}
	// This is a synthetic storage-authority test, not a real source assertion.
	if e := tx.attestLocal(ctx, id); e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	if e := s.verifyLocal(ctx, id); e != nil {
		t.Fatal(e)
	}
	mac, e := s.readSmall(ctx, "generations/"+fmt.Sprintf("%x", id)+"/local-acquisition.mac", 32)
	if e != nil {
		t.Fatal(e)
	}
	key, e := s.readSmall(ctx, "acquisition.key", 32)
	if e != nil {
		t.Fatal(e)
	}
	instance := s.instance
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(ctx, path, ReadOnly)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if e := reopened.verifyLocal(ctx, id); e != nil {
		t.Fatal("local authority lost at reopen", e)
	}
	other, _ := transactionFixture(t)
	base := "generations/" + fmt.Sprintf("%x", id)
	if e := other.owner.Mkdir(ctx, base); e != nil {
		t.Fatal(e)
	}
	copied, e := other.owner.CopyExclusive(ctx, base+"/local-acquisition.mac", bytes.NewReader(mac), 32)
	if e != nil {
		t.Fatal(e)
	}
	if e := copied.Close(); e != nil {
		t.Fatal(e)
	}
	// Even copying the secret and instance in an owned adversarial fixture must
	// not transfer authority to another actual physical root.
	f, e := other.owner.CopyExclusive(ctx, "staging/copied-key", bytes.NewReader(key), 32)
	if e != nil {
		t.Fatal(e)
	}
	if e := other.owner.Publish(ctx, f, "acquisition.key", true); e != nil {
		t.Fatal(e)
	}
	if e := f.Close(); e != nil {
		t.Fatal(e)
	}
	other.instance = instance
	if e := other.verifyLocal(ctx, id); !errors.Is(e, ErrUntrusted) {
		t.Fatal("copied local seal became source authority", e)
	}
}
