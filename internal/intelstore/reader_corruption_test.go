package intelstore

import (
	"context"
	"crypto/sha256"
	"os"
	"packtrace/internal/intel"
	"path/filepath"
	"testing"
)

func TestSnapshotUnknownIdentityIsNotUnavailableBlock(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	fixtureGeneration(t, s, "OWNED-1", "2026-11-01T00:00:00Z")
	snapshot, e := s.ReadPinned(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	got, e := snapshot.ReadIdentity(ctx, "absent-owned-package")
	if e != nil || len(got.Records) != 0 || got.BlockState != intel.SnapshotStreamStructured || got.Declaration != intel.SnapshotDeclarationVerified {
		t.Fatal("unknown identity lost structured scope", e)
	}
	ref := ObjectRef{SHA256: sha256.Sum256(nil)}
	if e := os.Remove(filepath.Join(path, filepath.FromSlash(objectPath(ref)))); e != nil {
		t.Fatal(e)
	}
	if _, e := snapshot.ReadIdentity(ctx, "absent-owned-package"); e == nil {
		t.Fatal("missing block became successful no-match")
	}
}
func TestSnapshotCorruptOriginalCannotRemainVerified(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	fixtureGeneration(t, s, "OWNED-1", "2026-11-01T00:00:00Z")
	snapshot, e := s.ReadPinned(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	good, e := snapshot.ReadIdentity(ctx, "left-pad")
	if e != nil || len(good.Records) != 1 {
		t.Fatal(e)
	}
	ref := ObjectRef{good.Records[0].SHA256, good.Records[0].Bytes}
	if e := os.WriteFile(filepath.Join(path, filepath.FromSlash(objectPath(ref))), []byte("owned-corruption"), 0600); e != nil {
		t.Fatal(e)
	}
	got, e := snapshot.ReadIdentity(ctx, "left-pad")
	if e == nil && len(got.Records) == 1 && got.Records[0].State == intel.SnapshotOriginalVerified {
		t.Fatal("corrupt raw object retained verified binding")
	}
}
