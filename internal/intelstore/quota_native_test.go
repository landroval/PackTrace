package intelstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestQuotaAccountsRetainedAndNestedStagingMetadata(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows quota")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state")
	s, err := Open(ctx, path, CreateOwned)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	marker, err := os.ReadFile(filepath.Join(path, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if os.MkdirAll(filepath.Join(path, "staging"), 0700) != nil || os.WriteFile(filepath.Join(path, "staging", "partial"), []byte("partial"), 0600) != nil {
		t.Fatal("owned partial staging")
	}
	s, err = Open(ctx, path, CreateOwned)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.owner.WriteControl(ctx, "writer.lock", nil); err != nil {
		t.Fatal(err)
	}
	lease, err := s.root.TryOwnedLock(ctx, "writer.lock", true)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	keyMetadata, err := os.Stat(filepath.Join(path, "acquisition.key"))
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(len(marker)+7) + uint64(keyMetadata.Size())
	got, err := s.observeQuota(ctx, lease, want)
	if err != nil || !got.complete || got.used != want || got.held != 0 {
		t.Fatal("retained/staging accounting", got, err)
	}
	if _, err := s.observeQuota(ctx, lease, want-1); !errors.Is(err, ErrLimit) {
		t.Fatal("existing bytes exceeded quota without refusal", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := s.observeQuota(ctx, lease, want); err == nil || got.complete {
		t.Fatal("closed kernel owner granted accounting")
	}
}

func TestQuotaRefusesWrongLeaseRole(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows quota")
	}
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "state"), CreateOwned)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, name := range []string{"reader.lock", "writer.lock"} {
		if err := s.owner.WriteControl(ctx, name, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name      string
		exclusive bool
	}{{"reader.lock", true}, {"writer.lock", false}} {
		lease, err := s.root.TryOwnedLock(ctx, tc.name, tc.exclusive)
		if err != nil {
			t.Fatal(err)
		}
		got, observeErr := s.observeQuota(ctx, lease, 32<<30)
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if observeErr == nil || got.complete {
			t.Fatal("non-writer role granted quota authority")
		}
	}
}

func TestQuotaMissingLeaseIsUnknown(t *testing.T) {
	var s Store
	if got, err := s.observeQuota(context.Background(), nil, 32<<30); err == nil || got.complete {
		t.Fatal("missing ownership became empty storage")
	}
}
