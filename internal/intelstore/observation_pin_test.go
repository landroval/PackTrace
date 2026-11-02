package intelstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExternalDescriptorDesignationIsIndependentOfReceiptText(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	fetch, close := fullSourceFixture(t, "success")
	defer close()
	result, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if e != nil {
		t.Fatal(e)
	}
	// Owned temporary fixture removes only local acquisition authority, as when a
	// portable package carries the same descriptor but cannot carry the secret.
	if e := os.Remove(filepath.Join(path, "generations", fmt.Sprintf("%x", result.Generation), "local-acquisition.mac")); e != nil {
		t.Fatal(e)
	}
	pin, e := s.Pin(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	raw, e := s.Observe(ctx, pin, time.Now(), nil)
	if e != nil || raw.SourceAuthority != SourceUnqualified {
		t.Fatal("receipt self-authorized", e, raw)
	}
	designated, e := s.Observe(ctx, pin, time.Now(), &result.Generation)
	if e != nil || designated.SourceAuthority != SourceDesignated {
		t.Fatal("independent matching descriptor ignored", e)
	}
	wrong := result.Generation
	wrong[0] ^= 1
	if _, e := s.Observe(ctx, pin, time.Now(), &wrong); !errors.Is(e, ErrUntrusted) {
		t.Fatal("conflicting pin downgraded", e)
	}
}
