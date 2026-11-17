package intelstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestConstructionValidationFollowsGenerationRetention(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	fetch, closeSource := fullSourceFixture(t, "success")
	defer closeSource()
	first, err := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if err != nil { t.Fatal(err) }
	held, err := s.ReadPinned(ctx, &first.Generation)
	if err != nil { t.Fatal(err) }
	defer held.Close()
	fixtureGeneration(t, s, "SECOND-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "THIRD-1", "2026-11-01T00:00:00Z")
	preview, err := s.PreviewPrune(ctx)
	if err != nil || preview.Generations != 0 { t.Fatal("reader-bound generation selected", preview, err) }
	if _, err := held.ValidateConstruction(ctx, 512 << 20); err != nil { t.Fatal("retained authority lost", err) }
	if err := held.Close(); err != nil { t.Fatal(err) }
	preview, err = s.PreviewPrune(ctx)
	if err != nil || preview.Generations != 1 { t.Fatal("unretained generation not selected", preview, err) }
	result, err := s.ApplyPrune(ctx, preview.Token)
	if err != nil || result.Generations != 1 { t.Fatal("validation sidecar broke maintenance", result, err) }
	if _, err := os.Stat(filepath.Join(path, filepath.FromSlash(validationPath(first.Generation)))); !os.IsNotExist(err) { t.Fatal("orphan authority survived generation", err) }
	if pin, err := s.ReadPinned(ctx, &first.Generation); err == nil { pin.Close(); t.Fatal("retired proof admitted") }
}
