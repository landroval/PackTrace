package intelstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestReachabilityMetadataRetentionLimitStaysUnknownNotEmpty(t *testing.T) {
	p := &pruneState{}
	accepted := 0
	for p.retainMetadata(1 << 20) {
		accepted++
		if accepted > 256 {
			t.Fatal("metadata retention unbounded")
		}
	}
	before := p.metadata
	if p.retainMetadata(1) || p.metadata != before || p.failure == nil {
		t.Fatal("exhausted metadata allowance silently renewed")
	}
}

func TestPruneChangedQuotaConfigurationInvalidatesConfirmation(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fixtureGeneration(t, s, "FIRST-1", "2026-11-01T00:00:00Z")
	preview, e := s.PreviewPrune(ctx)
	if e != nil {
		t.Fatal(e)
	}
	s.quotaLimit = (32 << 30) - 1
	if _, e := s.ApplyPrune(ctx, preview.Token); e == nil {
		t.Fatal("changed root configuration accepted old confirmation")
	}
}

func TestPruneEqualSelectorBytesCannotSubstituteNativeActivationIdentity(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	fixtureGeneration(t, s, "FIRST-1", "2026-11-01T00:00:00Z")
	preview, e := s.PreviewPrune(ctx)
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(path, "activation", "current.json")
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(file, file+".prior"); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(file, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(file + ".prior"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ApplyPrune(ctx, preview.Token); e == nil {
		t.Fatal("equal selector bytes substituted original activation control")
	}
}

func orphanForPrune(t *testing.T, s *Store) ObjectRef {
	t.Helper()
	ctx := context.Background()
	tx, e := s.begin(ctx, operationImport, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	ref, e := tx.put(ctx, bytes.NewReader([]byte("owned-orphan")), 12)
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	return ref
}
func TestReachabilityMissingProtectedOriginalNeverBecomesReclaimableZero(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	first := fixtureGeneration(t, s, "FIRST-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "SECOND-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "THIRD-1", "2026-11-01T00:00:00Z")
	snapshot, e := s.ReadPinned(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	evidence, e := snapshot.ReadIdentity(ctx, "left-pad")
	if e != nil || len(evidence.Records) != 1 {
		t.Fatal(e)
	}
	snapshot.Close()
	key := hex.EncodeToString(evidence.Records[0].SHA256[:])
	if e := os.Remove(filepath.Join(path, "objects", key[:2], key)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.PreviewPrune(ctx); e == nil {
		t.Fatal("incomplete retained reachability presented as clean empty")
	}
	if _, e := s.explicitHeader(ctx, first); e != nil {
		t.Fatal("failed reachability retired untouched history", e)
	}
}

func TestPruneChangedCandidateRejectsBeforeHistoricalTombstone(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	first := fixtureGeneration(t, s, "FIRST-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "SECOND-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "THIRD-1", "2026-11-01T00:00:00Z")
	ref := orphanForPrune(t, s)
	preview, e := s.PreviewPrune(ctx)
	if e != nil {
		t.Fatal(e)
	}
	key := hex.EncodeToString(ref.SHA256[:])
	file := filepath.Join(path, "objects", key[:2], key)
	if e := os.WriteFile(file, []byte("changed-body"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ApplyPrune(ctx, preview.Token); e == nil {
		t.Fatal("changed candidate confirmed")
	}
	pin, e := s.Pin(ctx, &first)
	if e != nil {
		t.Fatal("stale preview retired history before complete preflight", e)
	}
	pin.Close()
	data, e := os.ReadFile(file)
	if e != nil || string(data) != "changed-body" {
		t.Fatal("changed file deleted", e)
	}
}
func TestPruneAlienHardlinkOrCopiedCommitmentCannotAuthorize(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	fixtureGeneration(t, s, "FIRST-1", "2026-11-01T00:00:00Z")
	ref := orphanForPrune(t, s)
	preview, e := s.PreviewPrune(ctx)
	if e != nil {
		t.Fatal(e)
	}
	other, _ := transactionFixture(t)
	name := "previews/" + hex.EncodeToString(preview.Token[:]) + ".json"
	f, e := other.owner.CopyExclusive(ctx, name, bytes.NewReader(nil), 0)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	if _, e := other.ApplyPrune(ctx, preview.Token); e == nil {
		t.Fatal("copied commitment granted another root cleanup")
	}
	key := hex.EncodeToString(ref.SHA256[:])
	original := filepath.Join(path, "objects", key[:2], key)
	alien := filepath.Join(t.TempDir(), "alien")
	if e := os.Link(original, alien); e != nil {
		t.Fatal(e)
	}
	if _, e := s.PreviewPrune(ctx); e == nil {
		t.Fatal("alien hardlink offered as attributable owned reclamation")
	}
	data, e := os.ReadFile(alien)
	if e != nil || string(data) != "owned-orphan" {
		t.Fatal("alien bytes mutated", e)
	}
}
