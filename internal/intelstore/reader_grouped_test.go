package intelstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"packtrace/internal/intel"
)

func groupedDiskNames(t *testing.T, n int) []string {
	t.Helper()
	bucket, _ := intel.SnapshotNPMIdentityBlock("left-pad")
	names := []string{"left-pad"}
	for i := 0; len(names) < n; i++ {
		name := fmt.Sprintf("owned-grouped-%d", i)
		b, _ := intel.SnapshotNPMIdentityBlock(name)
		if b == bucket {
			names = append(names, name)
		}
	}
	return names
}

func TestWalkIdentitiesDiskParityBytesAndBoundary(t *testing.T) {
	snapshot, _ := limitedSnapshot(t)
	ctx := context.Background()
	names := groupedDiskNames(t, 64)
	expected := make(map[string]intel.SnapshotNPMEvidence)
	var baseline, originalBytes uint64
	for _, name := range names {
		got, used, err := snapshot.ReadIdentityLimited(ctx, name, 8<<30)
		if err != nil {
			t.Fatal(err)
		}
		expected[name] = got
		baseline += used
		for _, record := range got.Records {
			originalBytes += record.Bytes
		}
	}
	bucket, _ := intel.SnapshotNPMIdentityBlock(names[0])
	blockBytes := snapshot.manifest.Blocks[bucket].Reference.Bytes
	want := blockBytes + originalBytes
	for _, limit := range []uint64{0, 1, blockBytes - 1, blockBytes, want - 1, want, want + 1, 8 << 30} {
		emitted := 0
		var evidenceBytes uint64
		used, err := snapshot.WalkIdentities(ctx, names, limit, func(name string, got intel.SnapshotNPMEvidence) error {
			emitted++
			evidenceBytes += got.BytesRead
			old := expected[name]
			got.BytesRead = old.BytesRead
			if limit >= want && !reflect.DeepEqual(got, old) {
				t.Fatal("legacy evidence parity", name)
			}
			return nil
		})
		if used > limit {
			t.Fatal("overread", used, limit)
		}
		if limit < want {
			if !errors.Is(err, ErrLimit) || used != limit {
				t.Fatal("boundary failure accounting", limit, used, err)
			}
		} else if err != nil || used != want || evidenceBytes != used || emitted != 64 {
			t.Fatal("exact boundary/64 window", limit, used, emitted, evidenceBytes, err)
		}
	}
	t.Logf("64 same-block identities: legacy=%d grouped=%d index=%d bytes", baseline, want, blockBytes)
	if baseline <= want || baseline-want != 64*blockBytes {
		t.Fatal("one block read vs legacy two-pass/nonempty and single-pass/empty baseline", baseline, want, blockBytes)
	}
}

func TestWalkIdentitiesRejectsBeforeDiskAndCancellation(t *testing.T) {
	snapshot, _ := limitedSnapshot(t)
	names := groupedDiskNames(t, 2)
	mixed := "other-bucket"
	if a, _ := intel.SnapshotNPMIdentityBlock(mixed); a == 0x2a {
		t.Fatal("mixed fixture bucket")
	}
	for _, input := range [][]string{nil, {""}, {"@bad"}, {names[0], names[0]}, {names[0], mixed}, make([]string, 65)} {
		used, err := snapshot.WalkIdentities(context.Background(), input, 8<<30, func(string, intel.SnapshotNPMEvidence) error { t.Fatal("invalid emitted"); return nil })
		if err == nil || used != 0 {
			t.Fatal("invalid window read", input, used, err)
		}
	}
	if used, err := snapshot.WalkIdentities(context.Background(), names, (8<<30)+1, func(string, intel.SnapshotNPMEvidence) error { return nil }); !errors.Is(err, ErrLimit) || used != 0 {
		t.Fatal("oversized cap", used, err)
	}
	if used, err := snapshot.WalkIdentities(context.Background(), names, 1<<20, nil); err == nil || used != 0 {
		t.Fatal("nil emitter read", used, err)
	}
	for checkpoint := int32(1); checkpoint < 100; checkpoint++ {
		base, cancel := context.WithCancel(context.Background())
		ctx := &identityCancelContext{Context: base, at: checkpoint, cancel: cancel}
		used, err := snapshot.WalkIdentities(ctx, names, 1<<20, func(string, intel.SnapshotNPMEvidence) error { return nil })
		cancel()
		if used > 0 && errors.Is(err, context.Canceled) {
			return
		}
	}
	t.Fatal("no cancellation after bytes exercised")
}

func TestWalkIdentitiesChargesCorruptionAndMandatoryOriginal(t *testing.T) {
	for _, target := range []string{"index", "original", "missing-original"} {
		t.Run(target, func(t *testing.T) {
			snapshot, root := limitedSnapshot(t)
			good, err := snapshot.ReadIdentity(context.Background(), "left-pad")
			if err != nil {
				t.Fatal(err)
			}
			bucket, _ := intel.SnapshotNPMIdentityBlock("left-pad")
			block := snapshot.manifest.Blocks[bucket].Reference
			ref := ObjectRef{block.SHA256, block.Bytes}
			want := block.Bytes
			if target != "index" {
				ref = ObjectRef{good.Records[0].SHA256, good.Records[0].Bytes}
				if target == "original" {
					want += ref.Bytes
				}
			}
			path := filepath.Join(root, filepath.FromSlash(objectPath(ref)))
			if target == "missing-original" {
				err = os.Remove(path)
			} else {
				err = os.WriteFile(path, bytes.Repeat([]byte{'x'}, int(ref.Bytes)), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			emitted := 0
			used, err := snapshot.WalkIdentities(context.Background(), []string{"left-pad"}, 8<<30, func(_ string, got intel.SnapshotNPMEvidence) error {
				emitted++
				if len(got.Records) != 1 || got.Records[0].State == intel.SnapshotOriginalVerified {
					t.Fatal("original object not mandatory")
				}
				return nil
			})
			if used != want {
				t.Fatal("corrupt actual bytes lost", used, want, err)
			}
			if target == "index" {
				if err == nil || emitted != 0 {
					t.Fatal("index corruption admitted", err)
				}
			} else if err != nil || emitted != 1 {
				t.Fatal("original metadata gap parity", err, emitted)
			}
		})
	}
}

func TestWalkIdentitiesEmitterErrorAndLease(t *testing.T) {
	snapshot, _ := limitedSnapshot(t)
	sentinel := errors.New("owned emitter error")
	used, err := snapshot.WalkIdentities(context.Background(), []string{"left-pad"}, 8<<30, func(_ string, got intel.SnapshotNPMEvidence) error {
		if got.Records[0].State != intel.SnapshotOriginalVerified {
			t.Fatal("missing original")
		}
		return sentinel
	})
	good, legacyErr := snapshot.ReadIdentity(context.Background(), "left-pad")
	if legacyErr != nil {
		t.Fatal(legacyErr)
	}
	bucket, _ := intel.SnapshotNPMIdentityBlock("left-pad")
	want := good.BytesRead - snapshot.manifest.Blocks[bucket].Reference.Bytes
	if !errors.Is(err, sentinel) || used != want {
		t.Fatal("emitter byte accounting", used, want, err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if used, err := snapshot.WalkIdentities(context.Background(), []string{"left-pad"}, 8<<30, func(string, intel.SnapshotNPMEvidence) error { return nil }); err == nil || used != 0 {
		t.Fatal("closed lease read", used, err)
	}
}
