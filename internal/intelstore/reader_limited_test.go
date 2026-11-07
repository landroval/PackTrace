package intelstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"packtrace/internal/intel"
)

func limitedSnapshot(t *testing.T) (*Snapshot, string) {
	t.Helper()
	s, path := transactionFixture(t)
	fixtureGeneration(t, s, "OWNED-1", "2026-11-01T00:00:00Z")
	snapshot, err := s.ReadPinned(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { snapshot.Close() })
	return snapshot, path
}

func TestReadIdentityLimitedExactBoundaryAndLegacy(t *testing.T) {
	snapshot, _ := limitedSnapshot(t)
	ctx := context.Background()
	legacy, err := snapshot.ReadIdentity(ctx, "left-pad")
	if err != nil {
		t.Fatal(err)
	}
	index, err := intel.SnapshotNPMIdentityBlock("left-pad")
	if err != nil {
		t.Fatal(err)
	}
	blockBytes := snapshot.manifest.Blocks[index].Reference.Bytes
	want := 2*blockBytes + legacy.Records[0].Bytes
	if want != legacy.BytesRead {
		t.Fatalf("legacy accounting=%d actual=%d", legacy.BytesRead, want)
	}
	for _, limit := range []uint64{0, 1, blockBytes - 1, blockBytes, 2 * blockBytes, want - 1, want, want + 1, 8 << 30} {
		got, consumed, err := snapshot.ReadIdentityLimited(ctx, "left-pad", limit)
		if consumed > limit {
			t.Fatalf("overread: limit=%d consumed=%d", limit, consumed)
		}
		if limit < want {
			if !errors.Is(err, ErrLimit) || consumed != limit || len(got.Records) != 0 {
				t.Fatalf("limit=%d consumed=%d records=%d err=%v", limit, consumed, len(got.Records), err)
			}
		} else if err != nil || consumed != want || !reflect.DeepEqual(got, legacy) {
			t.Fatalf("boundary/legacy mismatch: limit=%d consumed=%d err=%v", limit, consumed, err)
		}
	}
	if _, consumed, err := snapshot.ReadIdentityLimited(ctx, "left-pad", (8<<30)+1); !errors.Is(err, ErrLimit) || consumed != 0 {
		t.Fatal("oversized allowance admitted", consumed, err)
	}
	// Repeated calls share the caller's aggregate allowance, not a new free cap.
	remaining := 2*want - 1
	for i := 0; i < 2; i++ {
		_, consumed, err := snapshot.ReadIdentityLimited(ctx, "left-pad", remaining)
		remaining -= consumed
		if i == 0 && err != nil || i == 1 && !errors.Is(err, ErrLimit) {
			t.Fatal("shared allowance", i, consumed, err)
		}
	}
	if remaining != 0 {
		t.Fatal("shared allowance not exhausted", remaining)
	}
	after, err := snapshot.ReadIdentity(ctx, "left-pad")
	if err != nil || !reflect.DeepEqual(after, legacy) {
		t.Fatal("limited reads changed legacy behavior", err)
	}
}

func TestReadIdentityLimitedEmptyAndUnavailable(t *testing.T) {
	snapshot, _ := limitedSnapshot(t)
	// This identity's block has no bytes, but still needs real digest/EOF checks.
	got, used, err := snapshot.ReadIdentityLimited(context.Background(), "absent-owned-package", 0)
	if err != nil || used != 0 || len(got.Records) != 0 || got.BlockState != intel.SnapshotStreamStructured {
		t.Fatal("empty boundary", used, err)
	}
	for _, input := range []struct {
		s    *Snapshot
		ctx  context.Context
		name string
	}{
		{nil, context.Background(), "left-pad"}, {snapshot, nil, "left-pad"}, {snapshot, context.Background(), ""},
	} {
		if _, used, err := input.s.ReadIdentityLimited(input.ctx, input.name, 100); err == nil || used != 0 {
			t.Fatal("unavailable/invalid read", used, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, used, err := snapshot.ReadIdentityLimited(ctx, "left-pad", 100); !errors.Is(err, context.Canceled) || used != 0 {
		t.Fatal("cancellation lost", used, err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, used, err := snapshot.ReadIdentityLimited(context.Background(), "left-pad", 100); err == nil || used != 0 {
		t.Fatal("closed snapshot", used, err)
	}
}

// Cancel at a controlled context checkpoint, without sleeps or goroutine races.
type identityCancelContext struct {
	context.Context
	calls  atomic.Int32
	at     int32
	cancel context.CancelFunc
}

func (c *identityCancelContext) Err() error {
	if c.calls.Add(1) == c.at {
		c.cancel()
	}
	return c.Context.Err()
}

func TestReadIdentityLimitedCancellationRetainsConsumed(t *testing.T) {
	snapshot, _ := limitedSnapshot(t)
	for checkpoint := int32(1); checkpoint <= 100; checkpoint++ {
		base, cancel := context.WithCancel(context.Background())
		ctx := &identityCancelContext{Context: base, at: checkpoint, cancel: cancel}
		_, used, err := snapshot.ReadIdentityLimited(ctx, "left-pad", 1<<20)
		cancel()
		if used > 1<<20 {
			t.Fatal("cancellation overread", used)
		}
		if used > 0 && errors.Is(err, context.Canceled) {
			t.Logf("canceled after actual bytes=%d checkpoint=%d", used, checkpoint)
			return
		}
	}
	t.Fatal("did not exercise cancellation after actual object bytes")
}

func TestReadIdentityLimitedChargesCorruptObjects(t *testing.T) {
	for _, target := range []string{"index", "original"} {
		t.Run(target, func(t *testing.T) {
			snapshot, root := limitedSnapshot(t)
			ctx := context.Background()
			good, err := snapshot.ReadIdentity(ctx, "left-pad")
			if err != nil {
				t.Fatal(err)
			}
			index, _ := intel.SnapshotNPMIdentityBlock("left-pad")
			block := snapshot.manifest.Blocks[index].Reference
			ref := ObjectRef{block.SHA256, block.Bytes}
			expected := block.Bytes
			if target == "original" {
				ref = ObjectRef{good.Records[0].SHA256, good.Records[0].Bytes}
				expected = 2*block.Bytes + ref.Bytes
			}
			// Same-sized corruption reaches EOF and must still fail digest validation.
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(objectPath(ref))), bytes.Repeat([]byte{'x'}, int(ref.Bytes)), 0600); err != nil {
				t.Fatal(err)
			}
			got, used, err := snapshot.ReadIdentityLimited(ctx, "left-pad", expected)
			if used != expected {
				t.Fatalf("failure bytes lost: got=%d want=%d err=%v", used, expected, err)
			}
			if err == nil && (target == "index" || len(got.Records) != 1 || got.Records[0].State == intel.SnapshotOriginalVerified) {
				t.Fatal("corruption became verified", err)
			}
		})
	}
}

func TestIdentityBudgetRealEOFNoOverreadAndMidReadCancellation(t *testing.T) {
	snapshot, root := limitedSnapshot(t)
	ctx := context.Background()
	evidence, err := snapshot.ReadIdentity(ctx, "left-pad")
	if err != nil {
		t.Fatal(err)
	}
	ref := ObjectRef{evidence.Records[0].SHA256, evidence.Records[0].Bytes}
	for _, limit := range []uint64{1, ref.Bytes} {
		r, err := snapshot.store.objectReader(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		budget := &identityReadBudget{remaining: limit}
		_, err = io.Copy(io.Discard, identityIndexReader{r, budget})
		if budget.consumed != limit || r.count != limit {
			t.Fatal("actual overread/lost bytes", r.count, budget.consumed)
		}
		if limit == ref.Bytes {
			if err != nil || !r.done {
				t.Fatal("real EOF/digest checks not completed", err)
			}
		} else if !errors.Is(err, ErrLimit) || r.done {
			t.Fatal("fabricated EOF", err)
		}
		r.Close()
	}
	// Growth at the exhausted boundary must not be hidden behind fabricated EOF.
	growing, err := snapshot.store.objectReader(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer growing.Close()
	growthBudget := &identityReadBudget{remaining: ref.Bytes}
	if n, err := growthBudget.read(growing, make([]byte, ref.Bytes)); uint64(n) != ref.Bytes || err != nil {
		t.Fatal("read before growth", n, err)
	}
	objectName := filepath.Join(root, filepath.FromSlash(objectPath(ref)))
	original := evidence.Records[0].Raw
	if err := os.WriteFile(objectName, append(append([]byte(nil), original...), 'x'), 0600); err != nil {
		t.Fatal(err)
	}
	if n, err := growthBudget.read(growing, make([]byte, 1)); n != 0 || err == nil || errors.Is(err, io.EOF) {
		t.Fatal("growth hidden/overread at boundary", n, err)
	}
	if growthBudget.consumed != ref.Bytes {
		t.Fatal("growth byte overread")
	}
	if err := os.WriteFile(objectName, original, 0600); err != nil {
		t.Fatal(err)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	r, err := snapshot.store.objectReader(cancelCtx, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	budget := &identityReadBudget{remaining: ref.Bytes}
	if n, err := budget.read(r, make([]byte, 7)); n != 7 || err != nil {
		t.Fatal(n, err)
	}
	cancel()
	if n, err := budget.read(r, make([]byte, 7)); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("mid-read cancellation", n, err)
	}
	if budget.consumed != 7 || r.count != 7 {
		t.Fatal("cancellation refunded bytes")
	}
}
