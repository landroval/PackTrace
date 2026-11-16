package intelstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"packtrace/internal/intel"
)

func TestOriginalAuditReadsAllObjectsAndChargesFailures(t *testing.T) {
	for _, mode := range []string{"verified", "missing", "corrupt", "limited", "canceled", "closed"} {
		t.Run(mode, func(t *testing.T) {
			snapshot, path := limitedSnapshot(t)
			var digest [32]byte
			var size uint64
			var ok bool
			digest, size, ok = snapshot.catalog.Reference(0)
			if !ok {
				t.Fatal("fixture original missing")
			}
			limit := uint64(512 << 20)
			ctx := context.Background()
			switch mode {
			case "missing":
				if err := os.Remove(filepath.Join(path, filepath.FromSlash(objectPath(ObjectRef{digest, size})))); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(filepath.Join(path, filepath.FromSlash(objectPath(ObjectRef{digest, size}))), []byte("corrupt-original"), 0600); err != nil {
					t.Fatal(err)
				}
			case "limited":
				limit = size - 1
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				if err := snapshot.Close(); err != nil {
					t.Fatal(err)
				}
			}
			count := 0
			used, err := snapshot.WalkOriginals(ctx, limit, func(ordinal uint64, record intel.SnapshotOriginalEvidence) error {
				count++
				if ordinal != 0 || record.SHA256 != digest || record.Bytes != size || record.State != intel.SnapshotOriginalVerified || len(record.Raw) != int(size) {
					t.Fatal("unbound original")
				}
				return nil
			})
			if used > limit {
				t.Fatal("budget overrun", used, limit)
			}
			if mode == "verified" {
				if err != nil || count != 1 || used != size {
					t.Fatal("original audit", used, count, err)
				}
			} else if err == nil || count != 0 {
				t.Fatal("failed original became evidence", mode, used, count, err)
			}
			if mode == "limited" && (!errors.Is(err, ErrLimit) || used != limit) {
				t.Fatal("failed reads not charged", used, err)
			}
		})
	}
}

func TestParentSnapshotObservationSharesReadBudget(t *testing.T) {
	snapshot, _ := limitedSnapshot(t)
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	id := snapshot.pin.ID()
	original, err := snapshot.Observe(context.Background(), now, &id)
	if err != nil {
		t.Fatal(err)
	}
	observed, want, err := snapshot.ObserveLimited(context.Background(), now, &id, 512<<20)
	if err != nil || want == 0 || !reflect.DeepEqual(original, observed) {
		t.Fatal("bounded observation changed evidence", want, err)
	}
	for _, limit := range []uint64{0, 1, want - 1, want} {
		got, used, err := snapshot.ObserveLimited(context.Background(), now, &id, limit)
		if limit < want {
			if !errors.Is(err, ErrLimit) || used != limit || !reflect.DeepEqual(got, Observation{}) {
				t.Fatal("failed observation must charge reads and return no evidence", limit, used, err)
			}
		} else if err != nil || used != want || !reflect.DeepEqual(got, original) {
			t.Fatal("exact observation budget", used, err)
		}
	}
}

func TestParentSnapshotAcquisitionSharesReadBudget(t *testing.T) {
	snapshot, _ := limitedSnapshot(t)
	id := snapshot.pin.ID()
	// The already retained snapshot's descriptor, manifest and catalog define the
	// exact independent parent read cost. Seal/pin metadata has separate native caps.
	want := snapshot.descriptorRef.Bytes + snapshot.descriptor.Manifest.Bytes + snapshot.manifest.Originals.Bytes
	for _, limit := range []uint64{0, 1, want - 1, want, want + 1} {
		got, used, err := snapshot.store.ReadPinnedLimited(context.Background(), &id, limit)
		if used > limit {
			t.Fatal("acquisition exceeded shared budget")
		}
		if limit < want {
			if err == nil || got != nil || used != limit {
				t.Fatal("limited acquisition", limit, used, err)
			}
		} else {
			if err != nil || got == nil || used != want {
				t.Fatal("exact acquisition", limit, used, err)
			}
			if err := got.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}
