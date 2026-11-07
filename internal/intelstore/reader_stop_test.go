package intelstore

import (
	"context"
	"errors"
	"testing"

	"packtrace/internal/intel"
)

func TestWalkIdentityStopStillChecksContextAndLease(t *testing.T) {
	for _, failure := range []string{"none", "context", "lease"} {
		t.Run(failure, func(t *testing.T) {
			snapshot, _ := limitedSnapshot(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			var expected uint64
			used, err := snapshot.WalkIdentities(ctx, groupedDiskNames(t, 2), 8<<30, func(_ string, e intel.SnapshotNPMEvidence) error {
				calls++
				expected += e.BytesRead
				if failure == "context" {
					cancel()
				}
				if failure == "lease" {
					if e := snapshot.pin.lease.Close(); e != nil {
						t.Fatal(e)
					}
				}
				return ErrIdentityWalkStopped
			})
			if calls != 1 || used == 0 || used != expected {
				t.Fatal("stop read/byte accounting", calls, used, expected, err)
			}
			if failure == "none" {
				if err != nil {
					t.Fatal("controlled stop failed", err)
				}
				if _, e := snapshot.ReadIdentity(context.Background(), "left-pad"); e != nil {
					t.Fatal("stop left snapshot unusable", e)
				}
			} else if err == nil || errors.Is(err, ErrIdentityWalkStopped) || failure == "context" && !errors.Is(err, context.Canceled) {
				t.Fatal("controlled stop swallowed actual final failure", failure, err)
			}
		})
	}
}
