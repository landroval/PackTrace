package intelstore

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestIndexMembershipLimitPreservesPriorRows(t *testing.T) {
	p := &preparationState{}
	p.record.Memberships = 1_999_999
	row := indexRow{V: 1, IdentityHash: strings.Repeat("2a", 32), Name: "left-pad", Ecosystem: "npm"}
	if e := p.admitRow(row); e != nil {
		t.Fatal(e)
	}
	if e := p.admitRow(row); !errors.Is(e, ErrLimit) {
		t.Fatal("membership ceiling bypassed", e)
	}
	if p.record.Memberships != 2_000_000 || p.counts[0x2a] != 1 || len(p.rows) != 1 {
		t.Fatal("prior admitted evidence corrupted")
	}
}

type archiveCanaryAt struct{ read bool }

func (r *archiveCanaryAt) ReadAt([]byte, int64) (int, error) {
	r.read = true
	return 0, errors.New("owned canary")
}
func TestArchiveCompressedBoundPrecedesAnyRead(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, err := s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	r := &archiveCanaryAt{}
	if _, e := prepareArchive(ctx, tx, r, (1<<30)+1); !errors.Is(e, ErrLimit) || r.read {
		t.Fatal("oversized acquisition read", e)
	}
}
