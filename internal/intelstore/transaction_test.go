package intelstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func transactionFixture(t *testing.T) (*Store, string) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native transaction")
	}
	path := filepath.Join(t.TempDir(), "state")
	s, e := Open(context.Background(), path, CreateOwned)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}
func TestTransactionReservesBeforeReadingAndSerializesWriters(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20, Deadline: time.Now().Add(time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	if other, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20}); !errors.Is(e, ErrBusy) || other != nil {
		t.Fatal("second writer admitted", e)
	}
	if e := s.Close(); !errors.Is(e, ErrBusy) {
		t.Fatal("store closed active transaction", e)
	}
	ref, e := tx.put(ctx, bytes.NewBufferString("hello"), 5)
	if e != nil || ref.SHA256 != sha256.Sum256([]byte("hello")) || ref.Bytes != 5 {
		t.Fatal("bounded put", ref, e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	next, e := s.begin(ctx, operationImport, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal("writer did not release", e)
	}
	if e := next.Close(); e != nil {
		t.Fatal(e)
	}
}

type transactionFailReader struct{ read bool }

func (r *transactionFailReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.ErrUnexpectedEOF
	}
	r.read = true
	return copy(p, "partial"), io.ErrUnexpectedEOF
}

type transactionCanaryReader struct{ read bool }

func (r *transactionCanaryReader) Read(p []byte) (int, error) { r.read = true; return 0, io.EOF }

func TestTransactionFailedBytesStayChargedAndQuotaPrecedesInput(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	s.quotaLimit = 4096
	canary := &transactionCanaryReader{}
	if tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 8192}); !errors.Is(e, ErrLimit) || tx != nil {
		t.Fatal("unreserved writer admitted", e)
	}
	if canary.read {
		t.Fatal("unadmitted source read")
	}
	s.quotaLimit = 32 << 30
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := tx.put(ctx, &transactionFailReader{}, 16); e == nil {
		t.Fatal("failed reader reported success")
	}
	if _, e := tx.put(ctx, canary, 1); e == nil || canary.read {
		t.Fatal("failed transaction resumed acquisition")
	}
	tx.Close()
	var found bool
	filepath.WalkDir(filepath.Join(path, "staging"), func(p string, d os.DirEntry, e error) error {
		if e == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			found = found || string(b) == "partial"
		}
		return e
	})
	if !found {
		t.Fatal("failed partial bytes erased")
	}
	next, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal("failed reservation not reconciled", e)
	}
	next.Close()
}

func TestTransactionObjectReservationPrecedesReader(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 8192})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	input := &transactionCanaryReader{}
	if _, e := tx.put(ctx, input, 8192); !errors.Is(e, ErrLimit) || input.read {
		t.Fatal("reader consumed before object reservation", e)
	}
}

func TestTransactionUpdatesDoNotInvalidateExistingRootReader(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	ref, e := tx.put(ctx, bytes.NewBufferString("first"), 5)
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	reader, e := Open(ctx, path, ReadOnly)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	tx, e = s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := tx.put(ctx, bytes.NewBufferString("second"), 6); e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	key := hex.EncodeToString(ref.SHA256[:])
	f, e := reader.root.OpenInput(ctx, "objects/"+key[:2]+"/"+key, 5)
	if e != nil {
		t.Fatal("legitimate writer invalidated pinned root", e)
	}
	b, e := io.ReadAll(f)
	stable, closed := f.Stable(), f.Close()
	if e != nil || stable != nil || closed != nil || string(b) != "first" {
		t.Fatal("old object changed")
	}
}

func TestTransactionRefusesCorruptReservationJournal(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	journal := filepath.Join(path, filepath.FromSlash(tx.path), "intent.json")
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(journal, []byte(`{"version":1,"version":1}`), 0600); e != nil {
		t.Fatal(e)
	}
	if next, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20}); !errors.Is(e, ErrCorrupt) || next != nil {
		t.Fatal("corrupt old reservation ignored", e)
	}
}

func TestTransactionDedupVerifiesExistingBlobAndDoesNotDropUnknown(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	want := sha256.Sum256([]byte("first"))
	sum := hex.EncodeToString(want[:])
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	a, e := tx.put(ctx, bytes.NewBufferString("first"), 5)
	if e != nil {
		t.Fatal(e)
	}
	b, e := tx.put(ctx, bytes.NewBufferString("first"), 5)
	if e != nil || a != b {
		t.Fatal("dedup mismatch", e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "objects", sum[:2], sum), []byte("other"), 0600); e != nil {
		t.Fatal(e)
	}
	tx, e = s.begin(ctx, operationSync, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	if _, e := tx.put(ctx, bytes.NewBufferString("first"), 5); !errors.Is(e, ErrCorrupt) {
		t.Fatal("hash-named corrupt object reused", e)
	}
}
