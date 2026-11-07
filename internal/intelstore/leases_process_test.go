package intelstore

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"packtrace/internal/nativefs"
	"testing"
	"time"
)

func TestPinProcessHelper(t *testing.T) {
	path := os.Getenv("PACKTRACE_TEST_PIN_STORE")
	if path == "" {
		t.Skip("private snapshot pin child")
	}
	s, e := Open(context.Background(), path, ReadOnly)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p, e := s.Pin(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	if e := p.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestParentGenerationPinOutlivesActualReaderChild(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
	if e != nil {
		t.Fatal(e)
	}
	id, e := tx.seal(ctx, storageDraft(t, tx, "first"))
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.activate(ctx, id); e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	parent, e := s.Pin(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer parent.Close()
	childCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestPinProcessHelper$")
	cmd.Env = append(os.Environ(), "PACKTRACE_TEST_PIN_STORE="+path)
	if out, e := cmd.CombinedOutput(); e != nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 0 {
		t.Fatal("actual reader child/reap", e, string(out))
	}
	other, e := nativefs.OpenRoot(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	name := "generations/" + hex.EncodeToString(id[:]) + "/read.lock"
	if lease, e := other.TryOwnedLock(ctx, name, true); !errors.Is(e, nativefs.ErrBusy) || lease != nil {
		t.Fatal("child exit released parent's snapshot")
	}
	if e := parent.Close(); e != nil {
		t.Fatal(e)
	}
	lease, e := other.TryOwnedLock(ctx, name, true)
	if e != nil {
		t.Fatal("final parent close did not release", e)
	}
	lease.Close()
}
