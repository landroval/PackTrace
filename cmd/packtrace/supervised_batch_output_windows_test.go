//go:build windows

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"packtrace/internal/execution"
)

// Executable Windows test candidate, cross-compiled here, NOT native evidence.
// A synchronous inherited sink belongs only to the killable writer process;
// there is no parent synchronous write or native-thread cancellation loop.
func TestSupervisedWindowsOutputSynchronousPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	run := execution.BatchRun{}
	if err = run.WriteOutput(ctx, w, bytes.Repeat([]byte("x"), 1<<20)); err == nil || err.Error() != "inspect-batch: worker-deadline" {
		t.Fatalf("synchronous pipe deadline (startup failure is not cancellation proof): %v", err)
	}
	if elapsed := time.Since(start); elapsed < 75*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("synchronous pipe cancellation outside deadline bound: %s", elapsed)
	}
	if _, err = w.Stat(); err != nil {
		t.Fatalf("caller's handle closed: %v", err)
	}
}

func TestSupervisedWindowsOutputBytes(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	run := execution.BatchRun{}
	if err = run.WriteOutput(context.Background(), f, []byte("legacy\n")); err != nil {
		t.Fatal(err)
	}
	_, _ = f.Seek(0, 0)
	data, err := io.ReadAll(f)
	if err != nil || string(data) != "legacy\n" {
		t.Fatalf("bytes: %q %v", data, err)
	}
}
