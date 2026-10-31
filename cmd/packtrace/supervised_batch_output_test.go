package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"packtrace/internal/execution"
	"packtrace/internal/inspect"
)

type batchUnownedWriter struct{ called bool }

func (w *batchUnownedWriter) Write(p []byte) (int, error) {
	w.called = true
	return len(p), nil
}

// Removing the concrete sink restriction could hang on an arbitrary writer.
func TestSupervisedOutputRejectsUnownedWriter(t *testing.T) {
	out := &batchUnownedWriter{}
	run := execution.BatchRun{}
	if err := run.WriteOutput(context.Background(), out, []byte("private")); err == nil || out.called {
		t.Fatalf("unowned writer: err=%v called=%t", err, out.called)
	}
}

func TestSupervisedOutputMemory(t *testing.T) {
	var out bytes.Buffer
	var text strings.Builder
	run := execution.BatchRun{}
	for _, sink := range []interface{ Write([]byte) (int, error) }{&out, &text} {
		if err := run.WriteOutput(context.Background(), sink, []byte("legacy\n")); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := run.WriteOutput(ctx, sink, []byte("extra")); err == nil || err.Error() != "inspect-batch: interrupted" {
			t.Fatalf("pre-canceled output: %v", err)
		}
	}
	if out.String() != "legacy\n" || text.String() != "legacy\n" {
		t.Fatal("memory bytes changed")
	}
}

// An expired work budget is not an explicit user interruption (exit 130).
func TestSupervisedOperationDeadlineNotInterrupt(t *testing.T) {
	input, keepOpen, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer keepOpen.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	var out, diag bytes.Buffer
	if exit := runBatchContext(ctx, nil, input, &out, &diag); exit != 2 || out.Len() != 0 {
		t.Fatalf("deadline: exit=%d stdout=%q stderr=%q", exit, out.String(), diag.String())
	}
}

func TestSupervisedInterruptAfterBudgetExpiry(t *testing.T) {
	interrupt, cancel := context.WithCancel(context.Background())
	defer cancel()
	budget, stop := context.WithDeadline(interrupt, time.Now().Add(-time.Second))
	defer stop()
	cancel()
	var out, diag bytes.Buffer
	// A child deadline keeps DeadlineExceeded even after its parent is canceled.
	// Sampling only budget.Err would lose this late explicit user interruption.
	if exit := renderSupervisedBatchContext(budget, interrupt, execution.BatchRun{}, errors.New("inspect-batch: worker-deadline"), "json", &out, &diag); exit != 130 {
		t.Fatalf("late interruption lost after deadline: %d", exit)
	}
}

func TestSupervisedRenderLiveCancellation(t *testing.T) {
	result, err := inspect.ReadBatch(strings.NewReader(batchInput))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, diag bytes.Buffer
	// No Interrupted bit or sampled bool supplies the expected precedence.
	if exit := renderSupervisedBatchContext(ctx, ctx, execution.BatchRun{Usable: true, Result: result}, nil, "json", &out, &diag); exit != 130 || out.Len() != 0 {
		t.Fatalf("live cancellation: exit=%d stdout=%q", exit, out.String())
	}
}
