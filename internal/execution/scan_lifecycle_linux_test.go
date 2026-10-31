//go:build linux && (amd64 || arm64)

package execution

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"packtrace/internal/integrityscan"
)

func TestScanParentRenderingAndSequentialWriterHaveFinalReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := newRunState(ctx)
	s.scan = newScanLifecycle(ctx, s.deadline)
	run := ScanRun{output: BatchRun{state: s}}
	defer run.Finish()
	before := s.scan.snapshot()
	// Perform actual bounded parent rendering with no child/protocol. Removing
	// continuous parent observation loses at least two real parent samples.
	report := integrityscan.Report{}
	renders := 0
	until := time.Now().Add(220 * time.Millisecond)
	for time.Now().Before(until) {
		if _, e := integrityscan.Render(report, "json"); e != nil {
			t.Fatal(e)
		}
		renders++
	}
	if e := run.Checkpoint(); e != nil {
		t.Fatal(e)
	}
	prepared := s.scan.snapshot()
	if prepared.Resources.SupervisorSamples < before.Resources.SupervisorSamples+2 || prepared.Resources.WorkerSamples != 0 || prepared.Finished {
		t.Fatalf("parent-only interval unobserved/future completion claimed: %+v", prepared)
	}
	f, e := os.CreateTemp(t.TempDir(), "approved-output")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = run.WriteOutput(ctx, f, []byte("approved\n")); e != nil {
		t.Fatal(e)
	}
	post := s.scan.snapshot()
	if post.Finished || len(post.Roles) != 1 || post.Roles[0].Role != "scan-writer" || !post.Roles[0].Reaped || !post.Roles[0].ExitObserved || post.Roles[0].Samples < 1 || post.Roles[0].PeakResidentBytes == 0 {
		t.Fatalf("writer not actually attributed through reap: %+v", post)
	}
	if post.Resources.WorkerSamples <= prepared.Resources.WorkerSamples {
		t.Fatal("future writer samples were fabricated in pre-output snapshot")
	}
	receipt, e := run.Finish()
	if e != nil || !receipt.Finished || !run.Operational.Finished || !receipt.CleanupConfirmed || receipt.MaxSampleGap > 350*time.Millisecond {
		t.Fatal(receipt, e)
	}
	if _, e := run.Finish(); e != nil {
		t.Fatal("Finish not idempotent", e)
	}
	data, e := os.ReadFile(f.Name())
	if e != nil || string(data) != "approved\n" {
		t.Fatal("approved bytes changed", string(data), e)
	}
	t.Logf("actual complete caller receipt after %d renders: %+v roles=%+v", renders, receipt, receipt.Roles)
}

func TestScanBlockedWriterRemainsObservedUntilCancelReap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newRunState(ctx)
	s.scan = newScanLifecycle(ctx, s.deadline)
	run := ScanRun{output: BatchRun{state: s}}
	defer run.Finish()
	read, write, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer read.Close()
	defer write.Close()
	result := make(chan error, 1)
	go func() { result <- run.WriteOutput(ctx, write, []byte(strings.Repeat("APPROVED", 1<<17))) }()
	pid := waitRole(t, WriterArgument)
	deadline := time.Now().Add(2 * time.Second)
	for {
		r := s.scan.snapshot()
		if len(r.Roles) == 1 && r.Roles[0].Samples >= 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("blocked writer not sampled", r)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("cancel became output success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer cancellation did not join/reap")
	}
	receipt, e := run.Finish()
	if e == nil || len(receipt.Roles) != 1 || receipt.Roles[0].PID != pid || !receipt.Roles[0].Reaped || !receipt.CleanupConfirmed || receipt.Resources.Stale || receipt.Resources.QueryFailed {
		t.Fatal(receipt, e)
	}
	if pids, _ := ownChildren(); len(pids) != 0 {
		t.Fatal("live owned child after cancel", pids)
	}
	t.Logf("actual cancelled caller receipt: %+v roles=%+v", receipt, receipt.Roles)
}

func TestScanLiveQueryFailureCancelsAndReapsWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := newRunState(ctx)
	s.scan = newScanLifecycle(ctx, s.deadline)
	run := ScanRun{output: BatchRun{state: s}}
	defer run.Finish()
	read, write, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer read.Close()
	defer write.Close()
	result := make(chan error, 1)
	go func() { result <- run.WriteOutput(ctx, write, []byte(strings.Repeat("APPROVED", 1<<17))) }()
	_ = waitRole(t, WriterArgument)
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.scan.mu.Lock()
		if s.scan.child != nil && len(s.scan.roles) == 1 && s.scan.roles[0].Samples > 0 {
			break
		}
		s.scan.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("no retained live child sample")
		}
		time.Sleep(time.Millisecond)
	}
	// Actually destroy the live query capability, not a fake zero or supplied
	// resource flag. The next query must cancel the owned blocked writer.
	_ = s.scan.child.Close()
	s.scan.mu.Unlock()
	s.scan.tick()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("query failure became output success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("query failure did not cancel/join/reap")
	}
	receipt, e := run.Finish()
	if e == nil || !receipt.Resources.QueryFailed || !receipt.CleanupConfirmed || len(receipt.Roles) != 1 || !receipt.Roles[0].Reaped {
		t.Fatal(receipt, e)
	}
	var next strings.Builder
	if e := run.WriteOutput(ctx, &next, []byte("must-not-commit")); e == nil || next.Len() != 0 {
		t.Fatal("next output after live observation failure", e)
	}
	if pids, _ := ownChildren(); len(pids) != 0 {
		t.Fatal("live owned child after query failure", pids)
	}
	t.Logf("actual query-failed caller receipt: %+v roles=%+v", receipt, receipt.Roles)
}

func TestScanConcurrentOutputKeepsResourceStateSerialized(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := newRunState(ctx)
	s.scan = newScanLifecycle(ctx, s.deadline)
	run := ScanRun{output: BatchRun{state: s}}
	defer run.Finish()
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			var output strings.Builder
			for j := 0; j < 20; j++ {
				if e := run.WriteOutput(ctx, &output, []byte("approved\n")); e != nil {
					done <- e
					return
				}
			}
			if output.String() != strings.Repeat("approved\n", 20) {
				done <- errors.New("approved bytes changed")
				return
			}
			done <- nil
		}()
	}
	for i := 0; i < 2; i++ {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
	if receipt, e := run.Finish(); e != nil || !receipt.CleanupConfirmed {
		t.Fatal(receipt, e)
	}
}

func TestScanOperationalGapsRefuseNextWriter(t *testing.T) {
	for _, mode := range []string{"stale", "query-failed", "threshold", "cleanup-unknown", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := newRunState(ctx)
			s.scan = newScanLifecycle(ctx, s.deadline)
			run := ScanRun{output: BatchRun{state: s}}
			defer run.Finish()
			// Boundary state models, NOT native failure qualification. Real failed
			// live-proc reads and identity negatives are tested in nativeresource.
			s.scan.mu.Lock()
			switch mode {
			case "stale":
				s.scan.last = time.Now().Add(-time.Second)
			case "query-failed":
				s.scan.resources.QueryFailed = true
			case "threshold":
				s.scan.resources.Stopped = true
			case "cleanup-unknown":
				s.broken = true
			case "deadline":
				s.deadline = time.Now().Add(-time.Second)
			}
			s.scan.mu.Unlock()
			var output strings.Builder
			e := run.WriteOutput(ctx, &output, []byte("must-not-commit"))
			if e == nil || output.Len() != 0 {
				t.Fatal("operational fault committed bytes", e, output.String())
			}
			if r := s.scan.snapshot(); len(r.Roles) != 0 {
				t.Fatal("next writer launched after fault", r)
			}
			if mode == "cleanup-unknown" && !errors.Is(e, errReap) {
				t.Fatal("reap uncertainty lost", e)
			}
		})
	}
}
