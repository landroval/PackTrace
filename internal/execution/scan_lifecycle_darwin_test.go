//go:build darwin && cgo && (amd64 || arm64)

package execution

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Actual owned writer, blocked inherited sink, retained native observation and
// confirmed cancellation/join/reap. Native-only; compilation is not execution.
func TestDarwinScanBlockedWriterObservedThroughCancellationAndReap(t *testing.T) {
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
	until := time.Now().Add(4 * time.Second)
	for {
		r := s.scan.snapshot()
		if len(r.Roles) == 1 && r.Roles[0].Samples >= 3 {
			break
		}
		if time.Now().After(until) {
			cancel()
			select {
			case <-result:
			case <-time.After(3 * time.Second):
			}
			t.Fatal("owned Darwin writer not sampled", r)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("canceled writer became success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("owned Darwin writer did not join/reap")
	}
	receipt, e := run.Finish()
	if e == nil || !receipt.Finished || !receipt.CleanupConfirmed || len(receipt.Roles) != 1 {
		t.Fatal(receipt, e)
	}
	role := receipt.Roles[0]
	if role.Role != "scan-writer" || role.Samples < 3 || !role.ExitObserved || !role.Reaped || !role.WaitReturned || !role.ExchangeJoined || !role.StderrJoined || receipt.Resources.QueryFailed || receipt.Resources.Stale {
		t.Fatal("Darwin lifecycle/observation gap", receipt)
	}
	t.Logf("actual Darwin canceled writer receipt: %+v roles=%+v", receipt, receipt.Roles)
}
