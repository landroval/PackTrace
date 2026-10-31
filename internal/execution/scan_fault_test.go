package execution

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestScanFaultMetadataDoesNotRetainRawErrorOrChangeAdmission(t *testing.T) {
	s := newRunState(context.Background())
	s.scan = newScanLifecycle(s.caller, s.deadline)
	run := ScanRun{output: BatchRun{state: s}}
	defer run.Finish()
	run.NoteFailure("PRIVATE-path", errors.New("PRIVATE-secret"))
	raw, _ := json.Marshal(s.scan.snapshot())
	if strings.Contains(string(raw), "PRIVATE") {
		t.Fatalf("raw diagnostic data retained: %s", raw)
	}
	if err := run.Checkpoint(); err != nil {
		t.Fatal("diagnostic recording changed resource admission", err)
	}
	receipt, err := run.Finish()
	if err != nil || receipt.FirstFault.Stage != "caller" || receipt.FirstFault.Code != "operation-failed" {
		t.Fatal(receipt, err)
	}
}

// Diagnostic state models only. Later failures/Finish must not replace the
// first observed fault; they must still invalidate output and retain cleanup.
func TestScanReceiptKeepsFirstFaultAfterLaterFailure(t *testing.T) {
	s := newRunState(context.Background())
	s.scan = newScanLifecycle(s.caller, s.deadline)
	run := ScanRun{output: BatchRun{state: s}}
	defer run.Finish()
	s.scan.mu.Lock()
	s.scan.last = time.Now().Add(-time.Second)
	s.scan.mu.Unlock()
	if err := run.Checkpoint(); err == nil {
		t.Fatal("stale sample accepted")
	}
	first, _ := json.Marshal(s.scan.snapshot())
	var before struct{ FirstFault struct{ Stage, Code string } }
	if err := json.Unmarshal(first, &before); err != nil {
		t.Fatal(err)
	}
	if before.FirstFault.Stage == "" || before.FirstFault.Code == "" {
		t.Fatalf("first operational fault not retained: %s", first)
	}
	s.scan.mu.Lock()
	s.scan.resources.QueryFailed = true
	s.scan.mu.Unlock()
	receipt, err := run.Finish()
	if err == nil || !receipt.Finished || !receipt.CleanupConfirmed {
		t.Fatal("fault turned into success or lost final receipt", receipt, err)
	}
	final, _ := json.Marshal(receipt)
	var after struct{ FirstFault struct{ Stage, Code string } }
	if err := json.Unmarshal(final, &after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("later fault replaced first: %s -> %s", first, final)
	}
}
