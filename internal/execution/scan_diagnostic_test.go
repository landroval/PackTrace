package execution

import (
	"bytes"
	"context"
	"testing"

	"packtrace/internal/cli"
)

func TestScanFailedDestinationStillHasBoundedPrivateSafeDiagnostic(t *testing.T) {
	s := newRunState(context.Background())
	s.scan = newScanLifecycle(s.caller, s.deadline)
	r := ScanRun{output: BatchRun{state: s}, fileOutput: &scanFileOutputState{}}
	defer r.Finish()
	if r.Checkpoint() == nil {
		t.Fatal("failed destination admitted a normal checkpoint")
	}
	var out bytes.Buffer
	if err := r.WriteDiagnostic(context.Background(), &out, "scan: output-destination-unavailable"); err != nil || out.String() != "scan: output-destination-unavailable\n" {
		t.Fatal("refusal suppressed diagnostic", err, out.String())
	}
	out.Reset()
	if err := r.WriteDiagnostic(context.Background(), &out, "scan: intelligence-binding-unavailable"); err != nil || out.String() != cli.DiagnosticText("scan: intelligence-binding-unavailable") {
		t.Fatal("guidance escaped bounded diagnostic writer", err, out.String())
	}
	out.Reset()
	if err := r.WriteDiagnostic(context.Background(), &out, "PRIVATE /home/PRIVATE secret"); err != nil || out.String() != "scan: unavailable\n" {
		t.Fatal("diagnostic became private-data output bypass", err, out.String())
	}
}
