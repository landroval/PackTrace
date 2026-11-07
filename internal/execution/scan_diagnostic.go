package execution

import (
	"context"
	"io"
)

// A failed destination/source binding must not suppress its own fixed diagnostic.
// This role exports no evidence: only allowlisted parent-selected error text, still
// through the bounded observed writer with confirmed cleanup/resource checks.
func (r *ScanRun) WriteDiagnostic(ctx context.Context, out io.Writer, code string) error {
	if !publicScanDiagnostic(code) {
		code = "scan: unavailable"
	}
	if err := r.diagnosticCheckpoint(); err != nil {
		return err
	}
	err := r.output.WriteOutput(ctx, out, []byte(code+"\n"))
	r.NoteFailure("diagnostic", err)
	if observed := r.diagnosticCheckpoint(); observed != nil {
		return observed
	}
	return err
}

func (r *ScanRun) diagnosticCheckpoint() error {
	if r.output.state == nil {
		return errScanResource
	}
	s := r.output.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scan == nil || s.broken {
		return errScanResource
	}
	s.scan.tick()
	r.Resources = s.scan.snapshot().Resources
	if err := s.contextError(s.caller); err != nil {
		return err
	}
	return s.scan.check()
}

func publicScanDiagnostic(code string) bool {
	if scanDiagnostic(code) {
		return true
	}
	switch code {
	case "scan: unavailable", "scan: unsupported-or-conflicting-options", "scan: worker-unavailable", "scan: worker-protocol", "scan: intelligence-binding-unavailable", "scan: cleanup-unconfirmed", "scan: worker-incomplete", "scan: interrupted", "scan: deadline", "scan: output-destination-unavailable", "scan: report-failed", "cli: output-failed":
		return true
	}
	return false
}
