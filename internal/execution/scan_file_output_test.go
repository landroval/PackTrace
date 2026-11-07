package execution

import (
	"context"
	"testing"

	"packtrace/internal/nativefs"
)

// A Publication is deliberately not a generic writer escape hatch around the
// terminable output process. No native publication is opened by this test.
func TestScanFilePublicationCannotBypassWriterTransport(t *testing.T) {
	var run ScanRun
	publication := &nativefs.Publication{}
	if e := run.WriteOutput(context.Background(), publication, []byte("approved report")); e != errOutput {
		t.Fatalf("publication incorrectly admitted as writer transport: %v", e)
	}
	if publication.Bytes() != 0 {
		t.Fatal("rejected transport touched publication")
	}
}

func TestScanFilePublicationRejectsTypedNil(t *testing.T) {
	var run ScanRun
	var publication *nativefs.Publication
	if e := run.WriteOutput(context.Background(), publication, []byte("approved report")); e != errOutput {
		t.Fatalf("nil publication incorrectly admitted: %v", e)
	}
}
