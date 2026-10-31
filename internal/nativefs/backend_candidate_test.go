//go:build !linux || (!amd64 && !arm64)

package nativefs

import (
	"context"
	"errors"
	"testing"
)

// This is only a fail-closed build contract, never platform qualification or a
// regular-file positive control. The backend returns before any target syscall.
func TestCandidateDoesNotActivateAnUnprovenOpener(t *testing.T) {
	if !errors.Is(PrepareProcess(), ErrUnavailable) {
		t.Fatal("unproven mechanism activated")
	}
	r, err := OpenRoot(context.Background(), "owned-fixture-not-accessed")
	if r != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("candidate admitted target access")
	}
}
