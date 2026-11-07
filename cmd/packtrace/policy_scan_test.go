package main

import (
	"errors"
	"testing"

	"packtrace/internal/integrityscan"
)

func TestPolicyScanOnlyRepresentableWorkerFailuresRemainReportable(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, true},
		{errors.New("scan: acquisition-unavailable"), true},
		{errors.New("scan: worker-incomplete"), true},
		{errors.New("scan: input-unusable"), true},
		{integrityscan.ErrPolicy, false},
		{integrityscan.ErrOptions, false},
		{errors.New("scan: cleanup-unconfirmed"), false},
		{errors.New("scan: intelligence-binding-unavailable"), false},
		{errors.New("scan: resident-observation-failed"), false},
		{errors.New("unrecognized error"), false},
	} {
		if got := reportableScanFailure(tc.err); got != tc.want {
			t.Fatalf("reportable(%v) = %t; want %t", tc.err, got, tc.want)
		}
	}
}
