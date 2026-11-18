//go:build linux && (amd64 || arm64)

package execution

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"packtrace/internal/cli"
)

func TestScanFinalPeakBoundaries(t *testing.T) {
	joined := ScanRoleReceipt{Reaped: true, WaitReturned: true, ExchangeJoined: true, StderrJoined: true}
	for _, tc := range []struct {
		name                     string
		own, child, sample, want uint64
		status                   string
	}{
		{"equal", 1 << 29, 1 << 29, 0, 1 << 30, "observed"},
		{"above", 1 << 29, 1<<29 + 1, 0, 1<<30 + 1, "observed"},
		{"saturate", math.MaxUint64 - 1, 2, 0, math.MaxUint64, "observed"},
		{"missing-own", 0, 1024, 0, 1024, "missing"},
		{"missing-wait-keeps-sample", 1024, 0, 2048, 3072, "missing"},
		{"larger-sample", 1024, 1024, 2048, 3072, "observed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := joined
			r.WaitPeakResidentBytes, r.PeakResidentBytes = tc.child, tc.sample
			got := accountScanPeaks(tc.own, 0, []ScanRoleReceipt{r})
			if got.Status != tc.status || got.SumPeakResidentBytes != tc.want {
				t.Fatal(got)
			}
		})
	}
	for _, field := range []string{"reap", "wait", "exchange", "stderr"} {
		r := joined
		r.WaitPeakResidentBytes = 1024
		switch field {
		case "reap":
			r.Reaped = false
		case "wait":
			r.WaitReturned = false
		case "exchange":
			r.ExchangeJoined = false
		case "stderr":
			r.StderrJoined = false
		}
		if got := accountScanPeaks(1024, 0, []ScanRoleReceipt{r}); got.Status != "missing" || got.SumPeakResidentBytes != 2048 {
			t.Fatal(field, got)
		}
	}
	if got := accountScanPeaks(1024, 4096, nil); got.SumPeakResidentBytes != 4096 || got.SupervisorPeakResidentBytes != 1024 {
		t.Fatal("native peak must not discard an already larger sample", got)
	}
	for _, tc := range []struct {
		supported bool
		own       uint64
		err       error
		want      string
	}{
		{false, 0, nil, "unsupported"},
		{true, 0, nil, "missing"},
		{true, 0, errors.New("query failure"), "failed"},
		{true, 1024, nil, "observed"},
	} {
		if got := scanPeakStatus(tc.supported, tc.own, tc.err, "observed"); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
	for _, kib := range []int64{-1, 0} {
		if got := linuxPeakBytes(kib); got != 0 {
			t.Fatal(kib, got)
		}
	}
	for _, kib := range []int64{math.MaxInt64, int64(math.MaxUint64/1024) + 1} {
		if got := linuxPeakBytes(kib); got != math.MaxUint64 {
			t.Fatal("positive unrepresentable peak lost", kib, got)
		}
	}
	if got := linuxPeakBytes(int64(math.MaxUint64 / 1024)); got != math.MaxUint64/1024*1024 {
		t.Fatal(got)
	}
	if waitPeakResidentBytes(nil) != 0 {
		t.Fatal("nil wait became observed")
	}
}

func TestScanFinalPeakMissingJoinRetainsLowerBound(t *testing.T) {
	ctx := context.Background()
	s := newRunState(ctx)
	s.scan = newScanLifecycle(ctx, s.deadline)
	run := ScanRun{output: BatchRun{state: s}}
	defer run.Finish()
	// Boundary model: reap alone must not imply the expected role joins.
	s.scan.mu.Lock()
	s.scan.roles = []ScanRoleReceipt{{Role: "scan", Reaped: true, WaitPeakResidentBytes: 1<<30 + 1}}
	s.scan.mu.Unlock()
	r, err := run.Finish()
	if !errors.Is(err, errScanResource) || r.Finalization.Status != "missing" || !r.Resources.Stale || !r.Resources.Stopped || r.Finalization.SumPeakResidentBytes <= 1<<30 {
		t.Fatal(r, err)
	}
}

func TestScanFinalPeakAfterSourceCloseFailure(t *testing.T) {
	run, base, dest := fileTransportFixture(t, true)
	if err := run.WriteReportOutput(context.Background(), nil, []byte("frozen")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "reference", "late"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := run.Finish()
	if err == nil || r.FirstFault.Stage != "file-output-close" || !run.fileOutput.closed || r.Finalization.Status != "observed" {
		t.Fatal(r, err)
	}
	if _, again := run.Finish(); again == nil {
		t.Fatal("late close error lost on repeated Finish")
	}
	if data, err := os.ReadFile(dest); err != nil || string(data) != "frozen" {
		t.Fatal(string(data), err)
	}
}

func TestScanFinalPeakLateOverride(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "resource", true: "cancel"}[canceled], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := newRunState(ctx)
			s.scan = newScanLifecycle(ctx, s.deadline)
			run := ScanRun{output: BatchRun{state: s}}
			defer run.Finish()
			f, err := os.CreateTemp(t.TempDir(), "output")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := run.WriteOutput(ctx, f, []byte("frozen comparison\n")); err != nil {
				t.Fatal(err)
			}
			before := s.scan.snapshot()
			if len(before.Roles) != 1 || before.Roles[0].WaitPeakResidentBytes == 0 || before.Finalization.Status != "" {
				t.Fatal(before)
			}
			// Boundary injection AFTER a real owned writer was joined/reaped.
			// This is not a native over-budget campaign or production exit claim.
			run.NoteFailure("render", errors.New("original fault"))
			first := s.scan.snapshot().FirstFault
			s.scan.mu.Lock()
			s.scan.roles[0].WaitPeakResidentBytes = 1<<30 + 1
			s.scan.mu.Unlock()
			if canceled {
				cancel()
			}
			receipt, err := run.Finish()
			if !errors.Is(err, errScanResource) || !receipt.Resources.Stopped || receipt.Finalization.Status != "observed" || receipt.Finalization.SupervisorPeakResidentBytes == 0 || receipt.FirstFault != first {
				t.Fatal(receipt, err)
			}
			conditions := cli.ScanExitConditions{Interrupted: canceled, ReportPreventingError: err != nil, RequiredCoverageIncomplete: true, EnforcedUnacceptedFindings: true}
			want := 2
			if canceled {
				want = 130
			}
			if got := cli.SelectScanExit(conditions); got != want {
				t.Fatal(got, want)
			}
			again, againErr := run.Finish()
			if !errors.Is(againErr, errScanResource) || again.Finalization != receipt.Finalization {
				t.Fatal(again, againErr)
			}
			data, err := os.ReadFile(f.Name())
			if err != nil || string(data) != "frozen comparison\n" {
				t.Fatal(string(data), err)
			}
			t.Logf("boundary-injected late override=%d final=%+v first=%+v roles=%+v", want, receipt.Finalization, receipt.FirstFault, receipt.Roles)
		})
	}
}
