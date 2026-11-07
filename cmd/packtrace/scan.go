package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/execution"
	"packtrace/internal/integrityscan"
)

// An observer receives caller-owned completion evidence only after Finish.
// Production supplies nil: there is no flag, environment switch or fallback I/O.
type scanObserver func(execution.ScanReceipt)

func runScan(request cli.ScanArgumentRequest, out, diagnostic io.Writer) int {
	return runScanObserved(request, out, diagnostic, nil)
}
func runScanObserved(request cli.ScanArgumentRequest, out, diagnostic io.Writer, observed scanObserver) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runScanContextObserved(ctx, request, out, diagnostic, observed)
}
func runScanContext(ctx context.Context, request cli.ScanArgumentRequest, out, diagnostic io.Writer) int {
	return runScanContextObserved(ctx, request, out, diagnostic, nil)
}
func runScanContextObserved(ctx context.Context, request cli.ScanArgumentRequest, out, diagnostic io.Writer, observed scanObserver) (exit int) {
	work, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	old := debug.SetMemoryLimit(128 << 20)
	defer debug.SetMemoryLimit(old)
	run, err := execution.RunScan(work, request)
	run.NoteFailure("run", err)
	interrupted := errors.Is(ctx.Err(), context.Canceled)
	conditions := cli.ScanExitConditions{Interrupted: interrupted, ReportPreventingError: !run.Usable || !reportableScanFailure(err)}
	defer func() {
		// This operational receipt necessarily exists AFTER public bytes. Never
		// predict it in the comparison report or recursively render new metrics.
		receipt, finishErr := run.Finish()
		if finishErr != nil {
			conditions.ReportPreventingError = true
		}
		conditions.Interrupted = conditions.Interrupted || errors.Is(ctx.Err(), context.Canceled)
		exit = cli.SelectScanExit(conditions)
		if observed != nil {
			observed(receipt)
		}
	}()
	selectExit := func() int {
		conditions.Interrupted = conditions.Interrupted || errors.Is(ctx.Err(), context.Canceled)
		return cli.SelectScanExit(conditions)
	}
	fail := func(code string) int {
		if work.Err() == nil && !conditions.Interrupted {
			if e := run.WriteDiagnostic(work, diagnostic, code); e != nil {
				run.NoteFailure("diagnostic", e)
			}
		}
		conditions.ReportPreventingError = true
		return selectExit()
	}
	if !run.Usable || conditions.ReportPreventingError {
		code := "scan: unavailable"
		if err != nil {
			code = err.Error()
		}
		return fail(code)
	}
	if e := run.Checkpoint(); e != nil {
		run.NoteFailure("checkpoint", e)
		return fail("scan: resident-observation-failed")
	}
	report := integrityscan.BuildReportWithPolicy(run.Plan, run.Records, run.Summary, run.Resources, interrupted, err != nil, run.Inventory, run.Intelligence, run.Advisories, run.PolicyMaterials, run.PolicyMaterialLimited, time.Now().UTC())
	comparison := integrityscan.ReportConditions(report)
	conditions.RequiredCoverageIncomplete = comparison.RequiredCoverageIncomplete
	conditions.EnforcedUnacceptedFindings = comparison.EnforcedUnacceptedFindings
	conditions.ReportPreventingError = conditions.ReportPreventingError || comparison.ReportPreventingError
	data, renderErr := integrityscan.Render(report, request.Format)
	if renderErr != nil {
		run.NoteFailure("render", renderErr)
		return fail("scan: report-failed")
	}
	if e := run.Checkpoint(); e != nil {
		run.NoteFailure("checkpoint", e)
		return fail("scan: resident-observation-failed")
	}
	if e := run.WriteReportOutput(work, out, data); e != nil {
		run.NoteFailure("output", e)
		return fail("cli: output-failed")
	}
	return selectExit()
}

// These fixed worker failures can leave independently admitted results. A
// selected policy error, unsafe binding or unknown error cannot become a gap.
func reportableScanFailure(err error) bool {
	if err == nil {
		return true
	}
	switch err.Error() {
	case "scan: acquisition-unavailable", "scan: worker-incomplete", "scan: input-unusable":
		return true
	}
	return false
}
