package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/execution"
	"packtrace/internal/inspect"
)

// Only the real inspect-batch invocation changes interrupt handling. Other
// commands retain their existing behavior, including direct test callers.
func runMain(args []string, in io.Reader, out, diagnostic io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case execution.ScanWorkerArgument:
			if len(args) != 1 {
				return failure(diagnostic, "scan: invalid-worker-arguments")
			}
			return execution.ScanWorkerMain(in, out, diagnostic)
		case execution.WorkerArgument:
			if len(args) != 1 {
				return failure(diagnostic, "inspect-batch: invalid-worker-arguments")
			}
			return execution.WorkerMain(in, out, diagnostic)
		case execution.WriterArgument:
			if len(args) != 1 {
				return failure(diagnostic, "inspect-batch: invalid-writer-arguments")
			}
			return execution.WriterMain(in, out, diagnostic)
		}
	}
	if len(args) > 0 && args[0] == "inspect-batch" {
		// No-work invocations retain legacy writes/default signal behavior and
		// never launch a child. Only valid actual work swallows default SIGINT.
		_, _, valid := inspectArgs(args[1:])
		if !valid {
			return runBatch(args[1:], in, out, diagnostic)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return runBatchContext(ctx, args[1:], in, out, diagnostic)
	}
	return runInput(args, in, out, diagnostic)
}

func runBatchContext(ctx context.Context, args []string, in io.Reader, out, diagnostic io.Writer) int {
	if len(args) == 1 && args[0] == "--help" {
		if !writeOutput(out, []byte("packtrace inspect-batch [--format terminal|json] [--identity-profile explicit-only|npm-lock-v2-v3]\nRead one stdin JSON envelope with lockfile and advisories (1–16 supplied records).\nLimits: 1 MiB wire, 64 lock records, 64 total affected slots, 4096 pairs.\nPortable-only experimental hypotheses; invalid advisory metadata leaves a gap. No target access.\n")) {
			return failure(diagnostic, "cli: output-failed")
		}
		return 0
	}
	format, profile, ok := inspectArgs(args)
	if !ok {
		return failure(diagnostic, "inspect-batch: invalid-arguments")
	}
	// One operation budget covers input, parsing, rendering and all public
	// output, including diagnostics. Child roles share the runtime's budget.
	work, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	run, err := execution.RunBatch(work, in, profile)
	// An operation deadline is not a user SIGINT.
	if errors.Is(work.Err(), context.DeadlineExceeded) && !errors.Is(ctx.Err(), context.Canceled) {
		run.Interrupted = false
		if err != nil && err.Error() == "inspect-batch: interrupted" {
			err = errors.New("inspect-batch: worker-deadline")
		}
	}
	return renderSupervisedBatchContext(work, ctx, run, err, format, out, diagnostic)
}

// The runtime validates worker data; the CLI alone selects public exit and
// rendering. An abnormal usable result is still a report, never a clean scan.
func renderSupervisedBatch(run execution.BatchRun, err error, format string, out, diagnostic io.Writer, canceled bool) int {
	run.Interrupted = run.Interrupted || canceled
	return renderSupervisedBatchContext(context.Background(), context.Background(), run, err, format, out, diagnostic)
}

func renderSupervisedBatchContext(ctx, interrupt context.Context, run execution.BatchRun, err error, format string, out, diagnostic io.Writer) int {
	conditions := cli.ScanExitConditions{Interrupted: run.Interrupted, RequiredCoverageIncomplete: true}
	selectExit := func() int {
		conditions.Interrupted = conditions.Interrupted || errors.Is(interrupt.Err(), context.Canceled)
		return cli.SelectScanExit(conditions)
	}
	fail := func(code string) int {
		// A diagnostic is optional after cancellation. Otherwise isolate its
		// inherited sink exactly like stdout, after the preceding child reaped.
		if ctx.Err() == nil && !errors.Is(interrupt.Err(), context.Canceled) {
			_ = run.WriteOutput(ctx, diagnostic, []byte(code+"\n"))
		}
		conditions.ReportPreventingError = true
		return selectExit()
	}
	if !run.Usable {
		if err != nil {
			return fail(err.Error()) // Runtime errors are fixed private codes.
		}
		return fail("inspect-batch: execution-failed")
	}
	run.Result.ExitCode = selectExit()
	data, renderErr := inspect.RenderBatch(run.Result, format)
	if renderErr != nil {
		return fail("inspect-batch: report-failed")
	}
	if run.WriteOutput(ctx, out, data) != nil {
		return fail("cli: output-failed")
	}
	// Already emitted bytes cannot be rewritten if cancellation arrived during
	// output. A canceled write may leave only a prefix, not a complete report.
	return selectExit()
}
