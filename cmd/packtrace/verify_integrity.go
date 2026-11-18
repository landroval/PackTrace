package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/execution"
	"packtrace/internal/integrityscan"
)

const integrityHelp = `packtrace verify-integrity --policy FILE --trusted-policy-digest SRI ROOT
Linux offline npm integrity check against explicitly trusted, independently anchored local references.
Both options are mandatory; only these options are accepted. Policy must select npm and integrity only.
Portable text output; no identities, paths, hashes, target config, network or code execution.
Every selected reference and installed instance must join uniquely and be readable/comparable.
Exits: 0 complete/equal, 1 complete/drift, 3 incomplete (even with drift), 2 invalid/fatal, 130 interrupted.
Not scan: no advisory checks or multi-platform release qualification claim; scan retains its own gates.
Output is a comparison snapshot; actual late failures override the process status without rewriting bytes.
`

func runIntegrityArgs(args []string, out, diagnostic io.Writer, observed scanObserver) int {
	if len(args) == 1 && args[0] == "--help" {
		if !writeOutput(out, []byte(integrityHelp)) {
			return failure(diagnostic, "cli: output-failed")
		}
		return 0
	}
	invocation, err := cli.ParseArgs(append([]string{"scan"}, args...))
	if err != nil {
		return failure(diagnostic, err.Error())
	}
	request := invocation.Scan
	allowed := cli.ArgumentOptionPolicy | cli.ArgumentOptionTrustedPolicyDigest
	if invocation.Action != cli.ArgumentActionScan || request.Provided != allowed || request.PolicyPath == "" || request.TrustedPolicyDigest == "" || runtime.GOOS != "linux" {
		return failure(diagnostic, "verify-integrity: explicit-policy-and-pin-required; Linux-only")
	}
	request.Manager = "npm"
	request.Checks = cli.ArgumentCheckIntegrity
	request.FailOn = cli.ArgumentCheckIntegrity
	request.Provided |= cli.ArgumentOptionManager | cli.ArgumentOptionChecks | cli.ArgumentOptionFailOn
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runIntegrityContext(ctx, request, out, diagnostic, observed)
}

func runIntegrityContext(ctx context.Context, request cli.ScanArgumentRequest, out, diagnostic io.Writer, observed scanObserver) (exit int) {
	work, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	old := debug.SetMemoryLimit(128 << 20)
	defer debug.SetMemoryLimit(old)
	run, err := execution.RunIntegrityCheck(work, request)
	run.NoteFailure("run", err)
	conditions := cli.ScanExitConditions{Interrupted: errors.Is(ctx.Err(), context.Canceled), ReportPreventingError: !run.Usable || !reportableScanFailure(err)}
	defer func() {
		receipt, finishErr := run.Finish()
		conditions.ReportPreventingError = conditions.ReportPreventingError || finishErr != nil
		conditions.Interrupted = conditions.Interrupted || errors.Is(ctx.Err(), context.Canceled)
		exit = cli.SelectScanExit(conditions)
		if observed != nil {
			observed(receipt)
		}
	}()
	fail := func(code string) int {
		conditions.ReportPreventingError = true
		if work.Err() == nil && !conditions.Interrupted {
			if e := run.WriteDiagnostic(work, diagnostic, code); e != nil {
				run.NoteFailure("diagnostic", e)
			}
		}
		return cli.SelectScanExit(conditions)
	}
	if conditions.ReportPreventingError {
		return fail("verify-integrity: acquisition-failed")
	}
	if e := run.Checkpoint(); e != nil {
		run.NoteFailure("checkpoint", e)
		return fail("verify-integrity: resource-observation-failed")
	}
	report := integrityscan.BuildReportWithPolicy(run.Plan, run.Records, run.Summary, run.Resources, conditions.Interrupted, err != nil, run.Inventory, run.Intelligence, run.Advisories, run.PolicyMaterials, run.PolicyMaterialLimited, time.Now().UTC())
	data, comparison, e := integrityscan.RenderIntegrityCheck(report)
	if e != nil {
		run.NoteFailure("render", e)
		return fail(e.Error())
	}
	conditions = comparison
	if e := run.Checkpoint(); e != nil {
		run.NoteFailure("checkpoint", e)
		return fail("verify-integrity: resource-observation-failed")
	}
	if e := run.WriteReportOutput(work, out, data); e != nil {
		run.NoteFailure("output", e)
		return fail("cli: output-failed")
	}
	return cli.SelectScanExit(conditions)
}
