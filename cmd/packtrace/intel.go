package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"packtrace/internal/cli"
	"packtrace/internal/execution"
	"packtrace/internal/interactive"
	"time"
)

func runIntel(request cli.IntelArgumentRequest, out, diagnostic io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runIntelContext(ctx, request, out, diagnostic)
}
func runIntelContext(caller context.Context, request cli.IntelArgumentRequest, out, diagnostic io.Writer) int {
	wantsUI := request.Format == "terminal-interactive"
	if wantsUI {
		request.Format = "terminal"
		request.Provided &^= cli.ArgumentOptionInteractive
	}
	var activity *os.File
	if wantsUI && interactive.Available(os.Stdin, out) {
		activity = out.(*os.File)
	}
	started := time.Now()
	work, cancel := context.WithTimeout(caller, 15*time.Minute)
	defer cancel()
	run, e := execution.RunIntelWithActivity(work, request, activity)
	conditions := cli.ScanExitConditions{Interrupted: errors.Is(caller.Err(), context.Canceled)}
	if e != nil || !run.Usable {
		conditions.ReportPreventingError = true
	} else if run.Result.Outcome != "complete" {
		if run.Result.Action == cli.ArgumentActionIntelStatus && run.Result.Outcome == "unavailable" {
			conditions.RequiredCoverageIncomplete = true
		} else {
			conditions.ReportPreventingError = true
		}
	}
	if v := run.Result.Observation; v != nil && len(v.Gaps) > 0 {
		conditions.RequiredCoverageIncomplete = true
	}
	if p := run.Result.Preview; p != nil && (p.Limited || p.QuarantinedBytes > 0) {
		conditions.RequiredCoverageIncomplete = true
	}
	finish := func() int {
		_, failure := run.Finish()
		if failure != nil {
			conditions.ReportPreventingError = true
		}
		conditions.Interrupted = conditions.Interrupted || errors.Is(caller.Err(), context.Canceled)
		return cli.SelectScanExit(conditions)
	}
	if !run.Usable {
		if work.Err() == nil {
			_ = run.WriteOutput(work, diagnostic, []byte(cli.DiagnosticText("intel: execution-unavailable")))
		}
		return finish()
	}
	code := cli.SelectScanExit(conditions)
	report := struct {
		SchemaVersion string                `json:"schemaVersion"`
		Result        execution.IntelResult `json:"intelligence"`
		ExitCode      int                   `json:"exitCode"`
	}{"1.0", run.Result, code}
	var data []byte
	if request.Format == "json" {
		data, e = json.Marshal(report)
		data = append(data, '\n')
	} else {
		data = renderIntelTerminal(run.Result)
		if activity != nil {
			data = append(data, []byte(fmt.Sprintf("Elapsed: %s (observed; no completion percentage inferred).\n", time.Since(started).Round(time.Millisecond)))...)
		}
	}
	if e != nil || run.WriteOutput(work, out, data) != nil {
		conditions.ReportPreventingError = true
	}
	return finish()
}
