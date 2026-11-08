package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"packtrace/internal/cli"
	"packtrace/internal/execution"
	"time"
)

func intelProgressOutput(request cli.IntelArgumentRequest, out io.Writer) *os.File {
	if request.Format == "json" || scanTerminalFormat("terminal", "-", out) != "terminal-color" {
		return nil
	}
	switch request.Action {
	case cli.ArgumentActionIntelSync, cli.ArgumentActionIntelImport, cli.ArgumentActionIntelExport:
		if file, ok := out.(*os.File); ok && terminalProgressWidth(file) {
			return file
		}
	}
	return nil
}
func runIntel(request cli.IntelArgumentRequest, out, diagnostic io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runIntelContext(ctx, request, out, diagnostic)
}
func runIntelContext(caller context.Context, request cli.IntelArgumentRequest, out, diagnostic io.Writer) int {
	work, cancel := context.WithTimeout(caller, 15*time.Minute)
	defer cancel()
	run, e := execution.RunIntelWithProgress(work, request, intelProgressOutput(request, out))
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
	}
	if e != nil || run.WriteOutput(work, out, data) != nil {
		conditions.ReportPreventingError = true
	}
	return finish()
}
