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
	"time"
)

func runIntel(request cli.IntelArgumentRequest, out, diagnostic io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runIntelContext(ctx, request, out, diagnostic)
}
func runIntelContext(caller context.Context, request cli.IntelArgumentRequest, out, diagnostic io.Writer) int {
	work, cancel := context.WithTimeout(caller, 15*time.Minute)
	defer cancel()
	run, e := execution.RunIntel(work, request)
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
			_ = run.WriteOutput(work, diagnostic, []byte("intel: execution-unavailable\n"))
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
		data = []byte(fmt.Sprintf("Intelligence operation: %s\n", run.Result.Outcome))
		if run.Result.Generation != "" {
			data = append(data, []byte("Snapshot: "+run.Result.Generation+"\n")...)
		}
		if p := run.Result.Preview; p != nil {
			data = append(data, []byte(fmt.Sprintf("Prune preview: %x\nCandidates: %d; bytes: %d; generations: %d\nHistorical reproducibility may be lost; no deletion performed.\n", p.Token, p.Candidates, p.Bytes, p.Generations))...)
		}
		if p := run.Result.Prune; p != nil {
			data = append(data, []byte(fmt.Sprintf("Removed files: %d; bytes: %d; partial: %t\n", p.RemovedFiles, p.RemovedBytes, p.Partial))...)
		}
	}
	if e != nil || run.WriteOutput(work, out, data) != nil {
		conditions.ReportPreventingError = true
	}
	return finish()
}
