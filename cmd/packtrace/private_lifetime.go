package main

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"packtrace/internal/execution"
)

// Private, non-authoritative operational evidence. No identities, PIDs, raw
// errors, paths, timestamps, or policy data cross this projection.
const lifetimeFlag = "--private-lifetime-fd"
const lifetimeLimit = 4096 // <= Linux PIPE_BUF: one nonblocking atomic write.

type lifetimeRole struct {
	Role     string `json:"role"`
	Peak     uint64 `json:"waitPeak"`
	Sampled  uint64 `json:"sampledPeak"`
	Samples  int    `json:"samples"`
	Wait     bool   `json:"wait"`
	Reaped   bool   `json:"reaped"`
	Exchange bool   `json:"exchange"`
	Success  bool   `json:"success"`
	Stderr   bool   `json:"stderr"`
	Exit     int    `json:"exit"`
}
type lifetimeRecord struct {
	Version           int            `json:"version"`
	Exit              int            `json:"exit"`
	Finished          bool           `json:"finished"`
	Cleanup           bool           `json:"cleanup"`
	Final             string         `json:"final"`
	QueryFailed       bool           `json:"queryFailed"`
	Stale             bool           `json:"stale"`
	Stopped           bool           `json:"stopped"`
	GapNS             int64          `json:"gapNS"`
	SupervisorSamples int            `json:"supervisorSamples"`
	Caller            string         `json:"caller"`
	Lifecycle         string         `json:"lifecycle"`
	Fault             [3]string      `json:"fault"` // first stage, code, role; transport never overwrites it
	Roles             []lifetimeRole `json:"roles"`
}

func lifetimeLabel(value, allowed string) string {
	if value == "" {
		return ""
	}
	for _, s := range strings.Fields(allowed) {
		if value == s {
			return s
		}
	}
	return "other"
}
func lifetimeBytes(r execution.ScanReceipt, exit int) ([]byte, error) {
	if exit != 0 && exit != 1 && exit != 2 && exit != 3 && exit != 130 {
		return nil, errors.New("private receipt exit invalid")
	}
	if r.MaxSampleGap < 0 || r.Resources.SupervisorSamples < 0 {
		return nil, errors.New("private receipt counter invalid")
	}
	if len(r.Roles) > 16 {
		return nil, errors.New("private receipt role limit")
	}
	record := lifetimeRecord{Version: 1, Exit: exit, Finished: r.Finished, Cleanup: r.CleanupConfirmed,
		Final:       lifetimeLabel(r.Finalization.Status, "observed missing failed unsupported"),
		QueryFailed: r.Resources.QueryFailed, Stale: r.Resources.Stale, Stopped: r.Resources.Stopped,
		GapNS: int64(r.MaxSampleGap), SupervisorSamples: r.Resources.SupervisorSamples,
		Caller: lifetimeLabel(r.CallerContext, "active canceled deadline unavailable"), Lifecycle: lifetimeLabel(r.LifecycleContext, "active canceled deadline unavailable"),
		Fault: [3]string{lifetimeLabel(r.FirstFault.Stage, "sample-gap supervisor-resident child-resident resident-overflow resident-threshold child-pin child-no-live-sample protocol-resident finish-context cleanup file-output-close bun-cache-close intelligence-close user-setup-close final-supervisor-peak final-peak-missing final-peak-threshold intelligence-binding user-setup-binding bun-cache-binding file-output-binding child-result control-deadline wait-exit stderr-limit stderr-read exchange exchange-context wait-context wait-timeout exchange-join stderr-join run checkpoint render output diagnostic caller"), lifetimeLabel(r.FirstFault.Code, "observation-failed canceled deadline resident-query-unavailable resident-observation-failed reap-unconfirmed join-unconfirmed output-failed protocol-failed limit child-exit operation-failed"), lifetimeLabel(r.FirstFault.Role, "scan scan-writer")}, Roles: make([]lifetimeRole, 0, len(r.Roles))}
	for _, role := range r.Roles {
		if role.Samples < 0 || role.ExitCode < -1 || role.ExitCode > 255 {
			return nil, errors.New("private receipt role counter invalid")
		}
		if role.Role != "scan" && role.Role != "scan-writer" {
			return nil, errors.New("private receipt role invalid")
		}
		record.Roles = append(record.Roles, lifetimeRole{role.Role, role.WaitPeakResidentBytes, role.PeakResidentBytes, role.Samples, role.WaitReturned, role.Reaped, role.ExchangeJoined, role.ExchangeSucceeded, role.StderrJoined, role.ExitCode})
	}
	b, e := json.Marshal(record)
	if e != nil {
		return nil, e
	}
	b = append(b, '\n')
	if len(b) > lifetimeLimit {
		return nil, errors.New("private receipt byte limit")
	}
	return b, nil
}
func lifetimeFailureExit(exit int) int {
	if exit == 130 {
		return 130
	}
	return 2
}

// Only explicit SCAN invocations inspect the option. No environment discovery,
// descriptor probing when absent, or propagation of the option to workers.
func runMainLifetime(args []string, in io.Reader, out, diagnostic io.Writer) int {
	if len(args) == 0 || args[0] != "scan" {
		return runMainObserved(args, in, out, diagnostic, nil)
	}
	fd := -1
	clean := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == lifetimeFlag || strings.HasPrefix(arg, lifetimeFlag+"=") {
			if fd != -1 || !strings.HasPrefix(arg, lifetimeFlag+"=") {
				return failure(diagnostic, "scan: private-receipt-invalid")
			}
			raw := strings.TrimPrefix(arg, lifetimeFlag+"=")
			n, e := strconv.Atoi(raw)
			if e != nil || n < 3 || n > 1<<20 || strconv.Itoa(n) != raw {
				return failure(diagnostic, "scan: private-receipt-invalid")
			}
			fd = n
		} else {
			clean = append(clean, arg)
		}
	}
	if fd == -1 {
		return runMainObserved(args, in, out, diagnostic, nil)
	}
	if !validLifetimeFD(fd) || !prepareLifetimeFD(fd) {
		return failure(diagnostic, "scan: private-receipt-invalid")
	}
	defer closeLifetimeFD(fd)
	var receipt execution.ScanReceipt
	count := 0
	exit := runMainObserved(clean, in, out, diagnostic, func(r execution.ScanReceipt) { receipt = r; count++ })
	if count != 1 || emitLifetime(fd, receipt, exit) != nil {
		// Preserve cancellation and every earlier first fault; output failure cannot
		// make an operational failure or incomplete scan successful. Do not write
		// diagnostics after Finish: an inherited stderr could itself block.
		return lifetimeFailureExit(exit)
	}
	return exit
}
