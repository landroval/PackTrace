package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRunDemoScenarios(t *testing.T) {
	for _, tc := range []struct {
		name             string
		candidates, exit int
	}{
		{"candidate", 1, 3}, {"no-version-match", 0, 3}, {"unsupported", 0, 3},
		{"withdrawn", 0, 3}, {"different-identity", 0, 3}, {"malformed", 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, format := range []string{"terminal", "json"} {
				t.Run(format, func(t *testing.T) {
					var out, diagnostic bytes.Buffer
					exit := run([]string{"demo", "--scenario", tc.name, "--format", format}, &out, &diagnostic)
					if exit != tc.exit {
						t.Fatalf("exit %d, want %d", exit, tc.exit)
					}
					if tc.exit == 2 {
						if out.Len() != 0 || diagnostic.Len() == 0 || strings.Contains(diagnostic.String(), "PRIVATE") {
							t.Fatal("fatal report/privacy failure")
						}
						return
					}
					if diagnostic.Len() != 0 {
						t.Fatal("successful report unexpectedly diagnosed", diagnostic.String())
					}
					if format == "json" {
						var report struct {
							Schema, Scope        string
							Experimental         bool
							Scenario             string
							Candidates, Findings []json.RawMessage
							ExitCode             int `json:"exit_code"`
							Coverage             []json.RawMessage
						}
						if err := json.Unmarshal(out.Bytes(), &report); err != nil {
							t.Fatal(err)
						}
						if report.Schema != "packtrace.demo.v1" || report.Scope != "owned-synthetic-fixture" || !report.Experimental || report.Scenario != tc.name || len(report.Candidates) != tc.candidates || len(report.Findings) != 0 || report.ExitCode != 3 || len(report.Coverage) != 5 {
							t.Fatal("incorrect executable JSON report", out.String())
						}
					} else if !strings.Contains(out.String(), "EXPERIMENTAL DEMO") || !strings.Contains(out.String(), "synthetic") || !strings.Contains(out.String(), fmt.Sprintf("Candidates: %d", tc.candidates)) || !strings.Contains(out.String(), "Confirmed findings: 0") || !strings.Contains(out.String(), "Required coverage: incomplete") {
						t.Fatal("terminal differs from model or hides limitations", out.String())
					}
				})
			}
		})
	}
}

func TestRunControlAndInvalidArguments(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		exit   int
		report bool
	}{
		{"help", []string{"--help"}, 0, true},
		{"version", []string{"--version"}, 0, true},
		{"scan-help", []string{"scan", "--help"}, 0, true},
		{"defaults", []string{"demo"}, 3, true},
		{"attached", []string{"demo", "--scenario=no-version-match", "--format=json"}, 3, true},
		{"missing-command", nil, 2, false},
		{"scan-not-opened", []string{"scan", "PRIVATE-ARG-MARKER"}, 2, false},
		{"unknown-command", []string{"PRIVATE-ARG-MARKER"}, 2, false},
		{"unknown-scenario", []string{"demo", "--scenario", "PRIVATE-ARG-MARKER"}, 2, false},
		{"unknown-option", []string{"demo", "--PRIVATE-ARG-MARKER"}, 2, false},
		{"wrong-format", []string{"demo", "--format", "PRIVATE-ARG-MARKER"}, 2, false},
		{"missing-value", []string{"demo", "--scenario"}, 2, false},
		{"empty-value", []string{"demo", "--scenario="}, 2, false},
		{"duplicate-scenario", []string{"demo", "--scenario", "candidate", "--scenario", "withdrawn"}, 2, false},
		{"duplicate-format", []string{"demo", "--format=json", "--format=terminal"}, 2, false},
		{"extra-argument", []string{"demo", "PRIVATE-ARG-MARKER"}, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			exit := run(tc.args, &out, &diagnostic)
			if exit != tc.exit || (out.Len() > 0) != tc.report || strings.Contains(out.String()+diagnostic.String(), "PRIVATE-ARG-MARKER") {
				t.Fatal("command, privacy or output contract failed", exit, out.String(), diagnostic.String())
			}
			if tc.exit == 0 && diagnostic.Len() != 0 {
				t.Fatal("control command failed")
			}
			if !tc.report && diagnostic.Len() == 0 {
				t.Fatal("failure silently hidden")
			}
		})
	}
}

type failedWriter struct{ short bool }

func (w failedWriter) Write(p []byte) (int, error) {
	if w.short {
		return 0, nil
	}
	return 0, errors.New("PRIVATE-WRITER-MARKER")
}

func TestRunOutputFailure(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"demo"}, {"demo", "--format=json"}} {
		for _, short := range []bool{false, true} {
			var diagnostic bytes.Buffer
			if exit := run(args, failedWriter{short}, &diagnostic); exit != 2 || strings.Contains(diagnostic.String(), "PRIVATE") || diagnostic.Len() == 0 {
				t.Fatal("failed/short output claimed success or disclosed writer error")
			}
		}
	}
}
