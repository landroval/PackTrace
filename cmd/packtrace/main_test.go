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

type forbiddenReader struct{}

func (forbiddenReader) Read([]byte) (int, error) { panic("stdin read on control/invalid invocation") }

const inspectPacket = `{"lockfile":{"lockfileVersion":3,"packages":{"node_modules/PRIVATE-PATH":{"name":"private-marker-package","version":"1.2.3"}}},"advisory":{"id":"PRIVATE-ID","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"private-marker-package"},"versions":["1.2.3"]}]}}`

func TestRunInspect(t *testing.T) {
	for _, format := range []string{"terminal", "json"} {
		var out, diagnostic bytes.Buffer
		if exit := runInput([]string{"inspect", "--format", format}, strings.NewReader(inspectPacket), &out, &diagnostic); exit != 3 || diagnostic.Len() != 0 {
			t.Fatal("inspect exit", exit, diagnostic.String())
		}
		if strings.Contains(out.String(), "PRIVATE") || strings.Contains(out.String(), "private-marker-package") || strings.Contains(out.String(), "1.2.3") {
			t.Fatal("command leaked metadata")
		}
		if format == "terminal" && !strings.Contains(out.String(), "Candidates: 1") {
			t.Fatal("terminal candidate missing")
		}
		if format == "json" {
			var r struct {
				Schema               string
				Candidates, Findings []json.RawMessage
			}
			if json.Unmarshal(out.Bytes(), &r) != nil || r.Schema != "packtrace.inspect.v1" || len(r.Candidates) != 1 || len(r.Findings) != 0 {
				t.Fatal("incorrect JSON")
			}
		}
		for _, short := range []bool{false, true} {
			if runInput([]string{"inspect", "--format", format}, strings.NewReader(inspectPacket), failedWriter{short}, &diagnostic) != 2 {
				t.Fatal("output failure")
			}
		}
	}
	var out, diagnostic bytes.Buffer
	if runInput([]string{"inspect"}, strings.NewReader("PRIVATE-MALFORMED"), &out, &diagnostic) != 2 || out.Len() != 0 || strings.Contains(diagnostic.String(), "PRIVATE") {
		t.Fatal("malformed input report/privacy")
	}
}

func TestInspectArgsBeforeReading(t *testing.T) {
	for _, args := range [][]string{{"inspect", "--format=PRIVATE"}, {"inspect", "--PRIVATE"}, {"inspect", "--format=json", "--format=terminal"}, {"inspect", "--format"}, {"inspect", "--format="}, {"inspect", "PRIVATE"}, {"inspect", "--help", "--format=json"}, {"inspect", "--privacy=local"}} {
		var out, diag bytes.Buffer
		if runInput(args, forbiddenReader{}, &out, &diag) != 2 || out.Len() != 0 || diag.Len() == 0 || strings.Contains(diag.String(), "PRIVATE") {
			t.Fatal("args/private/no-read")
		}
	}
	for _, args := range [][]string{{"inspect", "--help"}, {"--help"}, {"--version"}, {"scan", "--help"}} {
		var out, diag bytes.Buffer
		if runInput(args, forbiddenReader{}, &out, &diag) != 0 || out.Len() == 0 || diag.Len() != 0 {
			t.Fatal("control/no-read")
		}
	}
	for _, args := range [][]string{{"inspect"}, {"inspect", "--format=json"}} {
		var out, diag bytes.Buffer
		if runInput(args, strings.NewReader(inspectPacket), &out, &diag) != 3 {
			t.Fatal("default/attached")
		}
	}
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
