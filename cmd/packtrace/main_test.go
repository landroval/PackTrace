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

func TestInspectProfileArguments(t *testing.T) {
	payload := strings.Replace(strings.Replace(inspectPacket, `node_modules/PRIVATE-PATH`, `node_modules/private-marker-package`, 1), `"name":"private-marker-package",`, "", 1)
	for _, args := range [][]string{{"inspect", "--identity-profile=npm-lock-v2-v3", "--format=json"}, {"inspect", "--format", "json", "--identity-profile", "npm-lock-v2-v3"}} {
		var out, diag bytes.Buffer
		if runInput(args, strings.NewReader(payload), &out, &diag) != 3 || !strings.Contains(out.String(), "installation-name-version-only") || strings.Contains(out.String(), "private-marker-package") || diag.Len() != 0 {
			t.Fatal("opt-in command failed", out.String(), diag.String())
		}
	}
	for _, args := range [][]string{{"inspect", "--identity-profile=PRIVATE"}, {"inspect", "--identity-profile"}, {"inspect", "--identity-profile="}, {"inspect", "--identity-profile=explicit-only", "--identity-profile=npm-lock-v2-v3"}, {"inspect", "--format=json", "--identity-profile=npm-lock-v2-v3", "--format=terminal"}, {"inspect", "--help", "--identity-profile=npm-lock-v2-v3"}} {
		var out, diag bytes.Buffer
		if runInput(args, forbiddenReader{}, &out, &diag) != 2 || out.Len() != 0 || strings.Contains(diag.String(), "PRIVATE") {
			t.Fatal("bad profile arguments read input/leaked")
		}
	}
}

const batchInput = `{"lockfile":{"lockfileVersion":3,"packages":{"node_modules/PRIVATE-PATH":{"name":"private-marker-package","version":"1.2.3"}}},"advisories":[{"id":"PRIVATE-ID","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"private-marker-package"},"versions":["1.2.3"]}]},42]}`

func TestRunInspectBatch(t *testing.T) {
	for _, format := range []string{"terminal", "json"} {
		t.Run(format, func(t *testing.T) {
			var out, diag bytes.Buffer
			if exit := runInput([]string{"inspect-batch", "--format=" + format}, strings.NewReader(batchInput), &out, &diag); exit != 3 || diag.Len() != 0 {
				t.Fatal("batch executable failed", exit, diag.String())
			}
			for _, secret := range []string{"PRIVATE", "private-marker-package", "1.2.3"} {
				if strings.Contains(out.String(), secret) {
					t.Fatal("batch command leak")
				}
			}
			if format == "json" {
				var r struct {
					Schema         string
					CandidateCount int `json:"candidate_count"`
					Advisories     []json.RawMessage
					Findings       []json.RawMessage
				}
				if json.Unmarshal(out.Bytes(), &r) != nil || r.Schema != "packtrace.inspect.batch.v1" || r.CandidateCount != 1 || len(r.Advisories) != 2 || len(r.Findings) != 0 {
					t.Fatal("batch JSON wrong", out.String())
				}
			} else if !strings.Contains(out.String(), "Candidate comparisons: 1") || !strings.Contains(out.String(), "advisory-1: invalid-advisory") {
				t.Fatal("terminal gap/candidate missing")
			}
			for _, short := range []bool{false, true} {
				if runInput([]string{"inspect-batch", "--format", format}, strings.NewReader(batchInput), failedWriter{short}, &diag) != 2 {
					t.Fatal("batch writer error ignored")
				}
			}
		})
	}
	var out, diag bytes.Buffer
	if runInput([]string{"inspect-batch"}, strings.NewReader("PRIVATE-MALFORMED"), &out, &diag) != 2 || out.Len() != 0 || !strings.HasPrefix(diag.String(), "inspect-batch:") || strings.Contains(diag.String(), "PRIVATE") {
		t.Fatal("batch fatal contract", diag.String())
	}
}

func TestBatchArgumentsBeforeStdin(t *testing.T) {
	for _, args := range [][]string{{"inspect-batch", "--PRIVATE"}, {"inspect-batch", "PRIVATE"}, {"inspect-batch", "--format=PRIVATE"}, {"inspect-batch", "--format"}, {"inspect-batch", "--format="}, {"inspect-batch", "--format=json", "--format=terminal"}, {"inspect-batch", "--identity-profile=PRIVATE"}, {"inspect-batch", "--identity-profile"}, {"inspect-batch", "--identity-profile=explicit-only", "--identity-profile=npm-lock-v2-v3"}, {"inspect-batch", "--help", "--format=json"}} {
		var out, diag bytes.Buffer
		if runInput(args, forbiddenReader{}, &out, &diag) != 2 || out.Len() != 0 || !strings.HasPrefix(diag.String(), "inspect-batch:") || strings.Contains(diag.String(), "PRIVATE") {
			t.Fatal("batch flags/no-read/privacy", diag.String())
		}
	}
	var out, diag bytes.Buffer
	if runInput([]string{"inspect-batch", "--help"}, forbiddenReader{}, &out, &diag) != 0 || diag.Len() != 0 || !strings.Contains(out.String(), "advisories") || !strings.Contains(out.String(), "16") {
		t.Fatal("batch help/no-read failed")
	}
	payload := strings.Replace(strings.Replace(batchInput, `node_modules/PRIVATE-PATH`, `node_modules/private-marker-package`, 1), `"name":"private-marker-package",`, "", 1)
	for _, args := range [][]string{{"inspect-batch", "--format", "json", "--identity-profile=npm-lock-v2-v3"}, {"inspect-batch", "--identity-profile", "npm-lock-v2-v3", "--format=json"}} {
		out.Reset()
		diag.Reset()
		if runInput(args, strings.NewReader(payload), &out, &diag) != 3 || diag.Len() != 0 || !strings.Contains(out.String(), "installation-name-version-only") || strings.Contains(out.String(), "private-marker-package") {
			t.Fatal("batch profile not applied", diag.String())
		}
	}
}

const bunCommandPacket = `{"lockfile_text":"{\"lockfileVersion\":1,\"workspaces\":{},\"packages\":{\"PRIVATE-KEY\":[\"private-marker-package@1.2.3\",\"\",{},\"PRIVATE-INTEGRITY\"]}}","advisory":{"id":"PRIVATE-ID","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"private-marker-package"},"versions":["1.2.3"]}]}}`

func TestRunBunInspection(t *testing.T) {
	for _, args := range [][]string{{"inspect-bun"}, {"inspect-bun", "--format=terminal"}, {"inspect-bun", "--format", "json"}} {
		var out, diag bytes.Buffer
		if exit := runInput(args, strings.NewReader(bunCommandPacket), &out, &diag); exit != 3 || diag.Len() != 0 || !strings.Contains(out.String(), "bun-tuple-name-version-only") {
			t.Fatal("Bun command missing", exit, diag.String(), out.String())
		}
		for _, s := range []string{"PRIVATE", "private-marker-package", "1.2.3"} {
			if strings.Contains(out.String()+diag.String(), s) {
				t.Fatal("Bun command leak")
			}
		}
		for _, short := range []bool{false, true} {
			diag.Reset()
			if runInput(args, strings.NewReader(bunCommandPacket), failedWriter{short}, &diag) != 2 || strings.Contains(diag.String(), "PRIVATE") {
				t.Fatal("Bun output failure hidden/leaked")
			}
		}
	}
	var out, diag bytes.Buffer
	if runInput([]string{"inspect-bun"}, strings.NewReader("PRIVATE-MALFORMED"), &out, &diag) != 2 || out.Len() != 0 || !strings.HasPrefix(diag.String(), "inspect-bun:") || strings.Contains(diag.String(), "PRIVATE") {
		t.Fatal("Bun fatal/private")
	}
}

func TestBunArgumentsBeforeStdin(t *testing.T) {
	for _, tail := range [][]string{{"--PRIVATE"}, {"PRIVATE"}, {"--format"}, {"--format="}, {"--format=PRIVATE"}, {"--format=json", "--format=terminal"}, {"--identity-profile=explicit-only"}, {"--identity-profile", "npm-lock-v2-v3"}, {"--help", "--format=json"}} {
		args := append([]string{"inspect-bun"}, tail...)
		var out, diag bytes.Buffer
		if runInput(args, forbiddenReader{}, &out, &diag) != 2 || out.Len() != 0 || !strings.HasPrefix(diag.String(), "inspect-bun:") || strings.Contains(diag.String(), "PRIVATE") {
			t.Fatal("Bun arguments/private/no-read", diag.String())
		}
	}
	var out, diag bytes.Buffer
	if runInput([]string{"inspect-bun", "--help"}, forbiddenReader{}, &out, &diag) != 0 || diag.Len() != 0 || !strings.Contains(out.String(), "lockfile_text") {
		t.Fatal("Bun help/no-read")
	}
	for _, short := range []bool{false, true} {
		if runInput([]string{"inspect-bun", "--help"}, forbiddenReader{}, failedWriter{short}, &diag) != 2 {
			t.Fatal("Bun help output error")
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
