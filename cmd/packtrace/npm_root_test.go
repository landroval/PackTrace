package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func npmCommandPacket(version int, packages string) string {
	return fmt.Sprintf(`{"manifest":{"dependencies":{"PRIVATE":"1","only-manifest":"2"}},"lockfile":{"lockfileVersion":%d,"packages":%s}}`, version, packages)
}

func decodeNPMReport(data string, result any) error { return json.Unmarshal([]byte(data), result) }

func npmCommandReport(t *testing.T, args []string, input string) (string, int) {
	t.Helper()
	var out, diag bytes.Buffer
	exit := runInput(args, strings.NewReader(input), &out, &diag)
	if diag.Len() != 0 || strings.Contains(out.String(), "PRIVATE") {
		t.Fatalf("private data or diagnostic: exit=%d diagnostic=%q output=%q", exit, diag.String(), out.String())
	}
	return out.String(), exit
}

func TestNPMRootCommandVersionsAndFormats(t *testing.T) {
	for _, version := range []int{2, 3} {
		for _, args := range [][]string{{"compare-npm-root"}, {"compare-npm-root", "--format=terminal"}, {"compare-npm-root", "--format", "json"}, {"compare-npm-root", "--format=json"}} {
			t.Run(fmt.Sprint(version, args), func(t *testing.T) {
				input := npmCommandPacket(version, `{"":{"dependencies":{"PRIVATE":"3","only-lock":"4"}}}`)
				out, exit := npmCommandReport(t, args, input)
				if exit != 3 {
					t.Fatalf("usable metadata exit=%d output=%q", exit, out)
				}
				if strings.Contains(strings.Join(args, " "), "json") {
					var r struct {
						Schema             string `json:"schema"`
						RootPresent        bool   `json:"root_present"`
						ComparisonComplete bool   `json:"comparison_complete"`
						ExitCode           int    `json:"exit_code"`
						Groups             []struct {
							Name   string         `json:"name"`
							Counts map[string]int `json:"counts"`
						} `json:"groups"`
					}
					if err := decodeNPMReport(out, &r); err != nil || r.Schema != "packtrace.compare.npm-root.v1" || !r.RootPresent || !r.ComparisonComplete || r.ExitCode != 3 || len(r.Groups) != 4 || r.Groups[0].Name != "dependencies" || r.Groups[0].Counts["text_changed"] != 1 || r.Groups[0].Counts["manifest_only"] != 1 || r.Groups[0].Counts["lock_only"] != 1 {
						t.Fatalf("JSON textual count/report: %v %q", err, out)
					}
				} else if !strings.Contains(out, "text-changed=1") || !strings.Contains(out, "manifest-only=1") || !strings.Contains(out, "lock-only=1") || !strings.Contains(out, "not a target scan") || !strings.Contains(out, "Exit: 3") {
					t.Fatalf("terminal textual count/report: %q", out)
				}
			})
		}
	}
}

func TestNPMRootCommandMissingRoot(t *testing.T) {
	out, exit := npmCommandReport(t, []string{"compare-npm-root", "--format=json"}, npmCommandPacket(3, `{"node_modules/PRIVATE":{}}`))
	var r struct {
		RootPresent        bool  `json:"root_present"`
		ComparisonComplete bool  `json:"comparison_complete"`
		Groups             []any `json:"groups"`
	}
	if err := decodeNPMReport(out, &r); err != nil || exit != 3 || r.RootPresent || r.ComparisonComplete || r.Groups == nil || len(r.Groups) != 0 {
		t.Fatalf("missing root substituted: exit=%d err=%v report=%q", exit, err, out)
	}
}

type npmFailedReader struct{}

func (npmFailedReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE-READER") }

func TestNPMRootCommandAdmissionFailures(t *testing.T) {
	for _, tc := range []struct {
		name, input, diagnostic string
		reader                  bool
	}{
		{"malformed", "PRIVATE-MALFORMED", "compare-npm-root: invalid-input\n", false},
		{"duplicate-envelope", `{"manifest":{},"manifest":{},"lockfile":{}}`, "compare-npm-root: invalid-input\n", false},
		{"unknown-envelope", `{"manifest":{},"lockfile":{},"PRIVATE":{}}`, "compare-npm-root: invalid-input\n", false},
		{"non-object", `{"manifest":[],"lockfile":{}}`, "compare-npm-root: invalid-input\n", false},
		{"bad-metadata", `{"manifest":{},"lockfile":{"lockfileVersion":1,"packages":{}}}`, "compare-npm-root: invalid-metadata\n", false},
		{"over-limit", strings.Repeat(" ", 1<<20+1), "compare-npm-root: limit-exceeded\n", false},
		{"read-failed", "", "compare-npm-root: read-failed\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, diag bytes.Buffer
			var reader interface{ Read([]byte) (int, error) } = strings.NewReader(tc.input)
			if tc.reader {
				reader = npmFailedReader{}
			}
			if exit := runInput([]string{"compare-npm-root"}, reader, &out, &diag); exit != 2 || out.Len() != 0 || diag.String() != tc.diagnostic {
				t.Fatalf("admission exit=%d diagnostic=%q output=%q", exit, diag.String(), out.String())
			}
		})
	}
}

func TestNPMRootCommandArgumentsBeforeStdin(t *testing.T) {
	for _, tail := range [][]string{{"--PRIVATE"}, {"/PRIVATE/package.json"}, {"--format"}, {"--format="}, {"--format=text"}, {"--format=json", "--format=terminal"}, {"--identity-profile=explicit-only"}, {"--identity-profile", "npm-lock-v2-v3"}, {"--help", "--format=json"}} {
		var out, diag bytes.Buffer
		if exit := runInput(append([]string{"compare-npm-root"}, tail...), forbiddenReader{}, &out, &diag); exit != 2 || out.Len() != 0 || diag.String() != "compare-npm-root: invalid-arguments\n" {
			t.Fatalf("arguments/read/privacy: %v exit=%d diagnostic=%q", tail, exit, diag.String())
		}
	}
}

func TestNPMRootCommandHelpAndOutputFailures(t *testing.T) {
	var out, diag bytes.Buffer
	if exit := runInput([]string{"compare-npm-root", "--help"}, forbiddenReader{}, &out, &diag); exit != 0 || diag.Len() != 0 || !strings.Contains(out.String(), "manifest") || !strings.Contains(out.String(), "lockfile") || !strings.Contains(out.String(), "1 MiB") {
		t.Fatalf("help/read exit=%d output=%q diagnostic=%q", exit, out.String(), diag.String())
	}
	out.Reset()
	if exit := runInput([]string{"--help"}, forbiddenReader{}, &out, &diag); exit != 0 || diag.Len() != 0 || !strings.Contains(out.String(), "packtrace compare-npm-root [--format terminal|json]") || !strings.Contains(out.String(), "packtrace compare-bun-root [--format terminal|json]") {
		t.Fatalf("root help exit=%d output=%q diagnostic=%q", exit, out.String(), diag.String())
	}
	for _, short := range []bool{false, true} {
		for _, args := range [][]string{{"compare-npm-root", "--help"}, {"compare-npm-root", "--format=json"}} {
			diag.Reset()
			if exit := runInput(args, strings.NewReader(npmCommandPacket(3, `{"":{}}`)), failedWriter{short}, &diag); exit != 2 || diag.String() != "cli: output-failed\n" {
				t.Fatalf("write failure exit=%d diagnostic=%q", exit, diag.String())
			}
		}
	}
}
