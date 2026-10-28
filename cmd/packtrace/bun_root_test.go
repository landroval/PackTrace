package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/inspect"
)

func rootCommandPacket(t *testing.T, workspaces string) []byte {
	t.Helper()
	text := `{"lockfileVersion":1,"workspaces":` + workspaces + `,"packages":{}}`
	encoded, err := json.Marshal(text)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(`{"manifest":{"dependencies":{"PRIVATE":"1"}},"lockfile_text":` + string(encoded) + `}`)
}

func TestRootCommandFormats(t *testing.T) {
	for _, args := range [][]string{{"compare-bun-root"}, {"compare-bun-root", "--format=terminal"}, {"compare-bun-root", "--format", "json"}, {"compare-bun-root", "--format=json"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, diag bytes.Buffer
			if exit := runInput(args, bytes.NewReader(rootCommandPacket(t, `{"":{"dependencies":{"PRIVATE":"2"}}}`)), &out, &diag); exit != 3 || diag.Len() != 0 {
				t.Fatal("command scope/exit", exit, diag.String())
			}
			if bytes.Contains(out.Bytes(), []byte("PRIVATE")) {
				t.Fatal("portable metadata leak")
			}
			if strings.Contains(strings.Join(args, " "), "json") {
				var r inspect.BunRootResult
				if json.Unmarshal(out.Bytes(), &r) != nil || r.Schema != "packtrace.compare.bun-root.v1" || !r.RootPresent || !r.ComparisonComplete || len(r.Groups) != 4 || r.Groups[0].Counts != (inspect.BunRootCounts{TextChanged: 1}) || r.ExitCode != 3 {
					t.Fatal("JSON lost literal comparison", out.String())
				}
			} else if !strings.Contains(out.String(), "text-changed=1") || !strings.Contains(out.String(), "not a target scan") || !strings.Contains(out.String(), "Exit: 3") {
				t.Fatal("terminal lost count/limitations", out.String())
			}
			for _, short := range []bool{false, true} {
				diag.Reset()
				if runInput(args, bytes.NewReader(rootCommandPacket(t, `{"":{}}`)), failedWriter{short}, &diag) != 2 || diag.String() != "cli: output-failed\n" {
					t.Fatal("output failure hidden", diag.String())
				}
			}
		})
	}
}

func TestRootCommandMissingAndInvalidInput(t *testing.T) {
	var out, diag bytes.Buffer
	if runInput([]string{"compare-bun-root", "--format=json"}, bytes.NewReader(rootCommandPacket(t, `{"packages/other":{}}`)), &out, &diag) != 3 {
		t.Fatal("missing root should retain partial report", diag.String())
	}
	var r inspect.BunRootResult
	if json.Unmarshal(out.Bytes(), &r) != nil || r.RootPresent || r.ComparisonComplete || r.Groups == nil || len(r.Groups) != 0 {
		t.Fatal("non-root workspace substituted", out.String())
	}
	out.Reset()
	diag.Reset()
	if runInput([]string{"compare-bun-root"}, strings.NewReader("PRIVATE-MALFORMED"), &out, &diag) != 2 || out.Len() != 0 || diag.String() != "compare-bun-root: invalid-input\n" {
		t.Fatal("malformed wire error lost/private input leaked", diag.String())
	}
}

func TestRootCommandArgumentsBeforeStdin(t *testing.T) {
	for _, tail := range [][]string{{"--PRIVATE"}, {"/PRIVATE/package.json"}, {"--format"}, {"--format="}, {"--format=text"}, {"--format=json", "--format=terminal"}, {"--identity-profile=explicit-only"}, {"--identity-profile", "npm-lock-v2-v3"}, {"--help", "--format=json"}} {
		var out, diag bytes.Buffer
		if runInput(append([]string{"compare-bun-root"}, tail...), forbiddenReader{}, &out, &diag) != 2 || out.Len() != 0 || diag.String() != "compare-bun-root: invalid-arguments\n" {
			t.Fatal("arguments/read/privacy", tail, diag.String())
		}
	}
	var out, diag bytes.Buffer
	if runInput([]string{"compare-bun-root", "--help"}, forbiddenReader{}, &out, &diag) != 0 || diag.Len() != 0 || !strings.Contains(out.String(), "manifest") || !strings.Contains(out.String(), "lockfile_text") || !strings.Contains(out.String(), "1 MiB") {
		t.Fatal("help/read/output", out.String(), diag.String())
	}
	for _, short := range []bool{false, true} {
		diag.Reset()
		if runInput([]string{"compare-bun-root", "--help"}, forbiddenReader{}, failedWriter{short}, &diag) != 2 || diag.String() != "cli: output-failed\n" {
			t.Fatal("help write failure hidden")
		}
	}
	out.Reset()
	diag.Reset()
	if runInput([]string{"--help"}, forbiddenReader{}, &out, &diag) != 0 || diag.Len() != 0 || !strings.Contains(out.String(), "packtrace compare-bun-root [--format terminal|json] (supplied root manifest and text bun.lock)") {
		t.Fatal("root help missing new command")
	}
}
