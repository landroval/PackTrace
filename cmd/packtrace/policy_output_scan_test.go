package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"packtrace/internal/integrityscan"
)

func runPolicyFileCLI(t *testing.T, want int, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestSupervisedCLIProcess$", "--", "scan"}, args...)...)
	var out, diag bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diag
	err := cmd.Run()
	if err == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != want || out.Len() != 0 || want == 3 && diag.Len() != 0 || want == 2 && diag.Len() == 0 {
		t.Fatalf("file CLI err=%v state=%v stdout=%s stderr=%s", err, cmd.ProcessState, out.String(), diag.String())
	}
}

func TestScanFileOutputUsesActualBoundRootsWithoutImplicitState(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("separated native file-publication profile is Linux-only; stdout unaffected")
	}
	target := t.TempDir()
	reports := t.TempDir()
	destination := filepath.Join(reports, "report.json")
	for name, data := range map[string]string{"package.json": `{"name":"owned-case","version":"1.0.0","packageManager":"npm@10.9.4"}`, "package-lock.json": `{"lockfileVersion":3,"packages":{"":{}}}`} {
		if os.WriteFile(filepath.Join(target, name), []byte(data), 0600) != nil {
			t.Fatal("authored project")
		}
	}
	args := []string{"--checks", "integrity", "--format", "json", "--output", destination, target}
	runPolicyFileCLI(t, 3, args...)
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal("requested artifact absent", err)
	}
	var report integrityscan.Report
	if json.Unmarshal(data, &report) != nil || report.SchemaVersion != "1.7" || report.Policy == nil || report.Policy.Source != "built-in" || report.ExitCode != 3 || report.Intelligence != nil {
		t.Fatalf("file model mismatch: %s", data)
	}
	before := append([]byte(nil), data...)
	runPolicyFileCLI(t, 2, args...)
	after, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing report overwritten")
	}
	for _, bad := range []string{filepath.Join(target, "report.json"), filepath.Join(filepath.Dir(target), "ancestor-report.json")} {
		runPolicyFileCLI(t, 2, "--checks", "integrity", "--format", "json", "--output", bad, target)
		if _, err := os.Lstat(bad); !os.IsNotExist(err) {
			t.Fatal("unsafe/ancestor output created", err)
		}
	}
}

func TestScanFileOutputRetainsSelectedGenerationAndReferenceSources(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("separated native file-publication profile is Linux-only; stdout unaffected")
	}
	target, policy, state, pin, snapshot := matchingScanFixture(t, "1.0.0", true)
	destination := filepath.Join(t.TempDir(), "report.sarif")
	runPolicyFileCLI(t, 3, "--policy", policy, "--trusted-policy-digest", pin, "--state-dir", state, "--trusted-snapshot-digest", snapshot, "--checks", "malicious", "--format", "sarif", "--output", destination, target)
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal("requested SARIF absent", err)
	}
	var sarif struct {
		Runs []struct {
			Properties integrityscan.Report `json:"properties"`
			Results    []json.RawMessage    `json:"results"`
		} `json:"runs"`
	}
	if json.Unmarshal(data, &sarif) != nil || len(sarif.Runs) != 1 || sarif.Runs[0].Properties.Policy == nil || sarif.Runs[0].Properties.Advisories == nil || sarif.Runs[0].Properties.Advisories.Findings != 1 || len(sarif.Runs[0].Results) != 1 || sarif.Runs[0].Properties.Intelligence.Selection != "expected-digest" {
		t.Fatalf("bound generation/reference file report mismatch: %s", data)
	}
	for _, bad := range []string{filepath.Join(state, "report.json"), filepath.Join(filepath.Dir(policy), "report.json")} {
		runPolicyFileCLI(t, 2, "--policy", policy, "--trusted-policy-digest", pin, "--state-dir", state, "--trusted-snapshot-digest", snapshot, "--checks", "malicious", "--format", "json", "--output", bad, target)
		if _, err := os.Lstat(bad); !os.IsNotExist(err) {
			t.Fatal("protected state/reference output created", err)
		}
	}
}
