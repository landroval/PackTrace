//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"packtrace/internal/integrityscan"
	"packtrace/internal/projectinventory"
)

const pnpmScanLock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      PRIVATE-pkg:\n        specifier: ^7\n        version: 1.0.0\npackages:\n  PRIVATE-pkg@1.0.0:\n    resolution: {integrity: sha512-inert}\nsnapshots:\n  PRIVATE-pkg@1.0.0: {}\n"

func TestPNPMActualSupervisedScan(t *testing.T) {
	target, source, config := t.TempDir(), t.TempDir(), t.TempDir()
	state := filepath.Join(t.TempDir(), "absent-state")
	files := map[string]string{"package.json": `{"packageManager":"pnpm@10.34.9","dependencies":{"PRIVATE-pkg":"^1"},"workspaces":["packages/*"]}`, "pnpm-lock.yaml": pnpmScanLock, "node_modules/PRIVATE-pkg/package.json": `{"name":"PRIVATE-pkg","version":"1.0.0"}`, "packages/PRIVATE-workspace/package.json": `{"dependencies":{"PRIVATE-decoy":"1"}}`}
	for name, body := range files {
		full := filepath.Join(target, name)
		if os.MkdirAll(filepath.Dir(full), 0700) != nil || os.WriteFile(full, []byte(body), 0600) != nil {
			t.Fatal("fixture")
		}
	}
	policyPath := filepath.Join(source, "policy.json")
	p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "PRIVATE-reason", Provenance: "PRIVATE-source", Manager: "pnpm@lockfile-9", RequiredChecks: []string{"integrity"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{{Location: "node_modules/PRIVATE-pkg", LockKey: "PRIVATE-pkg@1.0.0", Name: "PRIVATE-pkg", Version: "1.0.0", Origin: "fixture:PRIVATE", Classification: "unknown", ExpectedSRI: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Archive: "PRIVATE-missing.tgz", Context: "none"}}}
	policy, err := json.Marshal(p)
	if err != nil || os.WriteFile(policyPath, policy, 0600) != nil {
		t.Fatal("policy", err)
	}
	invoke := func(want int, args ...string) []byte {
		t.Helper()
		args = append([]string{args[0], "--state-dir", state}, args[1:]...)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestSupervisedCLIProcess$", "--"}, args...)...)
		for _, v := range os.Environ() {
			if !strings.HasPrefix(v, "XDG_CONFIG_HOME=") {
				cmd.Env = append(cmd.Env, v)
			}
		}
		cmd.Env = append(cmd.Env, "XDG_CONFIG_HOME="+config)
		var out, diag bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diag
		err := cmd.Run()
		if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != want || want != 2 && diag.Len() != 0 {
			t.Fatalf("exit/reap: %v %v stdout=%s stderr=%s", err, cmd.ProcessState, out.Bytes(), diag.Bytes())
		}
		return out.Bytes()
	}
	for _, manager := range []string{"auto", "pnpm", "pnpm@lockfile-9"} {
		for _, format := range []string{"terminal", "json", "sarif"} {
			raw := invoke(3, "scan", "--manager", manager, "--format", format, target)
			for _, secret := range []string{"PRIVATE", target, source, config} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatalf("portable leak %q", secret)
				}
			}
			if format == "terminal" {
				if !bytes.Contains(raw, []byte("0 installed observations")) || !bytes.Contains(raw, []byte("INCOMPLETE")) {
					t.Fatal(string(raw))
				}
				continue
			}
			var fields map[string]json.RawMessage
			if format == "json" {
				err = json.Unmarshal(raw, &fields)
			} else {
				var sarif struct {
					Runs []struct {
						Properties map[string]json.RawMessage `json:"properties"`
					} `json:"runs"`
				}
				err = json.Unmarshal(raw, &sarif)
				if err == nil && len(sarif.Runs) == 1 {
					fields = sarif.Runs[0].Properties
				}
			}
			encoded, encodeErr := json.Marshal(fields)
			var report integrityscan.Report
			if encodeErr != nil || json.Unmarshal(encoded, &report) != nil || report.Findings != 0 || report.ObservedEntries != 0 || report.ExitCode != 3 || report.Advisories != nil && (report.Advisories.Candidates != 0 || report.Advisories.Findings != 0 || report.Advisories.Summary.BytesRead != 0) {
				t.Fatalf("pnpm gained scan authority: %s", raw)
			}
			var inv projectinventory.PublicInventory
			if err != nil || json.Unmarshal(fields["inventory"], &inv) != nil || projectinventory.ValidatePublic(inv) != nil || inv.Complete || inv.Selection.Family != "pnpm" || inv.Counts.Declared != 1 || inv.Counts.Locked < 2 || inv.Counts.Installed != 0 || inv.Counts.Scopes != 1 || len(inv.Relations) != 0 {
				t.Fatalf("common pnpm inventory: %s", raw)
			}
		}
	}
	// Explicit policy and saved setup retain the format pin, never grant installed authority.
	raw := invoke(3, "scan", "--policy", policyPath, "--format", "json", target)
	var explicit integrityscan.Report
	if json.Unmarshal(raw, &explicit) != nil || explicit.Inventory == nil || explicit.Inventory.Selection.Family != "pnpm" || explicit.Instances != 1 || explicit.ObservedEntries != 0 || explicit.Findings != 0 {
		t.Fatal(string(raw))
	}
	invoke(0, "setup", "--policy", policyPath)
	invoke(3, "scan", "--privacy", "portable", "--format", "json", target)
	invoke(2, "scan", "--manager", "npm", target)
	if os.WriteFile(policyPath, append(policy, '\n'), 0600) != nil {
		t.Fatal("policy mutation")
	}
	if len(invoke(2, "scan", "--format", "json", target)) != 0 {
		t.Fatal("changed setup pin emitted report")
	}
	invoke(3, "scan", "--policy", policyPath, "--privacy", "portable", "--format", "json", target)
	// No operator policy discovery is needed for mixed/invalid input gaps.
	if os.WriteFile(filepath.Join(target, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"":{}}}`), 0600) != nil {
		t.Fatal("mixed fixture")
	}
	mixed := invoke(3, "scan", "--policy", policyPath, "--manager", "auto", "--privacy", "portable", "--format", "json", target)
	if !bytes.Contains(mixed, []byte("manager-conflict")) {
		t.Fatal(string(mixed))
	}
	invoke(3, "scan", "--policy", policyPath, "--manager", "pnpm", "--privacy", "portable", "--format", "json", target)
	if os.WriteFile(filepath.Join(target, "pnpm-lock.yaml"), []byte("lockfileVersion: '8.0'\nimporters: {}\n"), 0600) != nil {
		t.Fatal("invalid format")
	}
	invalid := invoke(3, "scan", "--policy", policyPath, "--manager", "pnpm", "--privacy", "portable", "--format", "json", target)
	if !bytes.Contains(invalid, []byte("lock-version-unsupported")) {
		t.Fatal(string(invalid))
	}
	if os.WriteFile(filepath.Join(target, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\nPRIVATE-parser-secret: [\n"), 0600) != nil {
		t.Fatal("invalid YAML")
	}
	malformed := invoke(3, "scan", "--policy", policyPath, "--manager", "pnpm", "--privacy", "portable", "--format", "json", target)
	if !bytes.Contains(malformed, []byte("lock-invalid")) || bytes.Contains(malformed, []byte("PRIVATE")) {
		t.Fatal(string(malformed))
	}
	// Only intentionally changed lock/policy files may differ; installed/workspace decoys are inert.
	for name, body := range files {
		if name == "pnpm-lock.yaml" {
			continue
		}
		got, e := os.ReadFile(filepath.Join(target, name))
		if e != nil || string(got) != body {
			t.Fatal("target mutated", name, e)
		}
	}
}
