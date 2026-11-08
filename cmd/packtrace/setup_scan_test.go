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
)

func TestSetupThenOrdinaryScan(t *testing.T) {
	t.Parallel()
	for _, family := range []string{"npm", "bun"} {
		t.Run(family, func(t *testing.T) {
			t.Parallel()
			target, policy, state, _, snapshot := matchingScanFixtureBundle(t, "1.0.0", false, "readable.bundle")
			config := t.TempDir()
			data, err := os.ReadFile(policy)
			if err != nil {
				t.Fatal(err)
			}
			var p integrityscan.Policy
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatal(err)
			}
			p.AdvisoryCandidates = true
			if family == "bun" {
				if err := os.Remove(filepath.Join(target, "package-lock.json")); err != nil {
					t.Fatal(err)
				}
				for name, contents := range map[string]string{
					"package.json": `{"name":"owned-bun","version":"1.0.0","dependencies":{"left-pad":"1.0.0"}}`,
					"bun.lock":     `{"lockfileVersion":1,"configVersion":1,"workspaces":{"":{"name":"owned-bun","dependencies":{"left-pad":"1.0.0"}}},"packages":{"left-pad":["left-pad@1.0.0","",{},"sha512-inert"]}}`,
				} {
					if err := os.WriteFile(filepath.Join(target, name), []byte(contents), 0600); err != nil {
						t.Fatal(err)
					}
				}
				cache := t.TempDir()
				if err := os.Mkdir(filepath.Join(cache, "left-pad@1.0.0"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(filepath.Join(target, "node_modules/left-pad/package.json"), filepath.Join(cache, "left-pad@1.0.0/package.json")); err != nil {
					t.Fatal(err)
				}
				p.Manager, p.BunCacheDirectory = "bun@1.3.x", cache
			}
			data, err = json.Marshal(p)
			if err != nil || os.WriteFile(policy, data, 0600) != nil {
				t.Fatal("write policy", err)
			}
			invoke := func(want int, args ...string) []byte {
				t.Helper()
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
					t.Fatalf("command failed: %v, stdout=%s stderr=%s", err, out.Bytes(), diag.Bytes())
				}
				return out.Bytes()
			}
			invoke(0, "setup", "--policy", policy, "--state-dir", state, "--trusted-snapshot-digest", snapshot)
			// Actual product command, no policy/state/hash/privacy/check options.
			terminal := invoke(3, "scan", target)
			if !bytes.Contains(terminal, []byte("left-pad")) || !bytes.Contains(terminal, []byte("Candidate only")) || !bytes.Contains(terminal, []byte("[INCOMPLETE] Scan coverage")) || bytes.Contains(terminal, []byte("Advisory observation=")) {
				t.Fatalf("ordinary terminal scan is not a compact actionable summary: %s", terminal)
			}
			if !bytes.Contains(terminal, []byte("Advisory says: Owned advisory")) || !bytes.Contains(terminal, []byte("exact version is listed as affected")) || bytes.Contains(terminal, []byte("fixed boundary")) {
				t.Fatal("readable original context missing or invented fix", string(terminal))
			}
			verbose := invoke(3, "scan", "--verbose", target)
			if !bytes.Contains(verbose, []byte("Advisory observation=")) || !bytes.Contains(verbose, []byte("Support version=")) {
				t.Fatal("verbose flag lost the original evidence view", string(verbose))
			}
			var r integrityscan.Report
			raw := invoke(3, "scan", "--format", "json", target)
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			if r.Privacy != "local" || r.Advisories == nil || r.Advisories.Local == nil || r.Advisories.Candidates != 2 || r.Advisories.Findings != 0 || r.Advisories.Summary.BytesRead == 0 || r.Inventory == nil || !r.Inventory.Complete || r.Inventory.Selection.Family != family {
				t.Fatalf("saved setup failed to connect real inventory/matching: %s", raw)
			}
			portable := invoke(3, "scan", "--privacy", "portable", "--format", "json", target)
			for _, secret := range []string{"left-pad", "Owned advisory", target, config, policy, state, snapshot, "sha256-"} {
				if bytes.Contains(portable, []byte(secret)) {
					t.Fatalf("portable override leaked %q", secret)
				}
			}
			// Every scan must still independently verify the policy original.
			if err := os.WriteFile(policy, append(data, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if len(invoke(2, "scan", "--format", "json", target)) != 0 {
				t.Fatal("changed policy produced a report")
			}
		})
	}
}
