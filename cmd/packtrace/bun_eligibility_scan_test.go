package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/integrityscan"
)

// These are authored inert inputs and the unchanged owned full.bundle originals;
// no producer, package manager or target code is executed.
func TestScanActualBunEligibility(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native owned input")
	}
	for _, mode := range []string{"eligible", "absent-grant", "old-npm-grant", "unknown-info", "patch", "peer", "alias", "context", "manifest-conflict", "old-pin"} {
		t.Run(mode, func(t *testing.T) {
			target, policyPath, state, _, snapshotPin := fullScanFixture(t, 4)
			// Replace only this test's authored npm input, never a checked-in fixture.
			if err := os.Remove(filepath.Join(target, "package-lock.json")); err != nil {
				t.Fatal(err)
			}
			deps := map[string]string{}
			tuples := map[string]any{}
			for i := 0; i < 4; i++ {
				name, version := fmt.Sprintf("npmfixture-%04d", i), "1.0.0"
				if i == 0 {
					version = "2.0.0"
				}
				deps[name] = version
				info := map[string]any{}
				switch mode {
				case "unknown-info":
					info["PRIVATE-new-context"] = true
				case "peer":
					info["peerDependencies"] = map[string]string{"PRIVATE-peer": "1.0.0"}
				}
				key := name
				if mode == "alias" {
					key = "alias-" + name
				}
				tuples[key] = []any{name + "@" + version, "", info, "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}
			}
			lock := map[string]any{"lockfileVersion": 1, "workspaces": map[string]any{"": map[string]any{"name": "PRIVATE-root", "dependencies": deps}}, "packages": tuples}
			if mode == "patch" {
				lock["patchedDependencies"] = map[string]string{"npmfixture-0002@1.0.0": "PRIVATE-patch"}
			}
			if mode == "context" {
				lock["PRIVATE-new-context"] = true
			}
			write := func(path string, value any) []byte {
				t.Helper()
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				return raw
			}
			write(filepath.Join(target, "package.json"), map[string]any{"name": "PRIVATE-root", "packageManager": "bun@1.3.0", "dependencies": deps})
			write(filepath.Join(target, "bun.lock"), lock)
			if mode == "manifest-conflict" {
				for _, name := range []string{"npmfixture-0002", "npmfixture-0003"} {
					write(filepath.Join(target, "node_modules", name, "package.json"), map[string]string{"name": "PRIVATE-other", "version": "1.0.0"})
				}
			}
			p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "PRIVATE-owned", Provenance: "authored-inert", Manager: "bun@1.3.x", RequiredChecks: []string{"malicious", "vulnerability"}, FailOn: []string{"malicious", "vulnerability"}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{}}
			pin := func(raw []byte) string {
				sum := sha256.Sum256(raw)
				return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
			}
			oldPin := pin(write(policyPath, p))
			for _, name := range []string{"npmfixture-0002", "npmfixture-0003"} {
				origin := "https://registry.npmjs.org/" + name + "/-/" + name + "-1.0.0.tgz"
				if mode == "old-npm-grant" {
					p.NPMOrigins = append(p.NPMOrigins, integrityscan.NPMOriginRule{Location: "node_modules/" + name, Name: name, Version: "1.0.0", Origin: origin})
				} else if mode != "absent-grant" {
					p.BunOrigins = append(p.BunOrigins, integrityscan.BunOriginRule{Location: name, Name: name, Version: "1.0.0", Origin: origin})
				}
			}
			policyPin := pin(write(policyPath, p))
			if mode == "old-pin" {
				policyPin = oldPin
			}
			// Hash every authored target file before and after the actual subprocess.
			snapshot := func() map[string]string {
				t.Helper()
				result := map[string]string{}
				err := filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if d.IsDir() {
						return nil
					}
					raw, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					sum := sha256.Sum256(raw)
					result[path] = hex.EncodeToString(sum[:])
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			before := snapshot()
			privacies := []string{"portable"}
			if mode == "eligible" {
				privacies = append(privacies, "local")
			}
			for _, privacy := range privacies {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policyPath, "--trusted-policy-digest", policyPin, "--trusted-snapshot-digest", snapshotPin, "--state-dir", state, "--checks", "malicious,vulnerability", "--privacy", privacy, "--format", "json", target)
				receipt := retainScanReceipt(t, cmd)
				var out, diag bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &diag
				err := cmd.Run()
				cancel()
				wantExit := 3
				if mode == "old-pin" || mode == "old-npm-grant" {
					wantExit = 2
				}
				if err == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != wantExit {
					t.Fatalf("scan %s/%s: %v state=%v out=%s diag=%s receipt=%s", mode, privacy, err, cmd.ProcessState, out.String(), diag.String(), receipt())
				}
				if !reflect.DeepEqual(before, snapshot()) {
					t.Fatal("scan modified target")
				}
				if mode == "old-pin" || mode == "old-npm-grant" {
					// Old authority is rejected, never silently upgraded to Bun.
					continue
				}
				if diag.Len() != 0 {
					t.Fatal(diag.String())
				}
				if privacy == "portable" {
					for _, secret := range []string{"PRIVATE", target, "npmfixture-", "registry.npmjs.org", "sha512-", "sha256-", "OSV-", "MAL-2026-"} {
						if strings.Contains(out.String(), secret) {
							t.Fatalf("portable leak %q", secret)
						}
					}
				}
				var r integrityscan.Report
				if json.Unmarshal(out.Bytes(), &r) != nil || r.ExitCode != 3 || r.Advisories == nil || r.Policy == nil || r.Inventory == nil {
					t.Fatal("missing actual material/evaluation report", out.String())
				}
				eligible := mode == "eligible" || mode == "manifest-conflict"
				matches := map[string]map[string]int{}
				for _, d := range r.Advisories.Decisions {
					if !d.EnforcementEligible {
						continue
					}
					if !eligible || d.Origin != "operator-bun-rule" || d.Candidate || d.Rule < 1 || d.Rule > 2 {
						t.Fatal("unqualified or wrong namespace decision", d)
					}
					if d.Rule != map[string]int{"malicious": 1, "vulnerability": 2}[d.Category] {
						t.Fatal("Bun namespace rule mapped to wrong original package", d)
					}
					o := r.Inventory.Observations[d.Observation-1]
					if matches[d.Category] == nil {
						matches[d.Category] = map[string]int{}
					}
					matches[d.Category][o.Class]++
					if o.Class == "installed" {
						if mode == "manifest-conflict" || o.MetadataEvidence == 0 || r.Inventory.Evidence[o.Source-1].MetadataEvidence != o.MetadataEvidence || d.LockedObservation == 0 {
							t.Fatal("installed association lost", d, o)
						}
						relations := 0
						for _, rel := range r.Inventory.Relations {
							if rel.From == d.LockedObservation && rel.To == o.ID && rel.Kind == "candidate-correspondence" && rel.Status == "indeterminate" {
								relations++
							}
						}
						if relations != 1 {
							t.Fatal("not a unique original candidate relation", d, r.Inventory.Relations)
						}
					}
				}
				wantFindings := 0
				if eligible {
					wantFindings = 4
					if mode == "manifest-conflict" {
						wantFindings = 2
					}
					for _, category := range []string{"malicious", "vulnerability"} {
						installed := 1
						if mode == "manifest-conflict" {
							installed = 0
						}
						if matches[category]["locked"] != 1 || matches[category]["installed"] != installed {
							t.Fatal("real collected category/endpoints did not qualify", matches, out.String())
						}
					}
				}
				if r.Advisories.Findings != wantFindings || len(r.Policy.Findings) != wantFindings || r.Policy.EnforcedUnaccepted != wantFindings {
					t.Fatal("actual material/evaluation did not preserve eligible matches", out.String())
				}
				if privacy == "local" {
					for _, f := range r.Policy.Findings {
						if f.Acceptance == "" || f.Tracking == "" || f.Review == nil {
							t.Fatal("missing original material binding", f)
						}
						name := map[string]string{"malicious": "npmfixture-0002", "vulnerability": "npmfixture-0003"}[f.Category]
						source := filepath.Join(target, "bun.lock")
						if f.Review.Class == "installed" {
							source = filepath.Join(target, "node_modules", name, "package.json")
						}
						if f.Package != name || f.Version != "1.0.0" || f.Review.RootManifestSHA256 != before[filepath.Join(target, "package.json")] || f.Review.SelectedLockSHA256 != before[filepath.Join(target, "bun.lock")] || f.Review.ObservationSHA256 != before[source] || f.Review.OriginalSHA256 == "" {
							t.Fatal("evaluation material detached from actual authored originals", f)
						}
					}
				}
				// Matches and material receipts do not complete native/source/index gates.
				for _, check := range []string{"native-qualification", "malicious", "vulnerability"} {
					incomplete := false
					for _, c := range r.Coverage {
						if c.Check == check && c.Required && c.Outcome == "incomplete" {
							incomplete = true
						}
					}
					if !incomplete {
						t.Fatal("residual gate falsely completed", check, r.Coverage)
					}
				}
			}
		})
	}
}
