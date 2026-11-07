package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/integrityscan"
	"packtrace/internal/intelstore"
	"packtrace/internal/nativefs"
)

func matchingScanFixture(t *testing.T, version string, originRule bool) (string, string, string, string, string) {
	t.Helper()
	return matchingScanFixtureBundle(t, version, originRule, "matching.bundle")
}

func matchingScanFixtureBundle(t *testing.T, version string, originRule bool, bundle string) (string, string, string, string, string) {
	t.Helper()
	base := t.TempDir()
	target, external, state := filepath.Join(base, "PRIVATE-target"), filepath.Join(base, "PRIVATE-policy"), filepath.Join(base, "PRIVATE-state")
	location := "node_modules/left-pad"
	if os.MkdirAll(filepath.Join(target, filepath.FromSlash(location)), 0700) != nil || os.Mkdir(external, 0700) != nil {
		t.Fatal("owned directories")
	}
	origin := "https://registry.npmjs.org/left-pad/-/left-pad-" + version + ".tgz"
	manifest := `{"name":"PRIVATE-project","version":"1.0.0","packageManager":"npm@10.9.4","dependencies":{"left-pad":"` + version + `"}}`
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"PRIVATE-project","version":"1.0.0","dependencies":{"left-pad":"` + version + `"}},"` + location + `":{"name":"left-pad","version":"` + version + `","resolved":"` + origin + `"}}}`
	for name, content := range map[string]string{
		filepath.Join(target, "package.json"):                               manifest,
		filepath.Join(target, "package-lock.json"):                          lock,
		filepath.Join(target, filepath.FromSlash(location), "package.json"): `{"name":"left-pad","version":"` + version + `"}`,
		filepath.Join(target, filepath.FromSlash(location), "index.js"):     "// authored inert package; never executed\n",
	} {
		if e := os.WriteFile(name, []byte(content), 0600); e != nil {
			t.Fatal(e)
		}
	}
	p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "PRIVATE-owned-case", Provenance: "PRIVATE-authored-inert-source", Manager: "npm@10.9.4", RequiredChecks: []string{"malicious"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{}}
	if originRule {
		p.NPMOrigins = []integrityscan.NPMOriginRule{{Location: location, Name: "left-pad", Version: version, Origin: origin}}
	}
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	policy := filepath.Join(external, "policy.json")
	if e := os.WriteFile(policy, raw, 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	policyPin := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	ctx := context.Background()
	source, e := filepath.Abs("../../internal/execution/testdata/intel")
	if e != nil {
		t.Fatal(e)
	}
	root, e := nativefs.OpenRoot(ctx, source)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	input, e := root.OpenDistributionInput(ctx, bundle)
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	store, e := intelstore.Open(ctx, state, intelstore.CreateOwned)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	imported, e := store.Import(ctx, input, intelstore.ImportOptions{})
	if e != nil {
		t.Fatal(e)
	}
	snapshotPin := "sha256-" + base64.StdEncoding.EncodeToString(imported.Generation[:])
	return target, policy, state, policyPin, snapshotPin
}

func TestScanActualOfflineAdvisoryMatching(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native authored scan")
	}
	t.Parallel()
	for _, tc := range []struct {
		name, version     string
		rule, snapshotPin bool
		findings          int
	}{
		{"supported-malicious-match", "1.0.0", true, true, 1},
		{"supported-version-negative", "2.0.0", true, true, 0},
		{"lock-url-does-not-authorize-origin", "1.0.0", false, true, 0},
		{"import-does-not-inherit-source-authority", "1.0.0", true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			target, policy, state, policyPin, snapshotPin := matchingScanFixture(t, tc.version, tc.rule)
			formats := []string{"json"}
			// The positive case checks all views; semantic controls need only one
			// view of the same model, avoiding repeated supervised processes.
			if tc.name == "supported-malicious-match" {
				formats = append(formats, "terminal", "sarif")
			}
			for _, format := range formats {
				t.Run(format, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					args := []string{"-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--trusted-policy-digest", policyPin, "--checks", "malicious,vulnerability", "--fail-on", "malicious", "--state-dir", state, "--format", format}
					if tc.snapshotPin {
						args = append(args, "--trusted-snapshot-digest", snapshotPin)
					}
					args = append(args, target)
					cmd := exec.CommandContext(ctx, os.Args[0], args...)
					receipt := retainScanReceipt(t, cmd)
					var out, diag bytes.Buffer
					cmd.Stdout, cmd.Stderr = &out, &diag
					e := cmd.Run()
					if e == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 || diag.Len() != 0 {
						t.Fatalf("actual scan: %v state=%v out=%s diag=%s receipt=%s", e, cmd.ProcessState, out.String(), diag.String(), receipt())
					}
					for _, secret := range []string{"PRIVATE", "left-pad", "registry.npmjs.org", "MAL-2026-", "sha256-", "withdrawn_versions"} {
						if strings.Contains(out.String()+diag.String(), secret) {
							t.Fatalf("portable matching leaked %q", secret)
						}
					}
					if format == "terminal" {
						if !strings.Contains(out.String(), "Advisories: observed") || !strings.Contains(out.String(), "Required coverage: incomplete") {
							t.Fatal("matching or independent coverage absent", out.String())
						}
						for _, locator := range []string{"rule=1", "profile=openssf-malicious-v1", "fully-evaluated=true", "Support version=0 range=-1"} {
							if !strings.Contains(out.String(), locator) {
								t.Fatal("terminal dropped matching evidence", locator, out.String())
							}
						}
						return
					}
					var report integrityscan.Report
					if format == "json" {
						if json.Unmarshal(out.Bytes(), &report) != nil {
							t.Fatal("invalid scan JSON", out.String())
						}
					} else {
						var sarif struct {
							Runs []struct {
								Properties integrityscan.Report `json:"properties"`
								Results    []json.RawMessage    `json:"results"`
							} `json:"runs"`
						}
						if json.Unmarshal(out.Bytes(), &sarif) != nil || len(sarif.Runs) != 1 {
							t.Fatal("invalid scan SARIF", out.String())
						}
						report = sarif.Runs[0].Properties
						if len(sarif.Runs[0].Results) != tc.findings {
							t.Fatal("SARIF candidates promoted or findings omitted", out.String())
						}
					}
					a := report.Advisories
					if report.SchemaVersion != "1.6" || report.ExitCode != 3 || report.Findings != 0 || a == nil || a.State != "observed" || a.Findings != tc.findings || a.Summary.Observations != 1 || a.Summary.TotalObservations != 1 || len(a.Decisions) == 0 {
						t.Fatal("actual matching/independent drift model disagrees", out.String())
					}
					negative, withdrawn, unsupported := false, false, false
					for _, d := range a.Decisions {
						negative = negative || d.VersionOutcome == "no-match" && d.FullyEvaluated && d.Outcome == "no-match"
						withdrawn = withdrawn || d.Activity == "withdrawn" && !d.EnforcementEligible
						unsupported = unsupported || d.VersionOutcome == "match" && d.Outcome == "indeterminate" && !d.EnforcementEligible
					}
					if tc.rule && tc.snapshotPin && (!withdrawn || tc.version == "1.0.0" && !unsupported || tc.version == "2.0.0" && !negative) {
						t.Fatal("withdrawal/correction or full negative lost", out.String())
					}
				})
			}
		})
	}
}
