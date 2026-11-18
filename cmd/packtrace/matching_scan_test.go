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

	"packtrace/internal/execution"
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
	if filepath.IsAbs(bundle) {
		source, bundle = filepath.Dir(bundle), filepath.Base(bundle)
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

// This oracle is authored for the fixture, not computed by a production
// completeness predicate or copied from the other member of the pair. It also
// keeps unselected optional obligations distinct from required gaps.
func assertMatchingCoverage(t *testing.T, r integrityscan.Report) {
	t.Helper()
	want := map[string]struct {
		required bool
		outcome  string
	}{
		"inventory":              {true, "completed"},
		"integrity":              {false, "not-run"},
		"malicious":              {true, "incomplete"},
		"vulnerability":          {true, "incomplete"},
		"reference-authority":    {false, "not-run"},
		"native-qualification":   {true, "incomplete"},
		"resident-observation":   {true, "incomplete"},
		"execution":              {true, "completed"},
		"intelligence-access":    {true, "completed"},
		"intelligence-freshness": {true, "incomplete"},
	}
	for _, c := range r.Coverage {
		w, ok := want[c.Check]
		if !ok || c.Required != w.required || c.Outcome != w.outcome || c.Reason == "" {
			t.Fatalf("unexpected coverage row: %+v", c)
		}
		delete(want, c.Check)
	}
	if len(want) != 0 {
		t.Fatal("missing coverage rows", want)
	}
}

// Receipts are inspected after Wait even on successful assertions. Comparison
// coverage must not be retroactively completed by a healthy final receipt.
func assertMatchingScanReceipt(t *testing.T, raw string, outputFailed bool) {
	t.Helper()
	t.Logf("final receipt: %s", raw)
	var r execution.ScanReceipt
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal("invalid final receipt", err, raw)
	}
	if !r.Finished || !r.CleanupConfirmed || r.Resources.QueryFailed || r.Resources.Stale || r.Resources.Stopped || r.Resources.WorkerSamples == 0 || r.Resources.SupervisorSamples == 0 || r.CallerContext != "active" {
		t.Fatal("unhealthy final receipt", raw)
	}
	wantRoles := []string{"scan", "scan", "scan-writer"}
	if outputFailed {
		// The caller attempts a diagnostic after the failed report writer;
		// that writer also encounters the closed inherited sink.
		wantRoles = append(wantRoles, "scan-writer")
	}
	if len(r.Roles) != len(wantRoles) {
		t.Fatal("unexpected preparation/comparison/output roles", raw)
	}
	for i, role := range r.Roles {
		wantExit := 0
		wantExchange := true
		if outputFailed && i >= 2 {
			wantExit, wantExchange = 2, false
		}
		if role.Role != wantRoles[i] || !role.Reaped || !role.WaitReturned || !role.ExchangeJoined || !role.StderrJoined || role.Samples == 0 || role.ExchangeSucceeded != wantExchange || role.ExitCode != wantExit {
			t.Fatal("unconfirmed child lifecycle", raw)
		}
	}
	fault := r.FirstFault
	if outputFailed {
		writerFailure := fault.Stage == "exchange" && fault.Code == "output-failed" || fault.Stage == "wait-exit" && fault.Code == "child-exit"
		if !writerFailure || fault.Role != "scan-writer" || r.Roles[2].ExitCode != 2 {
			t.Fatal("late output failure lost its causal writer fault", raw)
		}
	} else if fault.Stage != "" || fault.Code != "" || fault.Role != "" {
		t.Fatal("unexpected first fault", raw)
	}
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
					if format == "terminal" {
						args = append(args, "--verbose") // This assertion checks per-record evidence, not the compact default.
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
					t.Logf("actual exit: %d", cmd.ProcessState.ExitCode())
					assertMatchingScanReceipt(t, receipt(), false)
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
					if format == "json" {
						t.Logf("comparison: %s", out.String())
					}
					a := report.Advisories
					if report.SchemaVersion != "1.8" || report.ExitCode != 3 || report.Findings != 0 || a == nil || a.State != "observed" || a.Findings != tc.findings || a.Summary.Observations != 1 || a.Summary.TotalObservations != 1 || len(a.Decisions) == 0 {
						t.Fatal("actual matching/independent drift model disagrees", out.String())
					}
					assertMatchingCoverage(t, report)
					if report.Policy == nil || len(report.Policy.Findings) != tc.findings || report.Policy.EnforcedUnaccepted != tc.findings {
						t.Fatal("policy findings differ from the independent case oracle", out.String())
					}
					for _, f := range report.Policy.Findings {
						if f.Category != "malicious" || f.Accepted || !f.Enforced {
							t.Fatal("eligible malicious finding lost enforcement", out.String())
						}
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
					if format == "json" && tc.rule && tc.snapshotPin {
						t.Run("late-output-failure", func(t *testing.T) {
							// Identical executable, arguments, policy, generation and owned
							// inputs. Only the inherited output sink changes. No snapshot
							// is patched or promoted to final operational authority.
							read, write, err := os.Pipe()
							if err != nil {
								t.Fatal(err)
							}
							if err := read.Close(); err != nil {
								t.Fatal(err)
							}
							defer write.Close()
							failed := exec.CommandContext(ctx, os.Args[0], args...)
							final := retainScanReceipt(t, failed)
							failed.Stdout, failed.Stderr = write, write
							err = failed.Run()
							if err == nil || failed.ProcessState == nil || failed.ProcessState.ExitCode() != 2 {
								t.Fatalf("late output: %v state=%v receipt=%s", err, failed.ProcessState, final())
							}
							t.Logf("actual exit: %d; preceding comparison exit: %d; enforced unaccepted: %d", failed.ProcessState.ExitCode(), report.ExitCode, report.Policy.EnforcedUnaccepted)
							assertMatchingScanReceipt(t, final(), true)
						})
					}
				})
			}
		})
	}
}
