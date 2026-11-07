package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func fullScanFixture(t *testing.T, count int) (string, string, string, string, string) {
	t.Helper()
	base := t.TempDir()
	target, controller, state := filepath.Join(base, "PRIVATE-target"), filepath.Join(base, "PRIVATE-controller"), filepath.Join(base, "PRIVATE-state")
	if os.MkdirAll(filepath.Join(target, "node_modules"), 0700) != nil || os.Mkdir(controller, 0700) != nil {
		t.Fatal("owned input directories")
	}
	write := func(path string, value any) {
		t.Helper()
		raw, e := json.Marshal(value)
		if e != nil || os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("authored metadata", e)
		}
	}
	dependencies := map[string]string{}
	packages := map[string]any{"": map[string]any{"name": "private-project", "version": "1.0.0", "dependencies": dependencies}}
	for i := range count {
		name, version := fmt.Sprintf("npmfixture-%04d", i), "1.0.0"
		if i%5 == 0 {
			version = "2.0.0"
		}
		dependencies[name] = version
		origin := "https://registry.npmjs.org/" + name + "/-/" + name + "-" + version + ".tgz"
		if i%29 == 0 {
			origin = "https://PRIVATE-user:PRIVATE-password@private.invalid/" + name + ".tgz"
		}
		packages["node_modules/"+name] = map[string]any{"name": name, "version": version, "resolved": origin}
		if i%41 == 0 {
			continue // Complete enumeration must distinguish a non-observed lock entry.
		}
		dir := filepath.Join(target, "node_modules", name)
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
		installed := version
		if i%17 == 0 {
			installed = "9.0.0" // Its own manifest conflicts with the selected lock.
		}
		write(filepath.Join(dir, "package.json"), map[string]any{"name": name, "version": installed})
	}
	write(filepath.Join(target, "package.json"), map[string]any{"name": "private-project", "version": "1.0.0", "packageManager": "npm@10.9.4", "dependencies": dependencies})
	write(filepath.Join(target, "package-lock.json"), map[string]any{"lockfileVersion": 3, "packages": packages})
	if e := os.WriteFile(filepath.Join(target, ".npmrc"), []byte("//private.invalid/:_authToken=PRIVATE-secret-token\n"), 0600); e != nil {
		t.Fatal(e)
	}
	policy := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "PRIVATE-investigation", Provenance: "authored-inert-local-policy", Manager: "npm@10.9.4", RequiredChecks: []string{"malicious", "vulnerability"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{}, NPMRegistry: "https://registry.npmjs.org"}
	policyPath := filepath.Join(controller, "policy.json")
	write(policyPath, policy)
	raw, e := os.ReadFile(policyPath)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	policyPin := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	ctx := context.Background()
	fixturePath, e := filepath.Abs("../../internal/execution/testdata/intel")
	if e != nil {
		t.Fatal(e)
	}
	root, e := nativefs.OpenRoot(ctx, fixturePath)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	input, e := root.OpenDistributionInput(ctx, "full.bundle")
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	store, e := intelstore.Open(ctx, state, intelstore.CreateOwned)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	received, e := store.Import(ctx, input, intelstore.ImportOptions{})
	if e != nil {
		t.Fatal(e)
	}
	return target, policyPath, state, policyPin, "sha256-" + base64.StdEncoding.EncodeToString(received.Generation[:])
}

func TestScanFiveHundredPackagesDistinguishesInstalledAndLocalPrivacy(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native inputs")
	}
	t.Parallel()
	target, policy, state, policyPin, snapshotPin := fullScanFixture(t, 500)
	var portable *integrityscan.AdvisoryReport
	for _, privacy := range []string{"portable", "local"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--trusted-policy-digest", policyPin, "--trusted-snapshot-digest", snapshotPin, "--state-dir", state, "--checks", "malicious,vulnerability", "--privacy", privacy, "--format", "json", target)
		receipt := retainScanReceipt(t, cmd)
		var out, diag bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diag
		e := cmd.Run()
		cancel()
		if e == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 || diag.Len() != 0 {
			t.Fatalf("500-package scan: privacy=%s err=%v state=%v out=%s diag=%s receipt=%s", privacy, e, cmd.ProcessState, out.String(), diag.String(), receipt())
		}
		var report integrityscan.Report
		if json.Unmarshal(out.Bytes(), &report) != nil || report.SchemaVersion != "1.4" || report.Privacy != privacy || report.Advisories == nil || report.Advisories.State != "observed" {
			t.Fatal("actual large scan/report unavailable", out.String())
		}
		a := report.Advisories
		if a.Summary.TotalObservations != 500 || a.Summary.Observations != 500 || a.Summary.TotalInstalledObservations < 450 || a.Summary.InstalledObservations != a.Summary.TotalInstalledObservations || a.Summary.Work > 4096 || a.Summary.BytesRead > 512<<20 {
			t.Fatal("normal project silently truncated or limits widened", a.Summary)
		}
		categories, classes, negative, unknown := map[string]int{}, map[string]int{}, 0, 0
		for _, d := range a.Decisions {
			if d.EnforcementEligible {
				categories[d.Category]++
				class := report.Inventory.Observations[d.Observation-1].Class
				classes[class]++
				if class == "installed" && d.LockedObservation == 0 {
					t.Fatal("installed evidence inherited no qualified correspondence")
				}
			}
			if d.Outcome == "no-match" {
				negative++
			}
			if d.Outcome == "indeterminate" {
				unknown++
			}
		}
		if categories["malicious"] == 0 || categories["vulnerability"] == 0 || classes["installed"] == 0 || classes["locked"] == 0 || negative == 0 || unknown == 0 {
			t.Fatal("missing actionable two-category/observation distinctions", categories, classes, negative, unknown)
		}
		for _, secret := range []string{"PRIVATE-secret-token", "PRIVATE-user", "PRIVATE-password", target, policy, policyPin, snapshotPin} {
			if strings.Contains(out.String(), secret) {
				t.Fatal("secrets, absolute selector or authority pin leaked", secret)
			}
		}
		if privacy == "portable" {
			if a.Local != nil || strings.Contains(out.String(), "npmfixture-") || strings.Contains(out.String(), "GHSA-") || strings.Contains(out.String(), "MAL-2026-") || strings.Contains(out.String(), "node_modules/") {
				t.Fatal("portable matching sidecar leaked raw identities")
			}
			portable = a
		} else {
			if a.Local == nil || a.Local.Limited || len(a.Local.Observations) < 950 || len(a.Local.Advisories) == 0 || !strings.Contains(out.String(), "node_modules/npmfixture-") || !strings.Contains(out.String(), "GHSA-") || !strings.Contains(out.String(), "MAL-2026-") {
				t.Fatal("explicit local view is not actionable", a.Summary)
			}
			left, _ := json.Marshal(portable.Decisions)
			right, _ := json.Marshal(a.Decisions)
			if !bytes.Equal(left, right) || portable.Findings != a.Findings || portable.Summary.Work != a.Summary.Work || portable.Summary.BytesRead != a.Summary.BytesRead {
				t.Fatal("presentation profile changed actual matching decisions")
			}
		}
		t.Logf("privacy=%s locked=%d installed=%d findings=%d work=%d bytes=%d categories=%v", privacy, a.Summary.Observations, a.Summary.InstalledObservations, a.Findings, a.Summary.Work, a.Summary.BytesRead, categories)
	}
}
