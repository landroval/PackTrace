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
)

func runPolicyAcceptanceJSON(t *testing.T, args ...string) (integrityscan.Report, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestSupervisedCLIProcess$", "--", "scan"}, args...)...)
	var out, diag bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diag
	err := cmd.Run()
	if err == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 || diag.Len() != 0 {
		t.Fatalf("expected genuinely incomplete scan, err=%v state=%v stdout=%s stderr=%s", err, cmd.ProcessState, out.String(), diag.String())
	}
	var report integrityscan.Report
	if json.Unmarshal(out.Bytes(), &report) != nil || report.SchemaVersion != "1.7" || report.Policy == nil || report.ExitCode != 3 {
		t.Fatalf("missing operational policy model: %s", out.String())
	}
	return report, out.Bytes()
}

func TestScanBuiltinDefaultsDoNotDiscoverPolicyOrGrantOrigins(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native authored CLI")
	}
	target := t.TempDir()
	for name, data := range map[string]string{
		"package.json":        `{"name":"owned-case","version":"1.0.0","packageManager":"npm@10.9.4"}`,
		"package-lock.json":   `{"lockfileVersion":3,"packages":{"":{}}}`,
		"packtrace.config.js": `throw new Error("PRIVATE-executable-policy-must-not-run")`,
		".packtracerc":        `{"requiredChecks":[],"failOn":[],"advisoryCandidates":true}`,
		".npmrc":              "//PRIVATE-authored-bait:never-read\n",
	} {
		if err := os.WriteFile(filepath.Join(target, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	report, raw := runPolicyAcceptanceJSON(t, "--checks", "integrity", "--format", "json", target)
	if report.Policy.Source != "built-in" || report.Policy.FailOn != 0 || len(report.Policy.Exceptions) != 0 || report.Policy.EnforcedUnaccepted != 0 || report.Instances != 0 || report.Inventory == nil || report.Inventory.Selection.Family != "npm" || report.Inventory.Selection.State != "usable" {
		t.Fatalf("defaults/source/selected interpretation disagree: %s", raw)
	}
	for _, secret := range []string{"PRIVATE", target, "owned-case", "sha256-"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("portable defaults leaked %q", secret)
		}
	}
}

func TestScanExceptionUsesEvidenceNotPolicyBytesOrPrivacy(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native authored CLI")
	}
	target, policy, state, pin, snapshot := matchingScanFixture(t, "1.0.0", true)
	base := []string{"--policy", policy, "--state-dir", state, "--trusted-snapshot-digest", snapshot, "--checks", "malicious", "--fail-on", "malicious", "--format", "json"}
	run := func(privacy, policyPin string) (integrityscan.Report, []byte) {
		args := append(append([]string{}, base...), "--privacy", privacy, "--trusted-policy-digest", policyPin, target)
		return runPolicyAcceptanceJSON(t, args...)
	}
	initial, _ := run("local", pin)
	if initial.Advisories == nil || initial.Advisories.Findings != 1 || len(initial.Policy.Findings) != 1 || initial.Policy.EnforcedUnaccepted != 1 {
		t.Fatal("nonvacuous finding required before acceptance")
	}
	finding := initial.Policy.Findings[0]
	if finding.Accepted || finding.Acceptance == "" || finding.Tracking == "" || finding.Decision < 0 || finding.Review == nil || finding.Review.Project == "" || finding.Review.OriginalSHA256 == "" {
		t.Fatal("reviewable local evidence missing")
	}
	decision := initial.Advisories.Decisions[finding.Decision]
	var id string
	for _, original := range initial.Advisories.Local.Advisories {
		if original.Advisory == decision.Advisory {
			id = original.ID
		}
	}
	project := finding.Review.Project
	if finding.Review.Advisory != id {
		t.Fatal("local review and original advisory disagree")
	}
	data, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	var selected integrityscan.Policy
	if json.Unmarshal(data, &selected) != nil {
		t.Fatal("authored policy")
	}
	now := time.Now().UTC().Truncate(time.Second)
	selected.FailOn = []string{"malicious"}
	selected.Exceptions = []integrityscan.Exception{{ID: "PRIVATE-review-id", Reason: "PRIVATE-reviewed-owned-fixture", Owner: "PRIVATE-approval-assertion", ApprovedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Scope: integrityscan.FindingScope{Project: project, Category: "malicious", Rule: "osv-npm", Class: "locked", Package: "left-pad", Version: "1.0.0", Origin: "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz", Instance: "node_modules/left-pad", Advisory: id}, Acceptance: finding.Acceptance}}
	writePolicy := func() string {
		data, err := json.Marshal(selected)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(policy, data, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	}
	pin = writePolicy()
	accepted, portable := run("portable", pin)
	if accepted.Advisories.Findings != 1 || len(accepted.Policy.Findings) != 1 || !accepted.Policy.Findings[0].Accepted || accepted.Policy.EnforcedUnaccepted != 0 || accepted.Policy.Exceptions[0].Disposition != "applied" {
		t.Fatalf("acceptance circular with policy bytes or lost finding: %s", portable)
	}
	for _, secret := range []string{"PRIVATE", "left-pad", "registry.npmjs.org", "sha256-", target, finding.Acceptance, finding.Tracking} {
		if strings.Contains(string(portable), secret) {
			t.Fatalf("portable exception leaked %q", secret)
		}
	}
	local, _ := run("local", pin)
	if !local.Policy.Findings[0].Accepted || local.Policy.Findings[0].Acceptance != finding.Acceptance || local.Policy.Findings[0].Tracking != finding.Tracking {
		t.Fatal("privacy changed acceptance evidence")
	}
	selected.Exceptions[0].ApprovedAt = now.Add(-2 * time.Hour).Format(time.RFC3339)
	selected.Exceptions[0].ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339)
	expired, _ := run("portable", writePolicy())
	if expired.Policy.Findings[0].Accepted || expired.Policy.EnforcedUnaccepted != 1 || expired.Policy.Exceptions[0].Disposition != "expired" {
		t.Fatal("expired exception accepted")
	}
	selected.Exceptions[0].ApprovedAt = now.Add(time.Hour).Format(time.RFC3339)
	selected.Exceptions[0].ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339)
	future, _ := run("portable", writePolicy())
	if future.Policy.Findings[0].Accepted || future.Policy.EnforcedUnaccepted != 1 || future.Policy.Exceptions[0].Disposition != "future" {
		t.Fatal("future approval accepted")
	}
	selected.Exceptions[0].ApprovedAt = now.Add(-time.Hour).Format(time.RFC3339)
	selected.Exceptions[0].ExpiresAt = now.Add(time.Hour).Format(time.RFC3339)
	pin = writePolicy()
	f, err := os.OpenFile(filepath.Join(target, "package-lock.json"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.WriteString("\n")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("owned lock mutation")
	}
	changed, _ := run("portable", pin)
	if changed.Policy.Findings[0].Accepted || changed.Policy.EnforcedUnaccepted != 1 || changed.Advisories.Findings != 1 {
		t.Fatal("changed selected-lock bytes inherited acceptance")
	}
}
