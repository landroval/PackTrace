package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"packtrace/internal/integrityscan"
)

func TestScanIntegrityExceptionBindsActualFileEvidenceAndAssurance(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native authored CLI")
	}
	target, policy := scanFixture(t)
	manifest := []byte(`{"name":"owned-project","version":"1.0.0","packageManager":"npm@10.9.4","dependencies":{"PRIVATE-pkg":"1.0.0"}}`)
	if os.WriteFile(filepath.Join(target, "package.json"), manifest, 0600) != nil || os.WriteFile(filepath.Join(target, "node_modules/PRIVATE-pkg/package.json"), []byte(`{"name":"PRIVATE-pkg","version":"1.0.0"}`), 0600) != nil {
		t.Fatal("authored manifests")
	}
	lockPath := filepath.Join(target, "package-lock.json")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var lock map[string]any
	if json.Unmarshal(data, &lock) != nil {
		t.Fatal("authored lock")
	}
	lock["packages"].(map[string]any)[""] = map[string]any{"name": "owned-project", "version": "1.0.0", "dependencies": map[string]string{"PRIVATE-pkg": "1.0.0"}}
	data, err = json.Marshal(lock)
	if err != nil || os.WriteFile(lockPath, data, 0600) != nil {
		t.Fatal("authored root lock")
	}
	data, err = os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	var selected integrityscan.Policy
	if json.Unmarshal(data, &selected) != nil {
		t.Fatal("authored policy")
	}
	selected.FailOn = []string{"integrity"}
	writePolicy := func() string {
		data, err := json.Marshal(selected)
		if err != nil {
			t.Fatal(err)
		}
		if os.WriteFile(policy, data, 0600) != nil {
			t.Fatal("authored pinned policy")
		}
		sum := sha256.Sum256(data)
		return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	}
	run := func(pin, privacy string) integrityscan.Report {
		r, _ := runPolicyAcceptanceJSON(t, "--policy", policy, "--trusted-policy-digest", pin, "--checks", "integrity", "--privacy", privacy, "--format", "json", target)
		return r
	}
	initial := run(writePolicy(), "local")
	var chosen *integrityscan.PolicyFinding
	for i := range initial.Policy.Findings {
		f := &initial.Policy.Findings[i]
		if f.Path == "index.js" {
			chosen = f
		}
	}
	if initial.Findings != 2 || chosen == nil || chosen.Review == nil || chosen.Review.Expected == nil || chosen.Review.Observed == nil || chosen.Review.Expected.SHA256 == chosen.Review.Observed.SHA256 || chosen.Review.Assurance != "independently-anchored" || chosen.Review.ReferenceObservedSRI == "" {
		t.Fatalf("actual changed-file review evidence missing: %+v", initial.Policy)
	}
	oldAcceptance := chosen.Acceptance
	now := time.Now().UTC().Truncate(time.Second)
	selected.Exceptions = []integrityscan.Exception{{ID: "owned-index-review", Reason: "authored inert change", Owner: "asserted owner", ApprovedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Acceptance: oldAcceptance, Scope: integrityscan.FindingScope{Project: chosen.Review.Project, Category: "integrity", Rule: "integrity-drift", Class: "installed", Package: chosen.Package, Version: chosen.Version, Origin: selected.References[0].Origin, Instance: chosen.Instance, Path: chosen.Path, Change: chosen.Review.Change}}}
	pin := writePolicy()
	accepted := run(pin, "portable")
	count := 0
	for _, f := range accepted.Policy.Findings {
		if f.Accepted {
			count++
		}
	}
	if accepted.Findings != 2 || count != 1 || accepted.Policy.EnforcedUnaccepted != 1 {
		t.Fatalf("narrow file acceptance lost findings or accepted added manifest: %+v", accepted.Policy)
	}
	if os.WriteFile(filepath.Join(target, "node_modules/PRIVATE-pkg/index.js"), []byte("another authored change"), 0600) != nil {
		t.Fatal("owned file mutation")
	}
	changed := run(pin, "local")
	for _, f := range changed.Policy.Findings {
		if f.Path == "index.js" && (f.Accepted || f.Acceptance == oldAcceptance) {
			t.Fatal("changed observed bytes inherited acceptance")
		}
	}
	if changed.Findings != 2 || changed.Policy.EnforcedUnaccepted != 2 {
		t.Fatal("changed evidence was hidden")
	}
}
