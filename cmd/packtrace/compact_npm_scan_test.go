package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"packtrace/internal/nativefs"
	"packtrace/internal/projectinventory"
)

func TestScanCompactNPMRootWholeIntegrity(t *testing.T) {
	for _, mode := range []string{"equal", "modified"} {
		t.Run(mode, func(t *testing.T) {
			target, policy, p, _ := wholeIntegrityFixture(t, "npm", mode)
			old := p.References[0].Origin
			p.References[0].Origin = "https://registry.npmjs.org/PRIVATE-pkg/-/PRIVATE-pkg-1.0.0.tgz"
			lock := filepath.Join(target, "package-lock.json")
			raw, err := os.ReadFile(lock)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lock, bytes.ReplaceAll(raw, []byte(old), []byte(p.References[0].Origin)), 0600); err != nil {
				t.Fatal(err)
			}
			raw, _ = json.Marshal(p)
			if err := os.WriteFile(policy, raw, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			root, err := nativefs.OpenRoot(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			inv, err := projectinventory.Collect(context.Background(), root, projectinventory.Options{Profile: p.Manager, RetainIntegrityOriginals: true})
			ce := root.Close()
			if err != nil || ce != nil {
				t.Fatal(err, ce)
			}
			if _, ok := projectinventory.CompactNPMOriginal(inv); !ok {
				t.Fatal("CLI fixture did not select compact profile")
			}
			before := wholeIntegrityTree(t, target)
			for _, privacy := range []string{"portable", "local"} {
				t.Run(privacy, func(t *testing.T) {
					r, raw := runPolicyAcceptanceJSON(t, "--policy", policy, "--trusted-policy-digest", "sha256-"+base64.StdEncoding.EncodeToString(sum[:]), "--checks", "integrity", "--privacy", privacy, "--format", "json", target)
					wholeIntegrityCoverage(t, r, "integrity", "completed")
					wholeIntegrityCoverage(t, r, "reference-authority", "completed")
					if r.Instances != 1 || (r.Findings == 0) != (mode == "equal") {
						t.Fatalf("wrong comparison: %s", raw)
					}
					if !reflect.DeepEqual(before, wholeIntegrityTree(t, target)) {
						t.Fatal("target changed")
					}
				})
			}
		})
	}
}

// This opt-in corpus is independently generated/replayed outside the product.
// Completion of comparison is deliberately distinct from whole-scope admission.
func TestOfflineCompactNPMBoundaryCLI(t *testing.T) {
	base := os.Getenv("PACKTRACE_COMPACT_NPM_BOUNDARIES")
	if base == "" {
		t.Skip("requires owned multi-file and boundary fixtures")
	}
	for _, tc := range []struct {
		name                             string
		instances, findings              int
		inventory, integrity, comparison string
	}{
		{"multifile-1000", 1000, 0, "completed", "completed", "completed"},
		{"witness-1022", 1022, 0, "completed", "completed", "completed"},
		{"witness-1023", 1023, 0, "completed", "incomplete", "completed"},
		{"manifest-4k", 1000, 0, "completed", "incomplete", "completed"},
		{"nested-1000", 1000, 1, "completed", "incomplete", "incomplete"},
		{"workspace-1000", 1000, 0, "incomplete", "incomplete", "completed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(base, tc.name, "target")
			policy := filepath.Join(base, tc.name, "prepared", "compact-policy.json")
			raw, err := os.ReadFile(policy)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			before := wholeIntegrityTree(t, target)
			// The external eight-file replay takes ~31 s. This is only the
			// test-process timeout; no product deadline or freshness guard changes.
			r, _ := runPolicyAcceptanceJSONWithin(t, 90*time.Second, "--policy", policy, "--trusted-policy-digest", "sha256-"+base64.StdEncoding.EncodeToString(sum[:]), "--checks", "integrity", "--privacy", "portable", "--format", "json", target)
			wholeIntegrityCoverage(t, r, "inventory", tc.inventory)
			wholeIntegrityCoverage(t, r, "integrity", tc.integrity)
			wholeIntegrityCoverage(t, r, "reference-comparison", tc.comparison)
			wholeIntegrityCoverage(t, r, "native-qualification", "incomplete")
			if r.Instances != tc.instances || r.Findings != tc.findings || r.ExitCode != 3 {
				t.Fatalf("wrong bounded outcome: instances=%d findings=%d exit=%d", r.Instances, r.Findings, r.ExitCode)
			}
			if !reflect.DeepEqual(before, wholeIntegrityTree(t, target)) {
				t.Fatal("target changed")
			}
			t.Logf("instances=%d findings=%d exit=%d inventory=%s integrity=%s comparison=%s", r.Instances, r.Findings, r.ExitCode, tc.inventory, tc.integrity, tc.comparison)
		})
	}
}

func TestOfflineCompactNPMThousandCLI(t *testing.T) {
	base := os.Getenv("PACKTRACE_COMPACT_NPM_CLI")
	if base == "" {
		t.Skip("requires owned 1000 tiny-payload fixture, not full workload")
	}
	target := filepath.Join(base, "checked-1000", "target")
	policy := filepath.Join(base, "checked-1000", "prepared", "compact-policy.json")
	raw, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	before := wholeIntegrityTree(t, target)
	r, _ := runPolicyAcceptanceJSON(t, "--policy", policy, "--trusted-policy-digest", "sha256-"+base64.StdEncoding.EncodeToString(sum[:]), "--checks", "integrity", "--privacy", "portable", "--format", "json", target)
	for _, check := range []string{"inventory", "integrity", "reference-authority", "reference-comparison"} {
		wholeIntegrityCoverage(t, r, check, "completed")
	}
	wholeIntegrityCoverage(t, r, "native-qualification", "incomplete")
	if r.Instances != 1000 || r.Inventory == nil || r.Inventory.Counts.Installed != 1000 || r.Findings != 0 || len(r.Comparison.Gaps) != 0 || r.ExitCode != 3 {
		t.Fatal("1000 tiny comparison milestone not met")
	}
	if !reflect.DeepEqual(before, wholeIntegrityTree(t, target)) {
		t.Fatal("target changed")
	}
	t.Logf("supervised CLI instances=%d installed=%d findings=%d exit=%d resources=%+v", r.Instances, r.Inventory.Counts.Installed, r.Findings, r.ExitCode, r.Resources)
}
