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
