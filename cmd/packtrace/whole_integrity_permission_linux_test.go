//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestScanWholeIntegrityPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-denial fixture requires an ordinary user")
	}
	for _, family := range []string{"npm", "bun"} {
		for _, privacy := range []string{"portable", "local"} {
			t.Run(family+"/"+privacy, func(t *testing.T) {
				target, policy, selected, _ := wholeIntegrityFixture(t, family, "equal")
				before := wholeIntegrityTree(t, target)
				data, err := json.Marshal(selected)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(policy, data, 0600); err != nil {
					t.Fatal(err)
				}
				manifest := filepath.Join(target, "node_modules/PRIVATE-pkg/package.json")
				if err := os.Chmod(manifest, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chmod(manifest, 0600); err != nil {
						t.Error(err)
					}
				})
				if _, err := os.ReadFile(manifest); !os.IsPermission(err) {
					t.Fatalf("fixture did not actually deny manifest reading: %v", err)
				}
				pin := sha256.Sum256(data)
				r, raw := runPolicyAcceptanceJSON(t, "--policy", policy, "--trusted-policy-digest", "sha256-"+base64.StdEncoding.EncodeToString(pin[:]), "--checks", "integrity", "--privacy", privacy, "--format", "json", target)
				if r.Inventory == nil || r.Inventory.Complete || r.Inventory.Counts.Installed != 1 || r.Findings != 0 || len(r.Policy.Findings) != 0 || r.Comparison.SuppliedComparisonComplete || len(r.Comparison.Gaps) == 0 {
					t.Fatalf("unreadable manifest became complete, absent or false drift: %s", raw)
				}
				unreadable := 0
				for _, observation := range r.Inventory.Observations {
					if observation.Class == "installed" && observation.Kind == "directory" && observation.Status == "unreadable" {
						unreadable++
					}
				}
				if unreadable != 1 {
					t.Fatalf("actual unreadable instance was hidden: %s", raw)
				}
				wholeIntegrityCoverage(t, r, "integrity", "incomplete")
				wholeIntegrityCoverage(t, r, "inventory", "incomplete")
				wholeIntegrityCoverage(t, r, "native-qualification", "incomplete")
				wholeIntegrityCoverage(t, r, "resident-observation", "incomplete")
				if privacy == "portable" {
					for _, secret := range []string{"PRIVATE", target, policy, "registry.npmjs.org", "sha256-"} {
						if strings.Contains(string(raw), secret) {
							t.Fatalf("permission-denial path exposed %q", secret)
						}
					}
				}
				info, err := os.Stat(manifest)
				if err != nil || info.Mode().Perm() != 0 {
					t.Fatalf("scan changed denied permissions: %v %v", info, err)
				}
				// Only fixture teardown restores readability; compare every original
				// file, mode and link after restoration, never silently repair a scan.
				if err := os.Chmod(manifest, 0600); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before, wholeIntegrityTree(t, target)) {
					t.Fatal("scan changed owned target contents, entries or modes")
				}
			})
		}
	}
}
