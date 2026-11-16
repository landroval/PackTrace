package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanPortableIntegrityOnlyRetainsInventoryWitnesses(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native Linux/Windows CLI fixtures")
	}
	target, policy := scanFixture(t)
	for name, data := range map[string]string{
		"package.json":                          `{"name":"owned-project","version":"1.0.0","packageManager":"npm@10.9.4","dependencies":{"PRIVATE-pkg":"1.0.0"}}`,
		"node_modules/PRIVATE-pkg/package.json": `{"name":"PRIVATE-pkg","version":"1.0.0"}`,
	} {
		if err := os.WriteFile(filepath.Join(target, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	lockPath := filepath.Join(target, "package-lock.json")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var lock map[string]any
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	lock["packages"].(map[string]any)[""] = map[string]any{"name": "owned-project", "version": "1.0.0", "dependencies": map[string]string{"PRIVATE-pkg": "1.0.0"}}
	data, err = json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, privacy := range []string{"portable", "local"} {
		t.Run(privacy, func(t *testing.T) {
			report, raw := runPolicyAcceptanceJSON(t, "--policy", policy, "--checks", "integrity", "--privacy", privacy, "--format", "json", target)
			if report.Inventory == nil || !report.Inventory.Complete || report.Inventory.Selection.Evidence == 0 || report.Advisories != nil {
				t.Fatalf("integrity-only original inventory witness missing: %s", raw)
			}
			installed := 0
			for _, observation := range report.Inventory.Observations {
				if observation.Class == "installed" {
					installed++
					if observation.MetadataEvidence == 0 || report.Inventory.Evidence[observation.Source-1].MetadataEvidence != observation.MetadataEvidence {
						t.Fatalf("manifest/native metadata association missing: %s", raw)
					}
				}
			}
			closedInventory := false
			for _, coverage := range report.Coverage {
				if coverage.Check == "inventory" {
					closedInventory = coverage.Required && coverage.Outcome == "completed"
				}
			}
			if installed != 1 || !closedInventory || len(report.Policy.Exceptions) != 0 {
				t.Fatalf("native inventory lost without advisory/exception material: %s", raw)
			}
			if privacy == "portable" {
				for _, secret := range []string{"PRIVATE", target, policy, "owned-project", "sha256-"} {
					if strings.Contains(string(raw), secret) {
						t.Fatalf("numeric inventory witness exposed %q", secret)
					}
				}
			}
		})
	}
}
