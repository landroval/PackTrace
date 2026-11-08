package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"packtrace/internal/cli"
	"packtrace/internal/integrityscan"
)

func TestScanNPMLTSCompatibility(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native authored scan")
	}
	t.Parallel()
	for _, profile := range []string{"npm@10.9.9", "npm@11.20.0", "npm@10-11"} {
		t.Run(profile, func(t *testing.T) {
			t.Parallel()
			parsed, err := cli.ParseArgs([]string{"scan", "--manager=" + profile, "root"})
			if err != nil || parsed.Scan.Manager != profile {
				t.Fatalf("CLI refused supported interpretation: %+v, %v", parsed, err)
			}
			target, policy, state, _, snapshot := matchingScanFixture(t, "1.0.0", true)
			// No producer hint: neither explicit policy nor built-in interpretation
			// may depend on claiming a false producer version in the target.
			manifest := `{"name":"PRIVATE-project","version":"1.0.0","dependencies":{"left-pad":"1.0.0"}}`
			if err := os.WriteFile(filepath.Join(target, "package.json"), []byte(manifest), 0600); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(policy)
			if err != nil {
				t.Fatal(err)
			}
			var selected integrityscan.Policy
			if err := json.Unmarshal(raw, &selected); err != nil {
				t.Fatal(err)
			}
			selected.Manager = profile
			raw, err = json.Marshal(selected)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(policy, raw, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			pin := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
			report, raw := runPolicyAcceptanceJSON(t, "--policy", policy, "--trusted-policy-digest", pin, "--state-dir", state, "--trusted-snapshot-digest", snapshot, "--checks", "malicious", "--format", "json", target)
			if report.Inventory == nil || report.Inventory.Selection.State != "usable" || report.Inventory.Counts.Locked == 0 || report.Advisories == nil || report.Advisories.Findings != 1 || report.Advisories.Summary.BytesRead == 0 || len(report.Policy.Findings) != 1 {
				t.Fatalf("range stopped at argument parsing instead of reaching matching: %s", raw)
			}
		})
	}
}

func TestScanNPMAutoWithoutProducerHint(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native authored scan")
	}
	t.Parallel()
	target := t.TempDir()
	for name, data := range map[string]string{
		"package.json":      `{"name":"owned-npm","dependencies":{"observed":"1.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"observed":"1.0.0"}},"node_modules/observed":{"version":"1.0.0"}}}`,
	} {
		if err := os.WriteFile(filepath.Join(target, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	report, raw := runPolicyAcceptanceJSON(t, "--format", "json", target)
	if report.Inventory == nil || report.Inventory.Selection.State != "usable" || report.Inventory.Selection.Family != "npm" || report.Inventory.Counts.Locked == 0 || report.Policy.Source != "built-in" || report.Advisories == nil || report.Advisories.Summary.BytesRead != 0 || report.Advisories.Findings != 0 {
		t.Fatalf("auto failed or format inference created advisory authority: %s", raw)
	}
}
