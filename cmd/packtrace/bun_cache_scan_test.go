//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"packtrace/internal/integrityscan"
)

func TestScanBunPairedCacheAndOfflineCandidates(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"no-cache-grant", "closed-pair", "third-alias"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			target, policy, state, _, snapshot := matchingScanFixture(t, "1.0.0", false)
			if err := os.Remove(filepath.Join(target, "package-lock.json")); err != nil {
				t.Fatal(err)
			}
			for name, data := range map[string]string{
				"package.json": `{"name":"owned-bun","version":"1.0.0","dependencies":{"left-pad":"1.0.0"}}`,
				"bun.lock":     `{"lockfileVersion":1,"configVersion":1,"workspaces":{"":{"name":"owned-bun","dependencies":{"left-pad":"1.0.0"}}},"packages":{"left-pad":["left-pad@1.0.0","",{},"sha512-inert"]}}`,
			} {
				if err := os.WriteFile(filepath.Join(target, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cache := t.TempDir()
			if err := os.Mkdir(filepath.Join(cache, "left-pad@1.0.0"), 0700); err != nil {
				t.Fatal(err)
			}
			manifest := filepath.Join(target, "node_modules/left-pad/package.json")
			if err := os.Link(manifest, filepath.Join(cache, "left-pad@1.0.0/package.json")); err != nil {
				t.Fatal(err)
			}
			if mode == "third-alias" {
				if err := os.Link(manifest, filepath.Join(t.TempDir(), "unapproved")); err != nil {
					t.Fatal(err)
				}
			}
			data, err := os.ReadFile(policy)
			if err != nil {
				t.Fatal(err)
			}
			var p integrityscan.Policy
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatal(err)
			}
			p.Manager = "bun@1.3.x"
			p.AdvisoryCandidates = true
			if mode != "no-cache-grant" {
				p.BunCacheDirectory = cache
			}
			data, err = json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(policy, data, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(data)
			pin := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
			report, raw := runPolicyAcceptanceJSON(t, "--policy", policy, "--trusted-policy-digest", pin, "--state-dir", state, "--trusted-snapshot-digest", snapshot, "--checks", "malicious", "--format", "json", target)
			want := 1
			if mode == "closed-pair" {
				want = 2
			}
			if report.Inventory == nil || report.Inventory.Selection.State != "usable" || report.Inventory.Selection.Family != "bun" || report.Inventory.Counts.Locked == 0 || report.Advisories == nil || report.Advisories.Candidates != want || report.Advisories.Findings != 0 || report.Advisories.Summary.BytesRead == 0 || len(report.Policy.Findings) != 0 {
				t.Fatalf("Bun pipeline missing or candidate became finding: %s", raw)
			}
			if (mode == "closed-pair") != report.Inventory.Complete {
				t.Fatal("hardlink coverage disagreement", mode, report.Inventory.Gaps)
			}
		})
	}
}
