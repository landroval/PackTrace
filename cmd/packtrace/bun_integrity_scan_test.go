package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"packtrace/internal/integrityscan"
)

func TestScanBunReferenceIntegrityUsesOriginalTupleAndActualFiles(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native Linux/Windows CLI fixtures")
	}
	for _, mode := range []string{"equal", "modified", "wrong-lock-digest", "wrong-origin", "wrong-archive"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			target, policy := scanFixture(t)
			if err := os.Rename(filepath.Join(target, "node_modules/PRIVATE-pkg"), filepath.Join(target, "node_modules/owned-bun-pkg")); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(target, "package-lock.json")); err != nil {
				t.Fatal(err)
			}
			manifest := []byte(`{"name":"owned-bun-pkg","version":"1.0.0"}`)
			var archive bytes.Buffer
			gz := gzip.NewWriter(&archive)
			tw := tar.NewWriter(gz)
			for _, file := range []struct {
				name string
				body []byte
			}{{"package.json", manifest}, {"index.js", []byte("expected")}} {
				if err := tw.WriteHeader(&tar.Header{Name: "package/" + file.name, Size: int64(len(file.body)), Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write(file.body); err != nil {
					t.Fatal(err)
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(archive.Bytes())
			sri := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
			origin, lockSRI := "https://registry.npmjs.org", sri
			if mode == "wrong-origin" {
				origin = "https://private.example.invalid"
			}
			if mode == "wrong-lock-digest" {
				lockSRI = "sha256-" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
			}
			lock := `{"lockfileVersion":1,"configVersion":1,"workspaces":{"":{"name":"owned-bun","dependencies":{"owned-bun-pkg":"1.0.0"}}},"packages":{"owned-bun-pkg":["owned-bun-pkg@1.0.0","` + origin + `",{},"` + lockSRI + `"]}}`
			body := "expected"
			if mode == "modified" {
				body = "owned inert modification"
			}
			files := map[string][]byte{
				"package.json": []byte(`{"name":"owned-bun","version":"1.0.0","packageManager":"bun@1.3.2","dependencies":{"owned-bun-pkg":"1.0.0"}}`),
				"bun.lock":     []byte(lock),
				"node_modules/owned-bun-pkg/package.json": manifest,
				"node_modules/owned-bun-pkg/index.js":     []byte(body),
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(target, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			archiveData := archive.Bytes()
			if mode == "wrong-archive" {
				archiveData = []byte("not the pinned archive")
			}
			if err := os.WriteFile(filepath.Join(filepath.Dir(policy), "reference.tgz"), archiveData, 0600); err != nil {
				t.Fatal(err)
			}
			selected := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "owned inert Bun reference", Provenance: "independently reviewed fixture", Manager: "bun@1.3.x", RequiredChecks: []string{"integrity"}, FailOn: []string{"integrity"}, MinimumAssurance: "independently-anchored", References: []integrityscan.Reference{{Location: "node_modules/owned-bun-pkg", LockKey: "owned-bun-pkg", Name: "owned-bun-pkg", Version: "1.0.0", Origin: "https://registry.npmjs.org", Classification: "unknown", ExpectedSRI: sri, Archive: "reference.tgz", Context: "none"}}}
			data, err := json.Marshal(selected)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(policy, data, 0600); err != nil {
				t.Fatal(err)
			}
			pin := sha256.Sum256(data)
			report, raw := runPolicyAcceptanceJSON(t, "--policy", policy, "--trusted-policy-digest", "sha256-"+base64.StdEncoding.EncodeToString(pin[:]), "--checks", "integrity", "--format", "json", target)
			if report.Inventory == nil || report.Inventory.Selection.Family != "bun" || report.Inventory.Selection.State != "usable" || !report.Inventory.Complete || report.Instances != 1 {
				t.Fatalf("Bun selection/physical inventory missing: %s", raw)
			}
			valid := mode == "equal" || mode == "modified"
			if valid {
				if report.ObservedEntries != 3 || !report.Comparison.SuppliedComparisonComplete || len(report.Comparison.Gaps) != 0 {
					t.Fatalf("valid reference comparison not completed: %s", raw)
				}
			} else if report.Comparison.SuppliedComparisonComplete || len(report.Comparison.Gaps) == 0 || report.ObservedEntries != 0 {
				t.Fatalf("invalid binding/archive falsely verified or started integrity traversal: %s", raw)
			}
			wantFindings := 0
			if mode == "modified" {
				wantFindings = 1
			}
			if report.Findings != wantFindings || len(report.Policy.Findings) != wantFindings || report.Policy.EnforcedUnaccepted != wantFindings {
				t.Fatalf("equality/drift/invalid-reference finding mismatch: %s", raw)
			}
			for _, private := range []string{target, policy, "owned-bun-pkg", "private.example.invalid", sri} {
				if strings.Contains(string(raw), private) {
					t.Fatalf("portable report leaked %q", private)
				}
			}
			for name, expected := range files {
				actual, err := os.ReadFile(filepath.Join(target, name))
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatalf("scan modified owned target %s: %v", name, err)
				}
			}
		})
	}
}
