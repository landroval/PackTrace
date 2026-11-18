package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/integrityscan"
)

// These are untouched npm pack --offline --ignore-scripts outputs, not tar
// streams rewritten to accommodate the parser. See testdata/npm-pack/README.md.
func npmPackIntegrityFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	target, prepared := filepath.Join(root, "target"), filepath.Join(root, "prepared")
	if err := os.MkdirAll(prepared, 0700); err != nil {
		t.Fatal(err)
	}
	packages := map[string]any{"": map[string]any{"name": "owned-root", "version": "1.0.0"}}
	policy := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "owned offline npm pack qualification", Provenance: "reviewed inert source and untouched npm pack archives", Manager: "npm@10.9.4", RequiredChecks: []string{"integrity"}, FailOn: []string{"integrity"}, MinimumAssurance: "independently-anchored"}
	put := func(path string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, location := range []string{"node_modules/owned-integrity-fixture", "node_modules/@owned/integrity-fixture", "node_modules/owned-integrity-fixture/node_modules/owned-integrity-fixture"} {
		name, archive := "owned-integrity-fixture", "owned-integrity-fixture-1.0.0.tgz"
		if location == "node_modules/@owned/integrity-fixture" {
			name, archive = "@owned/integrity-fixture", "scoped.tgz"
		}
		data, err := os.ReadFile(filepath.Join("testdata/npm-pack", archive))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		sri := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
		put(filepath.Join(prepared, archive), data)
		for _, file := range []string{"package.json", "index.js", "lib/deep/value.txt"} {
			data, err := os.ReadFile(filepath.Join("testdata/npm-pack/source", file))
			if err != nil {
				t.Fatal(err)
			}
			if name == "@owned/integrity-fixture" && file == "package.json" {
				data = []byte("{\"name\": \"@owned/integrity-fixture\", \"version\": \"1.0.0\", \"files\": [\"lib\", \"index.js\"]}\n")
			}
			put(filepath.Join(target, location, file), data)
		}
		origin := "https://registry.npmjs.org"
		packages[location] = map[string]any{"name": name, "version": "1.0.0", "resolved": origin, "integrity": sri}
		policy.References = append(policy.References, integrityscan.Reference{Location: location, LockKey: location, Name: name, Version: "1.0.0", Origin: origin, Classification: "unknown", ExpectedSRI: sri, Archive: archive, Context: "none"})
	}
	put(filepath.Join(target, "package.json"), []byte(`{"name":"owned-root","version":"1.0.0","packageManager":"npm@10.9.4"}`))
	lock, err := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": packages})
	if err != nil {
		t.Fatal(err)
	}
	put(filepath.Join(target, "package-lock.json"), lock)
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(prepared, "policy.json")
	put(path, data)
	sum := sha256.Sum256(data)
	return target, path, "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func TestVerifyIntegrityActualNPMPack(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux command")
	}
	target, policy, pin := npmPackIntegrityFixture(t)
	for _, tc := range []struct {
		mode string
		want int
	}{{"intact", 0}, {"drift", 1}, {"missing-plus-drift", 3}} {
		t.Run(tc.mode, func(t *testing.T) {
			if tc.mode == "drift" {
				if err := os.WriteFile(filepath.Join(target, "node_modules/owned-integrity-fixture/lib/deep/value.txt"), []byte("owned drift\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.mode == "missing-plus-drift" {
				if err := os.Remove(filepath.Join(filepath.Dir(policy), "scoped.tgz")); err != nil {
					t.Fatal(err)
				}
			}
			for _, command := range []string{"verify-integrity", "scan"} {
				var out, diag bytes.Buffer
				args := []string{command, "--policy", policy, "--trusted-policy-digest", pin}
				want := tc.want
				if command == "scan" {
					args = append(args, "--checks", "integrity")
					want = 3
				}
				args = append(args, target)
				if code := runMain(args, forbiddenReader{}, &out, &diag); code != want {
					t.Fatalf("%s: got %d want %d: %s %s", command, code, want, &out, &diag)
				}
			}
		})
	}
}

func TestVerifyIntegrityExpiredDeadline(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux command")
	}
	target, policy, pin := npmPackIntegrityFixture(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	var out, diag bytes.Buffer
	req := cli.ScanArgumentRequest{Path: target, PolicyPath: policy, TrustedPolicyDigest: pin, Manager: "npm", Checks: cli.ArgumentCheckIntegrity, FailOn: cli.ArgumentCheckIntegrity, Privacy: "portable", Format: "terminal", Output: "-"}
	if code := runIntegrityContext(ctx, req, &out, &diag, nil); code != 2 {
		t.Fatalf("deadline returned %d, not fatal: %s %s", code, &out, &diag)
	}
}
