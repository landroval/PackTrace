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
	"runtime"
	"strings"
	"testing"

	"packtrace/internal/cli"
)

func TestVerifyIntegrity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux command")
	}
	for _, tc := range []struct {
		mode string
		exit int
	}{
		{"equal", 0}, {"modified", 1}, {"extra-unmapped", 3}, {"extra-with-drift", 3}, {"wrong-reference", 3}, {"missing-archive", 3}, {"unavailable-manifest", 3}, {"identity-conflict", 3}, {"empty-mapping", 3}, {"shared-owner", 3}, {"package-shaped-file", 3},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			target, policy, selected, _ := wholeIntegrityFixture(t, "npm", tc.mode)
			data, _ := json.Marshal(selected)
			if err := os.WriteFile(policy, data, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(data)
			pin := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
			args := []string{"verify-integrity", "--policy", policy, "--trusted-policy-digest", pin, target}
			before := wholeIntegrityTree(t, target)
			var out, diag bytes.Buffer
			exit := runMain(args, forbiddenReader{}, &out, &diag)
			if exit != tc.exit || diag.Len() != 0 {
				t.Fatalf("exit %d want %d: %s %s", exit, tc.exit, &out, &diag)
			}
			if strings.Contains(out.String(), "PRIVATE") || strings.Contains(out.String(), target) || strings.Contains(out.String(), pin) {
				t.Fatal("privacy leak")
			}
			if !reflect.DeepEqual(before, wholeIntegrityTree(t, target)) {
				t.Fatal("target changed")
			}
			// The same actual sources still leave the old scan globally incomplete.
			out.Reset()
			diag.Reset()
			old := []string{"scan", "--policy", policy, "--trusted-policy-digest", pin, "--checks", "integrity", target}
			if exit := runMain(old, forbiddenReader{}, &out, &diag); exit != 3 {
				t.Fatalf("old scan exit %d: %s", exit, &diag)
			}
		})
	}
}

func TestVerifyIntegrityPersistentReferenceRemoval(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux command")
	}
	target, policy, selected, _ := wholeIntegrityFixture(t, "npm", "equal")
	// Two actual comparisons retain positive drift when the other archive goes missing.
	second := selected.References[0]
	second.Location = "node_modules/PRIVATE-second"
	second.LockKey = second.Location
	second.Archive = "second.tgz"
	selected.References = append(selected.References, second)
	archive, err := os.ReadFile(filepath.Join(filepath.Dir(policy), "reference.tgz"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(policy), second.Archive), archive, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, second.Location), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"package.json", "index.js"} {
		body, err := os.ReadFile(filepath.Join(target, "node_modules/PRIVATE-pkg", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, second.Location, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	lockPath := filepath.Join(target, "package-lock.json")
	lockBytes, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var lock map[string]any
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		t.Fatal(err)
	}
	packages := lock["packages"].(map[string]any)
	packages[second.Location] = packages["node_modules/PRIVATE-pkg"]
	lockBytes, err = json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, lockBytes, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	pin := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	args := []string{"verify-integrity", "--policy", policy, "--trusted-policy-digest", pin, target}
	var out, diag bytes.Buffer
	if code := runMain(args, forbiddenReader{}, &out, &diag); code != 0 || !strings.Contains(out.String(), "comparisons completed: 2/2.") || strings.Contains(out.String(), "Incomplete:") {
		t.Fatalf("intact %d %s %s", code, &out, &diag)
	}
	if err := os.WriteFile(filepath.Join(target, "node_modules/PRIVATE-pkg/index.js"), []byte("drift"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	diag.Reset()
	if code := runMain(args, forbiddenReader{}, &out, &diag); code != 1 || !strings.Contains(out.String(), "drift findings: 1") {
		t.Fatalf("drift %d %s %s", code, &out, &diag)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(policy), "second.tgz")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	diag.Reset()
	if code := runMain(args, forbiddenReader{}, &out, &diag); code != 3 || !strings.Contains(out.String(), "drift findings: 1") || !strings.Contains(out.String(), "comparisons completed: 1/2.") || !strings.Contains(out.String(), "reference-unusable") {
		t.Fatalf("missing plus drift %d %s %s", code, &out, &diag)
	}
}

func TestVerifyIntegrityControls(t *testing.T) {
	var out, diag bytes.Buffer
	for _, args := range [][]string{{"verify-integrity"}, {"verify-integrity", "--help", "extra"}, {"verify-integrity", "--policy", "x", "--trusted-policy-digest", "x", "--checks", "integrity", "root"}} {
		if code := runMain(args, forbiddenReader{}, &out, &diag); code != 2 {
			t.Fatalf("invalid args %d", code)
		}
	}
	if code := runMain([]string{"verify-integrity", "--help"}, forbiddenReader{}, &out, &diag); code != 0 {
		t.Fatal(code)
	}
	if runtime.GOOS != "linux" {
		return
	}
	target, policy, selected, _ := wholeIntegrityFixture(t, "npm", "equal")
	data, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	req := cli.ScanArgumentRequest{Path: target, PolicyPath: policy, TrustedPolicyDigest: "sha256-" + base64.StdEncoding.EncodeToString(sum[:]), Manager: "npm", Checks: cli.ArgumentCheckIntegrity, FailOn: cli.ArgumentCheckIntegrity, Privacy: "portable", Format: "terminal", Output: "-"}
	for _, short := range []bool{false, true} {
		if code := runIntegrityContext(context.Background(), req, failedWriter{short}, &diag, nil); code != 2 {
			t.Fatalf("output failure %d", code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := runIntegrityContext(ctx, req, &out, &diag, nil); code != 130 {
		t.Fatalf("cancel exit %d", code)
	}
}
