package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/integrityscan"
)

func TestActualPinnedPolicyScanAndRefusals(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned supported native unit")
	}
	root, policy := scanFixture(t)
	data, e := os.ReadFile(policy)
	if e != nil {
		t.Fatal("fixture policy")
	}
	var p integrityscan.Policy
	if json.Unmarshal(data, &p) != nil {
		t.Fatal("fixture shape")
	}
	p.MinimumAssurance = "independently-anchored"
	data, e = json.Marshal(p)
	if e != nil || os.WriteFile(policy, data, 0600) != nil {
		t.Fatal("fixture policy bytes")
	}
	a := sha256.Sum256(data)
	b := sha512.Sum384(data)
	c := sha512.Sum512(data)
	run := func(pin string) (int, []byte, []byte) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		args := []string{"-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--checks", "integrity", "--format", "json"}
		if pin != "" {
			args = append(args, "--trusted-policy-digest", pin)
		}
		cmd := exec.CommandContext(ctx, os.Args[0], append(args, root)...)
		var out, diag bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &diag
		_ = cmd.Run()
		if cmd.ProcessState == nil {
			t.Fatal("no waited command state")
		}
		if strings.Contains(out.String()+diag.String(), "PRIVATE") || strings.Contains(out.String()+diag.String(), "sha256-") || strings.Contains(out.String()+diag.String(), "sha384-") || strings.Contains(out.String()+diag.String(), "sha512-") {
			t.Fatal("portable pin flow exposed source data")
		}
		return cmd.ProcessState.ExitCode(), out.Bytes(), diag.Bytes()
	}
	for _, pin := range []string{"sha256-" + base64.StdEncoding.EncodeToString(a[:]), "sha384-" + base64.StdEncoding.EncodeToString(b[:]), "sha512-" + base64.StdEncoding.EncodeToString(c[:])} {
		code, out, diag := run(pin)
		var report integrityscan.Report
		if code != 3 || len(diag) != 0 || json.Unmarshal(out, &report) != nil || report.Findings != 1 || report.MinimumAssurance != "independently-anchored" || !strings.Contains(report.PolicyOrigin, "operator-digest-pin") {
			t.Fatalf("real pinned comparison failed: code=%d report=%s diagnostic=%s", code, out, diag)
		}
		authority := false
		for _, coverage := range report.Coverage {
			if coverage.Check == "reference-authority" {
				authority = coverage.Outcome == "completed"
			}
		}
		if !authority || report.NativeQualification != "not-run" {
			t.Fatal("operator authority missing or global native qualification promoted")
		}
	}
	pin := "sha256-" + base64.StdEncoding.EncodeToString(a[:])
	for _, bad := range []string{"", "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} {
		code, out, _ := run(bad)
		if code != 2 || len(out) != 0 {
			t.Fatal("missing/wrong operator pin produced report", code)
		}
	}
	changed := append(append([]byte{}, data...), ' ')
	if os.WriteFile(policy, changed, 0600) != nil {
		t.Fatal("owned mutation")
	}
	if code, out, _ := run(pin); code != 2 || len(out) != 0 {
		t.Fatal("changed policy bypassed pin")
	}
	if os.WriteFile(policy, data, 0600) != nil {
		t.Fatal("restore owned policy")
	}
	lock := filepath.Join(root, "package-lock.json")
	raw, e := os.ReadFile(lock)
	if e != nil {
		t.Fatal("fixture lock")
	}
	raw = bytes.ReplaceAll(raw, []byte(p.References[0].ExpectedSRI), []byte("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
	if os.WriteFile(lock, raw, 0600) != nil {
		t.Fatal("owned conflict")
	}
	code, out, _ := run(pin)
	var report integrityscan.Report
	if code != 3 || json.Unmarshal(out, &report) != nil || report.Findings != 0 {
		t.Fatal("conflicting lockfile became verified drift")
	}
	for _, coverage := range report.Coverage {
		if coverage.Check == "reference-authority" && coverage.Outcome == "completed" {
			t.Fatal("baseline conflict erased")
		}
	}
}
