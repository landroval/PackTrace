package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/execution"
	"packtrace/internal/integrityscan"
)

func scanFixture(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "PRIVATE-target")
	external := filepath.Join(base, "PRIVATE-reference")
	if e := os.MkdirAll(filepath.Join(root, "node_modules/PRIVATE-pkg"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(external, 0700); e != nil {
		t.Fatal(e)
	}
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	body := []byte("expected")
	if e := tw.WriteHeader(&tar.Header{Name: "package/index.js", Size: int64(len(body)), Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); e != nil {
		t.Fatal(e)
	}
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	hash := sha256.Sum256(data.Bytes())
	sri := "sha256-" + base64.StdEncoding.EncodeToString(hash[:])
	p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "PRIVATE-reason", Provenance: "PRIVATE-receipt", Manager: "npm@10.9.4", RequiredChecks: []string{"integrity"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{{Location: "node_modules/PRIVATE-pkg", LockKey: "node_modules/PRIVATE-pkg", Name: "PRIVATE-pkg", Version: "1.0.0", Origin: "fixture:PRIVATE", Classification: "unknown", ExpectedSRI: sri, Archive: "reference.tgz", Context: "patch"}}}
	policy, _ := json.Marshal(p)
	policyPath := filepath.Join(external, "policy.json")
	lock := `{"lockfileVersion":3,"packages":{"":{},"node_modules/PRIVATE-pkg":{"name":"PRIVATE-pkg","version":"1.0.0","resolved":"fixture:PRIVATE","integrity":"` + sri + `"}}}`
	for name, content := range map[string][]byte{policyPath: policy, filepath.Join(external, "reference.tgz"): data.Bytes(), filepath.Join(root, "package-lock.json"): []byte(lock), filepath.Join(root, "node_modules/PRIVATE-pkg/index.js"): []byte("actual modification")} {
		if e := os.WriteFile(name, content, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return root, policyPath
}

func TestScanActualSupervisedNativeFlow(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local owned Linux process cases only")
	}
	root, policy := scanFixture(t)
	for _, format := range []string{"terminal", "json", "sarif"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--checks", "integrity", "--fail-on", "integrity", "--format", format, root)
		var out, diag bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &diag
		e := cmd.Run()
		cancel()
		if e == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 || out.Len() == 0 || diag.Len() != 0 {
			t.Fatalf("actual scan %s: exit=%v %v stdout=%s stderr=%s", format, cmd.ProcessState, e, out.String(), diag.String())
		}
		if strings.Contains(out.String()+diag.String(), "PRIVATE") || strings.Contains(out.String(), sensitiveDigestPrefix) {
			t.Fatal("portable report leaked policy, identity, path or SRI", out.String())
		}
		if format == "json" {
			var r integrityscan.Report
			if json.Unmarshal(out.Bytes(), &r) != nil || r.ExitCode != 3 || r.Findings != 1 || r.NativeQualification != "not-run" || r.Resources.WorkerSamples < 1 || r.Resources.SupervisorSamples < 1 {
				t.Fatalf("actual model disagrees: %s", out.String())
			}
		}
	}
	actual, e := os.ReadFile(filepath.Join(root, "node_modules/PRIVATE-pkg/index.js"))
	if e != nil || string(actual) != "actual modification" {
		t.Fatal("observer wrote target")
	}
}

const sensitiveDigestPrefix = "sha256-"

func TestScanPreflightRejectsUnsafeModesAndPolicyWeakening(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local owned Linux process cases only")
	}
	root, policy := scanFixture(t)
	for _, extra := range [][]string{{"--privacy", "local"}, {"--output", filepath.Join(root, "report.json")}, {"--state-dir", root}, {"--checks", "malicious"}} {
		args := append([]string{"scan", "--policy", policy}, extra...)
		args = append(args, root)
		var out, diag bytes.Buffer
		if code := runMain(args, forbiddenReader{}, &out, &diag); code != 2 || out.Len() != 0 || strings.Contains(diag.String(), "PRIVATE") {
			t.Fatalf("unsafe mode accepted: %v %d %s %s", extra, code, out.String(), diag.String())
		}
	}
	if _, e := os.Lstat(filepath.Join(root, "report.json")); !os.IsNotExist(e) {
		t.Fatal("explicit output opened")
	}
}

func TestScanPrivateRoleAndCanceledBeforeAcquisition(t *testing.T) {
	var out, diag bytes.Buffer
	if code := runMain([]string{execution.ScanWorkerArgument}, forbiddenReader{}, &out, &diag); code != 2 || out.Len() != 0 || diag.Len() != 0 {
		t.Fatal("private scan role lacks capability gate")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := cli.ScanArgumentRequest{Path: "PRIVATE", PolicyPath: "PRIVATE", Manager: "auto", Privacy: "portable", Format: "json", Output: "-", Checks: cli.ArgumentCheckIntegrity}
	if code := runScanContext(ctx, request, &out, &diag); code != 130 || out.Len() != 0 || strings.Contains(diag.String(), "PRIVATE") {
		t.Fatal("pre-cancel ignored", code, out.String(), diag.String())
	}
}
