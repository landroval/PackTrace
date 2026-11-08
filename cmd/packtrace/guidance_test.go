package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHelpStartsWithUserGoalsAndExplainsTerms(t *testing.T) {
	var out, diag bytes.Buffer
	if runMain([]string{"--help"}, forbiddenReader{}, &out, &diag) != 0 || diag.Len() != 0 {
		t.Fatal("help failed")
	}
	text := out.String()
	for _, s := range []string{"Scan a project (offline)", "Prepare security advisory data", "Understand a result", "not artificial intelligence", "Candidates are leads, not confirmed vulnerabilities", "sync downloads", "Advanced command reference"} {
		if !strings.Contains(text, s) {
			t.Fatalf("missing guidance %q", s)
		}
	}
	if strings.Index(text, "Scan a project (offline)") > strings.Index(text, "Advanced command reference") {
		t.Fatal("advanced tools displaced user goals")
	}
}

func TestCommonArgumentErrorKeepsCodeAndExplainsNextStep(t *testing.T) {
	var out, diag bytes.Buffer
	if runMain([]string{"scan"}, forbiddenReader{}, &out, &diag) != 2 || out.Len() != 0 {
		t.Fatal("error semantics changed")
	}
	if !strings.HasPrefix(diag.String(), "cli: missing-root\n") || !strings.Contains(diag.String(), "Next:") || !strings.Contains(diag.String(), "packtrace scan --help") {
		t.Fatal("no safe guidance", diag.String())
	}
	out.Reset()
	diag.Reset()
	if runMain([]string{"intel", "import"}, forbiddenReader{}, &out, &diag) != 2 || out.Len() != 0 || !strings.Contains(diag.String(), "Intel import needs FILE") || strings.Contains(diag.String(), "no valid single project path") {
		t.Fatal("shared argument code got a scan-only remedy", diag.String())
	}
}

func TestMissingDatabaseStatusExplainsEffectWithoutCreatingState(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native role unavailable")
	}
	state := filepath.Join(t.TempDir(), "never-created-store")
	var out, diag bytes.Buffer
	code := runMain([]string{"intel", "status", "--state-dir", state}, forbiddenReader{}, &out, &diag)
	if code != 3 || diag.Len() != 0 {
		t.Fatal(code, diag.String())
	}
	for _, s := range []string{"Security advisory database (intel)", "not artificial intelligence", "unavailable", "Effect:", "does not mean no threats", "DIR is a placeholder"} {
		if !strings.Contains(out.String(), s) {
			t.Fatal("missing database guidance", s, out.String())
		}
	}
	if strings.Contains(out.String(), state) {
		t.Fatal("path leaked")
	}
	if _, err := os.Lstat(state); !os.IsNotExist(err) {
		t.Fatal("status created state", err)
	}
}
