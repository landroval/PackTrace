package main

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestCompatibilityRootBudgetReusesOnlyItsExistingSupervisorAllowance(t *testing.T) {
	if rootCorpusSeconds(false) != 270 {
		t.Fatal("native Windows root allocation changed")
	}
	root := rootCorpusSeconds(true)
	if root != 700 {
		t.Fatal("compatibility root allocation not reassigned", root)
	}
	// Source, Go version, self-check, root, vet, source-clean: compatibility
	// does not run race rows. Keep a margin inside the unchanged supervisor.
	if total := 10 + 10 + 90 + root + 25 + 10; total > 890-45 {
		t.Fatal("compatibility allocation escaped its existing total", total)
	}
}

func TestStorageFactsKeepLimitsAndHidePaths(t *testing.T) {
	for _, tc := range []struct {
		err   error
		stage string
		code  uint32
	}{
		{nil, "", 0}, {errStorageType, "owned-storage-type", 0}, {errStorageLimit, "owned-storage-limit", 0},
		{&os.PathError{Op: "lstat", Path: "PRIVATE", Err: syscall.Errno(5)}, "owned-storage-observation", 5},
	} {
		stage, code := storageFailureFacts(tc.err)
		if stage != tc.stage || code != tc.code || strings.Contains(stage, "PRIVATE") {
			t.Fatal("fixed storage metadata mismatch", stage, code)
		}
	}
}

func TestWindowsProfilesSeparateDiagnosticsFromValidation(t *testing.T) {
	for _, tc := range []struct {
		profile           string
		diagnostic, valid bool
	}{
		{"windows-scan-amd64-v1", false, true},
		{"windows-volume-diagnostic-amd64-v1", true, true},
		{"windows11-x64-compat-arm64-v1", false, true},
		{"", false, false}, {"windows-other", false, false},
	} {
		diagnostic, e := volumeDiagnostic(tc.profile)
		if (e == nil) != tc.valid || diagnostic != tc.diagnostic {
			t.Fatalf("profile=%q diagnostic=%t error=%v", tc.profile, diagnostic, e)
		}
	}
}

func TestDesktopMachinesRequireX64EmulationOnARM64(t *testing.T) {
	for _, tc := range []struct {
		compiledArch string
		host         uint16
		want         bool
	}{{"amd64", 0xaa64, true}, {"", 0xaa64, false}, {"amd64", 0x8664, false}, {"arm64", 0xaa64, false}, {"amd64", 0, false}, {"386", 0xaa64, false}} {
		if got := desktopEmulation(tc.compiledArch, tc.host); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}

func TestCaptureLimitRetainsExactPrefixAndStops(t *testing.T) {
	stopped := 0
	c := capture{cap: 4, complete: true, stop: func() { stopped++ }}
	n, e := c.Write([]byte("abcdef"))
	if n != 4 || e != errCapture || string(c.data) != "abcd" || c.complete || stopped != 1 {
		t.Fatal(n, e, string(c.data), c.complete, stopped)
	}
}
func TestCountsCannotPromotePartialOrFailedStream(t *testing.T) {
	for _, s := range []string{"", `{"Action":"pass","Test":"T"}`, "not-json\n"} {
		if _, e := testCounts([]byte(s)); e == nil {
			t.Fatal("incomplete admitted", s)
		}
	}
	c, e := testCounts([]byte(strings.Join([]string{`{"Action":"pass","Test":"T"}`, `{"Action":"fail","Package":"P"}`, `{"Action":"build-fail","Package":"Q"}`, ""}, "\n")))
	if e != nil || c.Passed != 1 || c.Failed != 1 || c.BuildFailed != 1 {
		t.Fatal(c, e)
	}
}
