package main

import (
	"strings"
	"testing"
)

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
