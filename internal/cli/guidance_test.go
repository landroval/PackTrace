package cli

import (
	"strings"
	"testing"
)

func TestDatabaseGuidanceSeparatesPreparationAndIndependentGaps(t *testing.T) {
	for _, v := range []struct{ state, check, full, want, absent string }{
		{"unavailable", "unknown", "unknown", "does not mean no threats", "sync --full"},
		{"available", "expired", "current", "packtrace intel sync --state-dir DIR", "sync --full"},
		{"available", "current", "expired", "packtrace intel sync --full --state-dir DIR", ""},
		{"available", "unknown", "unknown", "copied markers", "sync --full"},
		{"PRIVATE", "PRIVATE", "PRIVATE", "not proven current", "PRIVATE"},
	} {
		text := AdvisoryDatabaseNext(v.state, v.check, v.full)
		if !strings.Contains(text, v.want) || v.absent != "" && strings.Contains(text, v.absent) || len(text) > 2048 || strings.Contains(text, "\x1b") {
			t.Fatal(v, text)
		}
	}
	if AdvisoryDatabaseNext("available", "current", "current") != "" {
		t.Fatal("current data got a spurious refresh requirement")
	}
	for _, full := range []string{"current", "expired"} {
		text := AdvisoryDatabaseNext("available", "expired", full)
		for _, s := range []string{"downloads data and writes", "not run automatically", "cannot fix unreadable manifests", "Keep existing snapshot pins"} {
			if !strings.Contains(text, s) {
				t.Fatal(s, text)
			}
		}
	}
}

func TestDiagnosticGuidanceKeepsCodesAndClosedRemedies(t *testing.T) {
	for _, code := range []string{"cli: missing-root", "cli: unsupported-command", "scan: invalid-policy", "scan: unsupported-or-conflicting-options", "scan: intelligence-binding-unavailable", "scan: user-setup-invalid; run packtrace setup --help", "scan: saved-setup requires stdout; use --format json without --output"} {
		text := DiagnosticText(code)
		if !strings.HasPrefix(text, code+"\n") || !strings.Contains(text, "Next:") || len(text) > 2048 {
			t.Fatal(code, text)
		}
	}
	for _, code := range []string{"cli: output-failed", "scan: unavailable", "inspect: invalid-input"} {
		if DiagnosticText(code) != code+"\n" {
			t.Fatal("invented remedy for unrelated code")
		}
	}
}
