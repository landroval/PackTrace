package integrityscan

import (
	"strings"
	"testing"
	"time"
)

func TestTerminalCheckStatesAreExplicitAndScoped(t *testing.T) {
	plan, inv, info, a := candidateReportFixture(t, "local")
	r := BuildReportWithPolicy(plan, nil, Summary{}, Resources{}, false, false, &inv, &info, &a, nil, false, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	data, err := Render(r, "terminal")
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"[INCOMPLETE] Scan coverage", "[REVIEW] Candidate version matches", "[OK] Comparison work", "[OK] Local intelligence access", "[NOT RUN] Installed-file integrity", "[INCOMPLETE] Platform qualification"} {
		if !strings.Contains(string(data), label) {
			t.Fatalf("missing %q: %s", label, data)
		}
	}
	text := string(data)
	project, tool := strings.Index(text, "Project checks ("), strings.Index(text, "PackTrace validation (")
	if project < 0 || tool < project || strings.Index(text, "Platform qualification") < tool || !strings.Contains(text, "not project defects") || !strings.Contains(text, "Meaning: candidate = identity/version lead") {
		t.Fatal("project limits and tool assurance are confusing", text)
	}
	if strings.Contains(string(data), "[OK] Advisory matching") || strings.Contains(string(data), "[FINDING]") {
		t.Fatal("unknown/candidate promoted to a finding or safe check")
	}
}

func TestTerminalCheckStatesNeverPromoteUnknownOrSkipped(t *testing.T) {
	for _, c := range []Coverage{
		{Outcome: "completed", Required: true}, {Outcome: "incomplete", Required: true},
		{Outcome: "not-run", Required: true}, {Outcome: "not-run"}, {Outcome: "not-applicable", Required: true}, {Outcome: "unknown", Required: true}, {Outcome: ""},
	} {
		state, _ := terminalCheckState(c)
		if (state == "OK") != (c.Outcome == "completed") {
			t.Fatal("green status not backed by explicit completion", c, state)
		}
		if c.Outcome == "not-run" && c.Required && state != "INCOMPLETE" {
			t.Fatal("required missing work was presented as optional")
		}
	}
}

func TestTerminalPaletteUsesStateLabels(t *testing.T) {
	for _, c := range []struct{ label, color string }{
		{"OK", "1;32"}, {"FINDING", "1;31"}, {"REVIEW", "1;35"},
		{"INCOMPLETE", "1;33"}, {"NOT RUN", "37"}, {"INFO", "36"}, {"ERROR", "1;31"},
	} {
		plain := []byte("  [" + c.label + "] Explicit state\n")
		styled := string(colorTerminalSummary(plain))
		if !strings.HasPrefix(styled, "\x1b["+c.color+"m") || !strings.Contains(styled, string(plain[:len(plain)-1])+"\x1b[0m\n") {
			t.Fatal("wrong/unreset state color", c.label, styled)
		}
	}
}
