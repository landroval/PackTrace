package integrityscan

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTerminalSummaryPrivacyEvidenceAndVerbose(t *testing.T) {
	for _, privacy := range []string{"portable", "local"} {
		t.Run(privacy, func(t *testing.T) {
			plan, inv, info, a := candidateReportFixture(t, privacy)
			info.CheckAge = "expired"
			info.Gaps = append([]string{"source-check-expired"}, info.Gaps...)
			r := BuildReportWithPolicy(plan, nil, Summary{}, Resources{}, false, false, &inv, &info, &a, nil, false, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			before, err := Render(r, "json")
			if err != nil {
				t.Fatal(err)
			}
			sarifBefore, err := Render(r, "sarif")
			if err != nil {
				t.Fatal(err)
			}
			summary, err := Render(r, "terminal")
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{"[INCOMPLETE] Scan coverage", "eligible match rows: 0", "Candidate rows: 2 | Advisory records: 1", "advisory source check expired", "Required coverage: incomplete", "Comparison exit: 3", "--verbose"} {
				if !bytes.Contains(summary, []byte(text)) {
					t.Fatalf("missing %q: %s", text, summary)
				}
			}
			for _, noise := range []string{"Advisory observation=", "Inventory relation:", "original-sha256=", "Support version="} {
				if bytes.Contains(summary, []byte(noise)) {
					t.Fatalf("default still dumps %q", noise)
				}
			}
			verbose, err := Render(r, "terminal-verbose")
			if err != nil || bytes.Count(verbose, []byte("Advisory observation=")) != 2 || !bytes.Contains(verbose, []byte("First version problem:")) {
				t.Fatalf("full evidence lost: %v %s", err, verbose)
			}
			if privacy == "local" {
				if bytes.Count(bytes.Split(summary, []byte("Why these matches need review"))[0], []byte("left-pad")) != 1 || !bytes.Contains(summary, []byte("ADVISORY RECORDS")) {
					t.Fatal("package table did not group repeated original", string(summary))
				}
			} else {
				for _, view := range [][]byte{summary, verbose} {
					for _, secret := range []string{"left-pad", "MAL-2026-1", strings.Repeat("2", 64), "sha256-", "PRIVATE"} {
						if bytes.Contains(view, []byte(secret)) {
							t.Fatal("portable disclosure", secret)
						}
					}
				}
			}
			after, err := Render(r, "json")
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("terminal changed structured evidence")
			}
			sarifAfter, err := Render(r, "sarif")
			if err != nil || !bytes.Equal(sarifBefore, sarifAfter) {
				t.Fatal("terminal changed SARIF")
			}
			r.Policy = nil
			for _, format := range []string{"terminal", "terminal-verbose"} {
				if _, err := Render(r, format); err == nil {
					t.Fatal("new view bypassed frozen authority", format)
				}
			}
		})
	}
}

func TestTerminalGroupingIsDisplayOnlyAndDoesNotMergeOriginals(t *testing.T) {
	a := AdvisoryReport{Local: &LocalDetails{Observations: []LocalObservation{{Observation: 1, Name: "owned", Version: "1.0.0"}, {Observation: 2, Name: "owned", Version: "1.0.0"}}}, Decisions: []AdvisoryDecision{
		{Observation: 1, Advisory: 1, Candidate: true},
		{Observation: 2, Advisory: 1, Candidate: true},
		{Observation: 2, Advisory: 2, Candidate: true},
	}}
	groups := advisoryTerminalGroups(&a, map[uint32]string{1: "locked", 2: "installed"}, true)
	if len(groups) != 1 || len(groups[0].originals) != 2 || !groups[0].locked || !groups[0].installed || len(a.Decisions) != 3 {
		t.Fatal("display changed identity/original evidence", groups)
	}
	var out strings.Builder
	renderTerminalAdvisoryTable(&out, "Candidate version matches", groups)
	if !strings.Contains(out.String(), "lock + manifest") {
		t.Fatal("lost evidence classes")
	}
	// Missing identity cannot establish a common package, even with equal versions.
	a.Local.Observations[0].Name, a.Local.Observations[1].Name = "", ""
	if len(advisoryTerminalGroups(&a, nil, true)) != 2 {
		t.Fatal("unknown observations merged")
	}
}

func TestTerminalTableLimitAndEscaping(t *testing.T) {
	a := AdvisoryReport{Local: &LocalDetails{}}
	for i := 1; i <= maxTerminalGroups+3; i++ {
		a.Local.Observations = append(a.Local.Observations, LocalObservation{Observation: uint32(i), Name: fmt.Sprintf("package-%02d", i), Version: "1.0.0"})
		a.Decisions = append(a.Decisions, AdvisoryDecision{Observation: uint32(i), Advisory: i, Candidate: true})
	}
	groups := advisoryTerminalGroups(&a, nil, true)
	var out strings.Builder
	renderTerminalAdvisoryTable(&out, "Candidates", groups)
	if strings.Count(out.String(), "package-") != maxTerminalGroups || !strings.Contains(out.String(), "3 more groups") || len(a.Decisions) != maxTerminalGroups+3 {
		t.Fatal("silent truncation or lost evidence", out.String())
	}
	cell := terminalCell("untrusted\x1b[31m\n\t\u202e", 80)
	if strings.ContainsAny(cell, "\x1b\n\t\u202e") || !strings.Contains(cell, `\x1b`) {
		t.Fatal("unsafe terminal text", cell)
	}
	if got := terminalCell(strings.Repeat("a", 200), 32); len(got) != 32 || !strings.HasSuffix(got, "...") {
		t.Fatal("cell not bounded", got)
	}
}
