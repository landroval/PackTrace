package integrityscan

import "strings"

// Style only fixed report labels, after escaping/alignment. Removing SGR bytes
// must recover exactly the validated plain view; color never encodes severity.
func colorTerminalSummary(data []byte, r Report) []byte {
	var out strings.Builder
	coverage := false
	for _, line := range strings.SplitAfter(string(data), "\n") {
		body := strings.TrimSuffix(line, "\n")
		style := ""
		if body == "Coverage limitations" {
			coverage = true
		}
		switch {
		case strings.HasPrefix(body, "PackTrace |"), body == "Summary", body == "Packages to review", body == "Coverage limitations", strings.HasPrefix(body, "PACKAGE "):
			style = "\x1b[1;36m"
		case strings.HasPrefix(body, "Status:"):
			style = "\x1b[1;36m" // Completion is not a green safety verdict.
			if r.ExitCode == 1 || r.ExitCode == 2 {
				style = "\x1b[1;31m"
			} else if r.ExitCode == 130 || RequiredCoverageIncomplete(r) {
				style = "\x1b[1;33m"
			}
		case strings.HasPrefix(body, "Advisory findings"), strings.HasPrefix(body, "Advisories:") && r.Advisories != nil && r.Advisories.Findings > 0, strings.HasPrefix(body, "Integrity:") && r.Findings > 0:
			style = "\x1b[1;31m"
		case strings.HasPrefix(body, "Candidate version matches"), coverage && strings.HasPrefix(body, "  "), strings.HasPrefix(body, "Required coverage: incomplete"), strings.HasPrefix(body, "Intelligence:") && r.Intelligence != nil && (r.Intelligence.State != "available" || r.Intelligence.CheckAge != "current" || r.Intelligence.ReconciliationAge != "current"):
			style = "\x1b[33m"
		}
		if style != "" {
			out.WriteString(style)
			out.WriteString(body)
			out.WriteString("\x1b[0m")
		} else {
			out.WriteString(body)
		}
		if strings.HasSuffix(line, "\n") {
			out.WriteByte('\n')
		}
	}
	return []byte(out.String())
}
