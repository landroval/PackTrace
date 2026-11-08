package integrityscan

import (
	"fmt"
	"strings"
)

// ponytail: five examples in the default view, all records in verbose/JSON.
// Examples are deterministic, not a severity or remediation-priority ranking.
const maxTerminalExplanations = 5

func renderTerminalExplanations(out *strings.Builder, r Report) {
	a := r.Advisories
	if r.Privacy != "local" || a == nil || a.Local == nil {
		return
	}
	observations, advisories := localDetailMaps(a.Local)
	type explanationKey struct {
		advisory, affected int
		name, version      string
		candidate          bool
		unknown            uint32
	}
	seen := map[explanationKey]bool{}
	shown, total := 0, 0
	for _, d := range a.Decisions {
		if !d.Candidate && !d.EnforcementEligible {
			continue
		}
		// Locked/installed copies of the same package/version/original/affected
		// are displayed once, but their original decisions are never merged.
		o := observations[d.Observation]
		key := explanationKey{advisory: d.Advisory, affected: d.Affected, name: o.Name, version: o.Version, candidate: d.Candidate}
		if o.Name == "" || o.Version == "" {
			key.unknown = d.Observation
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		total++
		if shown == maxTerminalExplanations {
			continue
		}
		if shown == 0 {
			fmt.Fprintln(out, "\nWhy these matches need review (examples; not severity-ranked)")
		}
		shown++
		original := advisories[d.Advisory]
		id := original.ID
		if id == "" {
			id = fmt.Sprintf("advisory record #%d", d.Advisory)
		}
		state := "FINDING"
		if d.Candidate {
			state = "REVIEW"
		}
		fmt.Fprintf(out, "[%s] %s@%s — %s\n", state, terminalCell(o.Name, 48), terminalCell(o.Version, 32), terminalCell(id, 80))
		if original.Summary != "" {
			fmt.Fprintf(out, "  Advisory says: %s\n", terminalCell(original.Summary, 160))
		} else {
			fmt.Fprintf(out, "  Advisory type: %s; no supported short description was recorded.\n", terminalCell(d.Category, 32))
		}
		reason, next := localMatchReason(d, o, original)
		fmt.Fprintf(out, "  Why: %s\n  Next: %s\n", reason, next)
		if original.ExplanationLimited {
			fmt.Fprintln(out, "  Explanation limited; omitted metadata does not establish a fix.")
		}
	}
	if total > shown {
		fmt.Fprintf(out, "... %d more package/advisory/affected examples; use --verbose or --format json.\n", total-shown)
	}
}
