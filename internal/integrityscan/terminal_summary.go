package integrityscan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"packtrace/internal/integrity"
)

// ponytail: show at most 20 package groups per section; --verbose/JSON retain
// every observation and original. Display grouping never changes the report.
const maxTerminalGroups = 20

type terminalPackage struct {
	name, version string
	unknown       uint32 // Do not merge observations with missing identities.
}
type terminalAdvisoryGroup struct {
	pkg       terminalPackage
	originals map[int]bool
	locked    bool
	installed bool
}

func terminalCell(s string, width int) string {
	// ASCII quoting prevents control sequences, tabs and misleading Unicode from
	// changing the table. Shortened cells are display-only, never grouping keys.
	q := strconv.QuoteToASCII(s)
	q = q[1 : len(q)-1]
	if len(q) > width {
		return q[:width-3] + "..."
	}
	return q
}

func advisoryTerminalGroups(a *AdvisoryReport, classes map[uint32]string, candidates bool) []terminalAdvisoryGroup {
	observations, _ := localDetailMaps(a.Local)
	groups := map[terminalPackage]*terminalAdvisoryGroup{}
	for _, d := range a.Decisions {
		if candidates && !d.Candidate || !candidates && !d.EnforcementEligible {
			continue
		}
		o := observations[d.Observation]
		key := terminalPackage{name: o.Name, version: o.Version}
		if key.name == "" || key.version == "" {
			key.unknown = d.Observation
			if key.name == "" {
				key.name = fmt.Sprintf("observation #%d", d.Observation)
			}
			if key.version == "" {
				key.version = "unknown"
			}
		}
		g := groups[key]
		if g == nil {
			g = &terminalAdvisoryGroup{pkg: key, originals: map[int]bool{}}
			groups[key] = g
		}
		g.originals[d.Advisory] = true
		g.locked = g.locked || classes[d.Observation] == "locked"
		g.installed = g.installed || classes[d.Observation] == "installed"
	}
	result := make([]terminalAdvisoryGroup, 0, len(groups))
	for _, g := range groups {
		result = append(result, *g)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i].pkg, result[j].pkg
		if a.name != b.name {
			return a.name < b.name
		}
		if a.version != b.version {
			return a.version < b.version
		}
		return a.unknown < b.unknown
	})
	return result
}

func renderTerminalAdvisoryTable(out *strings.Builder, title string, groups []terminalAdvisoryGroup) {
	if len(groups) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%s (%d package/version groups)\n", title, len(groups))
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "PACKAGE\tVERSION\tADVISORY RECORDS\tEVIDENCE")
	for _, g := range groups[:min(len(groups), maxTerminalGroups)] {
		evidence := "unknown"
		if g.locked && g.installed {
			evidence = "lock + manifest"
		} else if g.locked {
			evidence = "lock only"
		} else if g.installed {
			evidence = "manifest only"
		}
		fmt.Fprintf(table, "%s\t%s\t%d\t%s\n", terminalCell(g.pkg.name, 32), terminalCell(g.pkg.version, 18), len(g.originals), evidence)
	}
	_ = table.Flush() // strings.Builder does not fail.
	if len(groups) > maxTerminalGroups {
		fmt.Fprintf(out, "... %d more groups; use --verbose or --format json.\n", len(groups)-maxTerminalGroups)
	}
}

// Called by Render only after frozen policy, advisory and privacy validation.
// This projection neither re-evaluates evidence nor authenticates saved JSON.
func renderTerminalSummary(r Report) []byte {
	var out strings.Builder
	status := "COMPLETE (not a safety verdict)"
	switch r.ExitCode {
	case 130:
		status = "INTERRUPTED"
	case 2:
		status = "ERROR"
	case 1:
		status = "FINDINGS (policy enforcement)"
	default:
		if RequiredCoverageIncomplete(r) {
			status = "INCOMPLETE"
		}
	}
	fmt.Fprintln(&out, "PackTrace | Offline dependency scan (experimental)")
	fmt.Fprintf(&out, "Status: %s\n", status)
	classes := map[uint32]string{}
	if p := r.Inventory; p != nil {
		usable := 0
		for _, o := range p.Observations {
			classes[o.ID] = o.Class
			if o.Class == "installed" && o.Status == "complete" {
				usable++
			}
		}
		fmt.Fprintf(&out, "Inventory: %d declared | %d locked | %d installed observations\n", p.Counts.Declared, p.Counts.Locked, p.Counts.Installed)
		inventoryCoverage := "incomplete"
		if p.Complete {
			inventoryCoverage = "complete"
		}
		fmt.Fprintf(&out, "Usable manifest observations: %d/%d | Inventory coverage: %s\n", usable, p.Counts.Installed, inventoryCoverage)
		conflicts := map[string]int{}
		for _, relation := range p.Relations {
			if relation.Status == "conflict" {
				conflicts[relation.Kind]++
			}
		}
		if len(conflicts) > 0 {
			terminalList(&out, "Inventory conflicts", terminalCounts(conflicts))
		}
	} else {
		fmt.Fprintln(&out, "Inventory: unavailable")
	}
	if i := r.Intelligence; i != nil {
		fmt.Fprintf(&out, "Intelligence: %s | source check: %s | reconciliation: %s\n", i.State, i.CheckAge, i.ReconciliationAge)
	}
	if a := r.Advisories; a != nil {
		fmt.Fprintf(&out, "Advisories: %s | eligible match rows: %d\n", a.State, a.Findings)
		originals := map[int]bool{}
		for _, d := range a.Decisions {
			if d.Candidate {
				originals[d.Advisory] = true
			}
		}
		fmt.Fprintf(&out, "Candidate rows: %d | Advisory records: %d (not confirmed findings)\n", a.Candidates, len(originals))
		if a.Findings > 0 || a.Candidates > 0 {
			if r.Privacy == "local" && a.Local != nil {
				renderTerminalAdvisoryTable(&out, "Advisory findings", advisoryTerminalGroups(a, classes, false))
				renderTerminalAdvisoryTable(&out, "Candidate version matches (origin unconfirmed)", advisoryTerminalGroups(a, classes, true))
			} else {
				fmt.Fprintln(&out, "Package identities hidden by portable privacy; use --privacy local for local review.")
			}
			fmt.Fprintln(&out, "Counts are not distinct incidents or a severity ranking; grouping is display-only.")
			if a.Candidates > 0 {
				fmt.Fprintln(&out, "Candidate only: origin unconfirmed, not enforcement-eligible.")
			}
			fmt.Fprintln(&out, "Manifest evidence does not authenticate installed contents or runtime use.")
		}
	} else {
		fmt.Fprintln(&out, "Advisories: not run (not selected)")
	}
	integrityNotRun := false
	for _, c := range r.Coverage {
		if c.Check == "integrity" && c.Outcome == "not-run" {
			integrityNotRun = true
		}
	}
	if integrityNotRun && r.Findings == 0 {
		fmt.Fprintln(&out, "\nIntegrity: not run (not selected)")
	} else {
		fmt.Fprintf(&out, "\nIntegrity: %d observed differences\n", r.Findings)
	}
	changes := map[string]int{}
	for _, d := range r.Comparison.Differences {
		if name := differenceName(d.Kind); name != "unknown" {
			changes[name]++
		}
	}
	if len(changes) > 0 {
		terminalList(&out, "Changes", terminalCounts(changes))
	}
	contexts := map[string]bool{}
	for _, c := range r.Comparison.Contexts {
		if c.Kind == integrity.ContextPatch {
			contexts["patch-context-claim"] = true
		}
		if c.Kind == integrity.ContextGenerated {
			contexts["generated-context-claim"] = true
		}
	}
	for _, name := range []string{"patch-context-claim", "generated-context-claim"} {
		if contexts[name] {
			fmt.Fprintf(&out, "  Context: %s (claim only; differences remain findings)\n", name)
		}
	}
	if p := r.Policy; p != nil {
		accepted := 0
		for _, f := range p.Findings {
			if f.Accepted {
				accepted++
			}
		}
		enforcement := "report-only"
		if p.FailOn != 0 {
			enforcement = "enabled"
		}
		fmt.Fprintf(&out, "Policy: enforcement %s | accepted findings: %d | enforced/unaccepted: %d\n", enforcement, accepted, p.EnforcedUnaccepted)
		if r.Findings > 0 {
			fmt.Fprintln(&out, "File-level differences, including accepted findings: --verbose or --format json.")
		}
		if p.MaterialLimited {
			fmt.Fprintln(&out, "Policy evidence limit reached; acceptance cannot waive coverage.")
		}
	}

	fmt.Fprintln(&out, "\nCoverage and limitations")
	integrityGaps := map[string]int{}
	for _, gap := range r.Comparison.Gaps {
		integrityGaps[string(gap.Code)]++
	}
	if len(integrityGaps) > 0 {
		terminalList(&out, "Integrity gaps", terminalCounts(integrityGaps))
	}
	if p := r.Inventory; p != nil {
		gaps := map[string]int{}
		for _, g := range p.Gaps {
			gaps[g.Code]++
		}
		codes := make([]string, 0, len(gaps))
		for code := range gaps {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		for _, code := range codes {
			label := strings.ReplaceAll(code, "-", " ")
			if code == "installed-manifest-unavailable" {
				label = "installed manifests unavailable"
			}
			fmt.Fprintf(&out, "  %s: %d gap records\n", terminalCell(label, 72), gaps[code])
		}
	}
	if a := r.Advisories; a != nil && len(a.Summary.Gaps) > 0 {
		terminalList(&out, "Matching limits", a.Summary.Gaps)
	}
	if i := r.Intelligence; i != nil && len(i.Gaps) > 0 {
		terminalList(&out, "Intelligence limits", i.Gaps)
		if i.State == "unavailable" {
			fmt.Fprintln(&out, "  Next: packtrace setup --help (select prepared local data; no automatic download).")
		}
	}
	if a := r.Advisories; a != nil && a.Local != nil && a.Local.Limited {
		fmt.Fprintln(&out, "  Local presentation limited; missing identities remain opaque.")
	}
	incomplete, notRun := []string{}, []string{}
	for _, c := range r.Coverage {
		if c.Required && c.Outcome != "completed" && c.Outcome != "not-applicable" {
			incomplete = append(incomplete, c.Check)
		}
		if c.Outcome == "not-run" && !c.Required {
			notRun = append(notRun, c.Check)
		}
	}
	if len(incomplete) > 0 {
		terminalList(&out, "Required checks incomplete", incomplete)
	}
	if len(notRun) > 0 {
		terminalList(&out, "Not run", notRun)
	}
	coverage := "complete"
	if RequiredCoverageIncomplete(r) {
		coverage = "incomplete"
	}
	fmt.Fprintf(&out, "\nRequired coverage: %s\nComparison exit: %d\n", coverage, r.ExitCode)
	fmt.Fprintln(&out, "Zero findings is not a clean bill of health. Output/final cleanup can still fail.")
	fmt.Fprintln(&out, "Details: --verbose | Full structured evidence: --format json")
	return []byte(out.String())
}

func terminalCounts(counts map[string]int) []string {
	result := make([]string, 0, len(counts))
	for label, n := range counts {
		result = append(result, fmt.Sprintf("%s (%d)", label, n))
	}
	sort.Strings(result)
	return result
}

func terminalList(out *strings.Builder, label string, values []string) {
	// Keep every limitation visible, wrapping rather than silently truncating it.
	prefix := "  " + label + ": "
	line := prefix
	for i, value := range values {
		part := terminalCell(strings.ReplaceAll(value, "-", " "), 72)
		if len(line)+len(part)+2 > 100 && line != prefix {
			fmt.Fprintln(out, line)
			line = "    "
		} else if i > 0 {
			line += "; "
		}
		line += part
	}
	fmt.Fprintln(out, line)
}
