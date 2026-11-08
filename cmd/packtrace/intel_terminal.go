package main

import (
	"fmt"
	"strings"

	"packtrace/internal/cli"
	"packtrace/internal/execution"
	"packtrace/internal/intel"
)

func intelAgeLabel(age intel.FreshnessState) string {
	switch age {
	case intel.FreshnessCurrent:
		return "current"
	case intel.FreshnessExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// RunIntel validated these closed result fields before rendering. Presentation
// adds no source reads, trust designation, state changes or new exit decision.
func renderIntelTerminal(result execution.IntelResult) []byte {
	var out strings.Builder
	fmt.Fprintln(&out, "Security advisory database (intel)")
	fmt.Fprintln(&out, "Local reports of malicious packages and vulnerabilities; not artificial intelligence.")
	fmt.Fprintf(&out, "Database operation: %s\n", result.Outcome)
	if result.Generation != "" {
		fmt.Fprintf(&out, "Snapshot: %s\n", result.Generation)
	}
	if o := result.Observation; o != nil {
		check, full := intelAgeLabel(o.Check), intelAgeLabel(o.FullReconciliation)
		fmt.Fprintf(&out, "Advisory records: %d (not installed packages or confirmed vulnerabilities)\n", o.Records)
		fmt.Fprintf(&out, "Source check: %s (24 hours) | Full reconciliation: %s (7 days)\n", check, full)
		fmt.Fprintf(&out, "Source designation: %s (not publisher authentication)\n", o.SourceAuthority)
		fmt.Fprintf(&out, "Unresolved evidence: identity %d | timestamps %d | changed/withdrawn records %d\n", o.IdentityGaps, o.TemporalGaps, o.DispositionGaps)
		if next := cli.AdvisoryDatabaseNext("available", check, full); next != "" {
			fmt.Fprintln(&out, next)
		} else {
			fmt.Fprintln(&out, "Effect: source dates are current, not a complete project investigation or a safety verdict.")
			if len(o.Gaps) > 0 {
				fmt.Fprintln(&out, "Next: inspect --format json for remaining source/record gaps; current dates do not resolve unsupported records. Status does not scan a project.")
			}
		}
	} else if result.Action == cli.ArgumentActionIntelStatus && result.Outcome == "unavailable" {
		fmt.Fprintln(&out, cli.AdvisoryDatabaseNext("unavailable", "unknown", "unknown"))
	}
	if result.Outcome != "complete" && !(result.Action == cli.ArgumentActionIntelStatus && result.Outcome == "unavailable") {
		fmt.Fprintln(&out, "Effect: the requested database operation did not complete.\nNext: preserve existing state and inspect --format json plus packtrace --help. Do not retry downloads, delete state or change trust pins automatically.")
	}
	if p := result.Preview; p != nil {
		fmt.Fprintf(&out, "Prune preview: %x\nCandidates: %d; bytes: %d; generations: %d\nHistorical reproducibility may be lost; no deletion performed. Applying a reviewed preview is a separate destructive operation.\n", p.Token, p.Candidates, p.Bytes, p.Generations)
	}
	if p := result.Prune; p != nil {
		fmt.Fprintf(&out, "Removed files: %d; bytes: %d; partial: %t\n", p.RemovedFiles, p.RemovedBytes, p.Partial)
	}
	if result.Action == cli.ArgumentActionIntelPin || result.Action == cli.ArgumentActionIntelUnpin {
		fmt.Fprintln(&out, "Retention only: this does not select a scan generation or renew advisory data.")
	}
	return []byte(out.String())
}
