package integrityscan

import (
	"fmt"
	"strings"
)

// A green OK is earned only by an explicitly completed check. Absence of
// findings, available metadata and not-applicability are not completed checks.
func terminalCheckState(c Coverage) (string, string) {
	switch c.Outcome {
	case "completed":
		return "OK", "completed"
	case "not-applicable":
		return "NOT RUN", "not applicable"
	case "not-run":
		if !c.Required {
			return "NOT RUN", "not selected"
		}
		return "INCOMPLETE", "required but not run"
	default:
		return "INCOMPLETE", "not fully established"
	}
}

func terminalCheckName(name string) string {
	switch name {
	case "inventory":
		return "Inventory evidence"
	case "integrity":
		return "Installed-file integrity"
	case "malicious":
		return "Known malicious-package check"
	case "vulnerability":
		return "Vulnerability check"
	case "reference-authority":
		return "Reference authority"
	case "native-qualification":
		return "Platform qualification"
	case "resident-observation":
		return "Resource/final-lifecycle evidence"
	case "execution":
		return "Comparison work"
	case "intelligence-access":
		return "Local intelligence access"
	case "intelligence-freshness":
		return "Intelligence freshness"
	default:
		return terminalCell(strings.ReplaceAll(name, "-", " "), 72)
	}
}

func renderTerminalChecks(out *strings.Builder, r Report) {
	fmt.Fprintln(out, "\nCheck status")
	for _, tool := range []bool{false, true} {
		heading := false
		for _, check := range r.Coverage {
			isTool := check.Check == "native-qualification" || check.Check == "resident-observation" || check.Check == "execution"
			if isTool != tool {
				continue
			}
			if !heading {
				if tool {
					fmt.Fprintln(out, "PackTrace validation (tool assurance, not project defects)")
					fmt.Fprintln(out, "  Missing platform/resource evidence can keep required coverage incomplete; it does not prove a package failure or out-of-memory event.")
				} else {
					fmt.Fprintln(out, "Project checks (evidence used for this investigation)")
				}
				heading = true
			}
			state, detail := terminalCheckState(check)
			if check.Check == "execution" && state == "OK" {
				detail = "completed before final output/cleanup"
			}
			fmt.Fprintf(out, "  [%s] %s: %s\n", state, terminalCheckName(check.Check), detail)
		}
	}
}
