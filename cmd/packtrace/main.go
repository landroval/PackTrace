// Command packtrace exposes experimental metadata inspection, not a project scan.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"packtrace/internal/cli"
	"packtrace/internal/demo"
	"packtrace/internal/inspect"
)

func main() { os.Exit(runInput(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func runInput(args []string, in io.Reader, out, diagnostic io.Writer) int {
	if len(args) == 0 || args[0] != "inspect" {
		return run(args, out, diagnostic)
	}
	if len(args) == 2 && args[1] == "--help" {
		if !writeOutput(out, []byte("packtrace inspect [--format terminal|json] [--identity-profile explicit-only|npm-lock-v2-v3]\nDefault explicit-only; opt-in installation-name claims are hypotheses, not canonical proof.\nRead one bounded stdin JSON envelope containing lockfile and advisory objects.\nPortable-only experimental metadata inspection; no project access or complete applicability.\n")) {
			return failure(diagnostic, "cli: output-failed")
		}
		return 0
	}
	format, profile, ok := inspectArgs(args[1:])
	if !ok {
		return failure(diagnostic, "inspect: invalid-arguments")
	}
	result, err := inspect.ReadProfile(in, profile)
	if err != nil {
		return failure(diagnostic, err.Error())
	}
	data, err := inspect.Render(result, format)
	if err != nil {
		return failure(diagnostic, "inspect: report-failed")
	}
	if !writeOutput(out, data) {
		return failure(diagnostic, "cli: output-failed")
	}
	return result.ExitCode
}

func inspectArgs(args []string) (string, string, bool) {
	format, profile := "terminal", "explicit-only"
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		name, value, attached := strings.Cut(args[i], "=")
		if (name != "--format" && name != "--identity-profile") || seen[name] {
			return "", "", false
		}
		seen[name] = true
		if !attached {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return "", "", false
			}
			value = args[i]
		}
		if name == "--format" {
			format = value
		} else {
			profile = value
		}
	}
	return format, profile, (format == "terminal" || format == "json") && (profile == "explicit-only" || profile == "npm-lock-v2-v3")
}

func run(args []string, out, diagnostic io.Writer) int {
	if len(args) > 0 && args[0] == "demo" {
		scenario, format, ok := demoArgs(args[1:])
		if !ok {
			return failure(diagnostic, "demo: invalid-arguments")
		}
		result, err := demo.EvaluateScenario(scenario)
		if err != nil {
			return failure(diagnostic, err.Error())
		}
		data, err := render(result, format)
		if err != nil {
			return failure(diagnostic, "demo: report-failed")
		}
		if !writeOutput(out, data) {
			return failure(diagnostic, "cli: output-failed")
		}
		return result.ExitCode
	}
	invocation, err := cli.ParseArgs(args)
	if err != nil {
		return failure(diagnostic, err.Error())
	}
	var text string
	switch invocation.Action {
	case cli.ArgumentActionHelp:
		text = "PackTrace development — experimental metadata tools only\nUsage: packtrace inspect [--format terminal|json] (stdin JSON; portable only)\n       packtrace demo [--scenario NAME] [--format terminal|json]\nScenarios: candidate, no-version-match, unsupported, withdrawn, different-identity, malformed\nControls: --help, --version, scan --help\nActual scan execution is unavailable; demo never opens target projects.\n"
	case cli.ArgumentActionVersion:
		text = "packtrace development (experimental demo; not a qualified release)\n"
	case cli.ArgumentActionScanHelp:
		text = "packtrace scan: execution unavailable in this increment\nThe existing scan argument grammar is retained, but no target is opened.\nUse packtrace demo for the owned synthetic pipeline.\n"
	case cli.ArgumentActionScan:
		return failure(diagnostic, "cli: scan-unavailable")
	default:
		return failure(diagnostic, "cli: invalid-invocation")
	}
	if !writeOutput(out, []byte(text)) {
		return failure(diagnostic, "cli: output-failed")
	}
	return 0
}

// Experimental grammar stays separate from the unchanged production request parser.
func demoArgs(args []string) (string, string, bool) {
	scenario, format := "candidate", "terminal"
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		name, value, attached := strings.Cut(args[i], "=")
		if (name != "--scenario" && name != "--format") || seen[name] {
			return "", "", false
		}
		seen[name] = true
		if !attached {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return "", "", false
			}
			value = args[i]
		}
		if value == "" {
			return "", "", false
		}
		if name == "--scenario" {
			scenario = value
		} else {
			format = value
		}
	}
	return scenario, format, format == "terminal" || format == "json"
}

func render(result demo.Result, format string) ([]byte, error) {
	if format == "json" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(data, '\n'), nil
	}
	var text strings.Builder
	fmt.Fprintln(&text, "EXPERIMENTAL DEMO — owned synthetic data; not a target scan")
	fmt.Fprintf(&text, "Scenario: %q\nLocked entries: %d\n", result.Scenario, len(result.Inventory))
	for _, observation := range result.Inventory {
		fmt.Fprintf(&text, "  %q@%q [%s] at %q\n", observation.Name, observation.Version, observation.Observation, observation.Location)
	}
	fmt.Fprintf(&text, "Inputs: npm=%s advisory=%s\n", result.Inputs.LockSHA256, result.Inputs.AdvisorySHA256)
	for _, evaluation := range result.Evaluations {
		fmt.Fprintf(&text, "  package[%d] affected[%d]: identity=%s equal=%t version=%s fully_evaluated=%t withdrawal=%s\n", evaluation.PackageIndex, evaluation.AffectedIndex, evaluation.IdentityQualification, evaluation.IdentityEqual, evaluation.VersionOutcome, evaluation.VersionFullyEvaluated, evaluation.Withdrawal)
		for _, problem := range evaluation.Problems {
			fmt.Fprintf(&text, "    limitation: %s version[%d] range[%d] event[%d]\n", problem.Kind, problem.VersionIndex, problem.RangeIndex, problem.EventIndex)
		}
	}
	fmt.Fprintf(&text, "Candidates: %d (identity/version only; not enforcement eligible)\nConfirmed findings: %d\n", len(result.Candidates), len(result.Findings))
	for _, coverage := range result.Coverage {
		fmt.Fprintf(&text, "  %s: %s (%s)\n", coverage.Check, coverage.Outcome, coverage.Reason)
	}
	fmt.Fprintf(&text, "Required coverage: incomplete\nExit: %d\n", result.ExitCode)
	return []byte(text.String()), nil
}

func writeOutput(out io.Writer, data []byte) bool {
	n, err := out.Write(data)
	return err == nil && n == len(data)
}

func failure(diagnostic io.Writer, message string) int {
	fmt.Fprintln(diagnostic, message)
	return 2
}
