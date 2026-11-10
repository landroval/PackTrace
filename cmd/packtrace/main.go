// Command packtrace exposes experimental metadata inspection, not a project scan.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"packtrace/internal/cli"
	"packtrace/internal/demo"
	"packtrace/internal/inspect"
)

func main() { os.Exit(runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func runInput(args []string, in io.Reader, out, diagnostic io.Writer) int {
	return runInputObserved(args, in, out, diagnostic, nil)
}
func runInputObserved(args []string, in io.Reader, out, diagnostic io.Writer, observed scanObserver) int {
	if len(args) > 0 && args[0] == "check-reference-digest" {
		return runReferenceDigest(args[1:], in, out, diagnostic)
	}
	if len(args) > 0 && args[0] == "inspect-bun" {
		return runBun(args[1:], in, out, diagnostic)
	}
	if len(args) > 0 && args[0] == "inspect-batch" {
		return runBatch(args[1:], in, out, diagnostic)
	}
	if len(args) > 0 && args[0] == "inspect-bun-batch" {
		return runBunBatch(args[1:], in, out, diagnostic)
	}
	if len(args) > 0 && args[0] == "compare-bun-root" {
		return runBunRoot(args[1:], in, out, diagnostic)
	}
	if len(args) > 0 && args[0] == "compare-npm-root" {
		return runNPMRoot(args[1:], in, out, diagnostic)
	}
	if len(args) == 0 || args[0] != "inspect" {
		return runObserved(args, out, diagnostic, observed)
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

func runBun(args []string, in io.Reader, out, diagnostic io.Writer) int {
	if len(args) == 1 && args[0] == "--help" {
		if !writeOutput(out, []byte("packtrace inspect-bun [--format terminal|json]\nRead one bounded stdin JSON envelope with lockfile_text (original text bun.lock) and advisory.\nOnly recognized npm tuples with concrete SemVer permit version evaluation.\nPortable tuple claims, not authenticated source, installed state or complete applicability.\n")) {
			return failure(diagnostic, "cli: output-failed")
		}
		return 0
	}
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		if name == "--identity-profile" {
			return failure(diagnostic, "inspect-bun: invalid-arguments")
		}
	}
	format, _, ok := inspectArgs(args)
	if !ok {
		return failure(diagnostic, "inspect-bun: invalid-arguments")
	}
	result, err := inspect.ReadBun(in)
	if err != nil {
		return failure(diagnostic, err.Error())
	}
	data, err := inspect.Render(result, format)
	if err != nil {
		return failure(diagnostic, "inspect-bun: report-failed")
	}
	if !writeOutput(out, data) {
		return failure(diagnostic, "cli: output-failed")
	}
	return result.ExitCode
}

func runBatch(args []string, in io.Reader, out, diagnostic io.Writer) int {
	return runBatchContext(context.Background(), args, in, out, diagnostic)
}

func runBunBatch(args []string, in io.Reader, out, diagnostic io.Writer) int {
	if len(args) == 1 && args[0] == "--help" {
		if !writeOutput(out, []byte("packtrace inspect-bun-batch [--format terminal|json]\nRead one stdin JSON envelope with lockfile_text (original text bun.lock) and advisories (1–16 supplied records).\nLimits: 1 MiB wire, 64 package tuples, 64 workspaces, 64 total affected slots, 4096 pairs.\nPortable tuple claims only; invalid advisory metadata leaves a gap. No target access.\n")) {
			return failure(diagnostic, "cli: output-failed")
		}
		return 0
	}
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		if name == "--identity-profile" {
			return failure(diagnostic, "inspect-bun-batch: invalid-arguments")
		}
	}
	format, _, ok := inspectArgs(args)
	if !ok {
		return failure(diagnostic, "inspect-bun-batch: invalid-arguments")
	}
	result, e := inspect.ReadBunBatch(in)
	if e != nil {
		return failure(diagnostic, e.Error())
	}
	data, e := inspect.RenderBatch(result, format)
	if e != nil {
		return failure(diagnostic, "inspect-bun-batch: report-failed")
	}
	if !writeOutput(out, data) {
		return failure(diagnostic, "cli: output-failed")
	}
	return result.ExitCode
}

func runBunRoot(args []string, in io.Reader, out, diagnostic io.Writer) int {
	if len(args) == 1 && args[0] == "--help" {
		if !writeOutput(out, []byte("packtrace compare-bun-root [--format terminal|json]\nRead one stdin JSON envelope with manifest (package.json object) and lockfile_text (original text bun.lock).\nLimit: 1 MiB wire; existing declaration/workspace bounds also apply.\nPortable textual counts only; not semantic equivalence, installed state or a target scan. Usable metadata exits 3.\n")) {
			return failure(diagnostic, "cli: output-failed")
		}
		return 0
	}
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		if name == "--identity-profile" {
			return failure(diagnostic, "compare-bun-root: invalid-arguments")
		}
	}
	format, _, ok := inspectArgs(args)
	if !ok {
		return failure(diagnostic, "compare-bun-root: invalid-arguments")
	}
	result, err := inspect.ReadBunRoot(in)
	if err != nil {
		return failure(diagnostic, err.Error())
	}
	data, err := inspect.RenderBunRoot(result, format)
	if err != nil {
		return failure(diagnostic, "compare-bun-root: report-failed")
	}
	if !writeOutput(out, data) {
		return failure(diagnostic, "cli: output-failed")
	}
	return result.ExitCode
}

func runNPMRoot(args []string, in io.Reader, out, diagnostic io.Writer) int {
	if len(args) == 1 && args[0] == "--help" {
		if !writeOutput(out, []byte("packtrace compare-npm-root [--format terminal|json]\nRead one stdin JSON envelope with manifest (package.json object) and lockfile (npm lockfile v2/v3 object).\nLimit: 1 MiB wire; existing declaration and lock projection bounds also apply.\nPortable textual counts only; not semantic equivalence, installed state or a target scan. Usable metadata exits 3.\n")) {
			return failure(diagnostic, "cli: output-failed")
		}
		return 0
	}
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		if name == "--identity-profile" {
			return failure(diagnostic, "compare-npm-root: invalid-arguments")
		}
	}
	format, _, ok := inspectArgs(args)
	if !ok {
		return failure(diagnostic, "compare-npm-root: invalid-arguments")
	}
	result, err := inspect.ReadNPMRoot(in)
	if err != nil {
		return failure(diagnostic, err.Error())
	}
	data, err := inspect.RenderNPMRoot(result, format)
	if err != nil {
		return failure(diagnostic, "compare-npm-root: report-failed")
	}
	if !writeOutput(out, data) {
		return failure(diagnostic, "cli: output-failed")
	}
	return result.ExitCode
}

func runReferenceDigest(args []string, in io.Reader, out, diagnostic io.Writer) int {
	if len(args) == 1 && args[0] == "--help" {
		if !writeOutput(out, []byte("packtrace check-reference-digest --integrity SRI [--max-bytes N] [--format terminal|json]\nRead raw supplied stdin bytes only; default limit 512 MiB. Single canonical SHA-256/384/512 SRI token only.\nDigest equality only; not reference assurance, archive validity, coverage or security. Usable reports exit 3.\n")) {
			return failure(diagnostic, "cli: output-failed")
		}
		return 0
	}
	integrityArg, format, maxBytes := "", "terminal", int64(512*1024*1024)
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		name, value, attached := strings.Cut(args[i], "=")
		if (name != "--integrity" && name != "--max-bytes" && name != "--format") || seen[name] {
			return failure(diagnostic, "check-reference-digest: invalid-arguments")
		}
		seen[name] = true
		if !attached {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return failure(diagnostic, "check-reference-digest: invalid-arguments")
			}
			value = args[i]
		}
		if value == "" {
			return failure(diagnostic, "check-reference-digest: invalid-arguments")
		}
		switch name {
		case "--integrity":
			integrityArg = value
		case "--format":
			format = value
		case "--max-bytes":
			for _, digit := range value {
				if digit < '0' || digit > '9' {
					return failure(diagnostic, "check-reference-digest: invalid-arguments")
				}
			}
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed > 512*1024*1024 {
				return failure(diagnostic, "check-reference-digest: invalid-arguments")
			}
			maxBytes = parsed
		}
	}
	if integrityArg == "" || (format != "terminal" && format != "json") {
		return failure(diagnostic, "check-reference-digest: invalid-arguments")
	}
	result, err := inspect.ReadReferenceDigest(context.Background(), integrityArg, in, maxBytes)
	if err != nil {
		return failure(diagnostic, "check-reference-digest: check-failed")
	}
	data, err := inspect.RenderReferenceDigest(result, format)
	if err != nil {
		return failure(diagnostic, "check-reference-digest: report-failed")
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
	return runObserved(args, out, diagnostic, nil)
}
func runObserved(args []string, out, diagnostic io.Writer, observed scanObserver) int {
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
	case cli.ArgumentActionSetup:
		return runSetup(invocation.Setup, out, diagnostic)
	case cli.ArgumentActionSetupHelp:
		text = setupHelp
	case cli.ArgumentActionIntelSync, cli.ArgumentActionIntelImport, cli.ArgumentActionIntelExport, cli.ArgumentActionIntelStatus, cli.ArgumentActionIntelPin, cli.ArgumentActionIntelUnpin, cli.ArgumentActionCachePrune:
		return runIntel(invocation.Intel, out, diagnostic)
	case cli.ArgumentActionHelp:
		text = mainGuidance + "PackTrace development — gated offline scanner and supplied metadata tools\nUsage: packtrace scan [options] ROOT (offline advisory and integrity investigation; scan --help)\n       packtrace setup --policy FILE [--state-dir DIR] (once per user; setup --help)\n       packtrace inspect [--format terminal|json] (stdin JSON; portable only)\n       packtrace inspect-batch [--format terminal|json] (bounded stdin advisory array)\n       packtrace inspect-bun [--format terminal|json] (supplied text bun.lock and advisory)\n       packtrace inspect-bun-batch [--format terminal|json] (supplied text bun.lock and advisory array)\n       packtrace compare-bun-root [--format terminal|json] (supplied root manifest and text bun.lock)\n       packtrace compare-npm-root [--format terminal|json] (supplied root manifest and npm lockfile)\n       packtrace check-reference-digest --integrity SRI [--max-bytes N] [--format terminal|json] (raw stdin bytes)\n       packtrace demo [--scenario NAME] [--format terminal|json]\nScenarios: candidate, no-version-match, unsupported, withdrawn, different-identity, malformed\nControls: --help, --version, scan --help\nActual scan is an offline gated candidate; demo never opens target projects.\nIntelligence preparation (explicit, never part of scan):\n  packtrace intel sync [--full] [--state-dir DIR] [--format terminal|json]\n  packtrace intel import [--state-dir DIR] [--trusted-snapshot-digest SHA256_SRI] [--format terminal|json] FILE\n  packtrace intel export [--state-dir DIR] --output FILE [--format terminal|json]\n  packtrace intel status [--state-dir DIR] [--format terminal|json]\n  packtrace intel pin [--state-dir DIR] GENERATION_SHA256_HEX\n  packtrace intel unpin [--state-dir DIR] GENERATION_SHA256_HEX\n  packtrace cache prune [--state-dir DIR] [--apply PREVIEW_SHA256_HEX] [--format terminal|json]\nPrune without --apply is preview only; apply needs its unchanged independently confirmed token.\nSource licenses, currentness and native qualification remain separate gates.\n"
	case cli.ArgumentActionVersion:
		text = "packtrace development (experimental demo; not a qualified release)\n"
	case cli.ArgumentActionScanHelp:
		text = scanGuidance + "packtrace scan [options] ROOT\nTerminal defaults to Summary, Packages to review and Coverage limitations, with semantic colors on a capable stdout terminal. NO_COLOR (including empty) or TERM=dumb disables color; pipes, files, JSON/SARIF and --verbose remain plain. Windows requires existing VT support; unsupported platforms stay plain. Explicit states: [OK] green for completed checks only, [FINDING]/[ERROR] red, [REVIEW] magenta, [INCOMPLETE] amber, [NOT RUN] gray, [INFO] cyan; headings blue. Green is not a safe-project verdict and red is not an inferred severity. --verbose shows all technical decisions/relations; JSON/SARIF keep full evidence unchanged.\nSaved user setup is reused automatically; configure once with packtrace setup --policy FILE [--state-dir DIR].\nOnly the OS user-config location is consulted, never project configuration. Saved privacy defaults to local; without setup it remains portable. Explicit --policy bypasses saved setup. Saved setup initially supports stdout only.\nOffline advisory and integrity candidate: [--policy EXTERNAL_POLICY] [--trusted-policy-digest SRI] [--checks malicious,vulnerability,integrity] [--fail-on none|CATEGORIES] [--state-dir DIR] [--trusted-snapshot-digest SHA256_SRI] [--privacy portable|local] [--format terminal|json|sarif] [--verbose] [--output FILE]\nAn explicit operator policy pin (single canonical SHA-256/384/512 SRI) is required for independently-anchored references; it is not publisher authentication.\nExplicit version-1 policy maps locked identities/SRI to local prepared archives; no network or target code execution.\nNative and physical authority qualification remain gated; required gaps exit 3. No shipping/platform qualification claim.\nChecks default to malicious,vulnerability,integrity with no finding enforcement; explicit static policy is optional and can require checks/enforcement. No policy discovery or executable configuration. --manager auto|npm|npm@VERSION|npm@7-11|npm@12.x|bun|bun@1.2-1.4|bun@1.2.x|bun@1.3.x|bun@1.4.x|bun@VERSION selects stable npm 7.x-12.x or bounded Bun 1.2.x-1.4.x interpretations. The legacy npm@10-11 profile remains available; existing pinned policies are not rewritten. With no packageManager hint, auto accepts a sole npm root lockfile or unique supported Bun text lock; conflicting managers/inputs remain gaps. Competing npm locks require an explicit npm selection. npm 7-11 validates v2/v3; npm 12 supports v3 only, ignores shrinkwrap and never falls back to it. Lockfile v4/patch/extension semantics remain unsupported with lock-version-unsupported. No producer version or advisory authority is inferred. Prereleases and unknown producer hints remain gaps. Privacy defaults to portable; explicit local is policy-controlled. Output defaults to stdout; --output FILE requires an existing directory physically disjoint from project/state/references, never overwrites and initially requires the Linux native mechanism. Ancestor/common-parent/unsupported output destinations are refused.\nAn existing physically separate state directory is pinned through rendering, output and confirmed reap.\nScan never initializes, downloads, repairs or renews intelligence; bounded locked npm advisory matching and explicit observed-installed correspondence use selected originals.\nOptional npmOrigins rules and npmRegistry require an operator policy pin; documented OSV source paths distinguish supported malicious/vulnerability profiles, never IDs alone.\nExplicit --privacy local shows permitted identities and relative paths; requirePortable policy can refuse it. Portable stays the default.\nUnknown categories, origins, corrections and unsupported installed correspondence remain explicitly incomplete. First version-condition blockers expose fixed codes and numeric source positions, not raw condition text.\nOptional bunCacheDirectory requires an independent policy pin and admits an explicitly selected disjoint read-only cache source. The initial Linux/stdout profile reads installed manifests only with a stable closed two-name hardlink pair; third aliases, replacement and mutation remain refused. No implicit cache discovery, credential/config reads or publisher authentication.\nOptional advisoryCandidates supports bounded npm and Bun package identities and requires an independent policy pin to investigate stable observed names/versions in the local index even with private/unknown origins; it never qualifies origin or produces enforcement-eligible findings. Without the option, unqualified origins trigger no identity lookup. Candidate counts are separate from findings; portable stays opaque.\nThe optional canonical single SHA256 snapshot pin designates descriptor bytes, not publisher authenticity.\nMissing/untrusted/expired source leaves visible gaps. Storage occupation is unknown in readonly scan.\nPinned policies may contain exact evidence-bound exceptions: default maximum 30 elapsed days, explicit UTC approval/expiry, no wildcard or coverage waiver. Accepted findings stay visible; candidates remain ineligible. Explicit weakening flags fail with 2.\nOperational schema 1.7 records effective policy and derives coverage/enforcement; real gaps still exit 3. Local review fingerprints are not approval or upload permission. Output/final lifecycle can fail after the comparison snapshot.\n"
	case cli.ArgumentActionScan:
		return runScanObserved(invocation.Scan, out, diagnostic, observed)
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
	fmt.Fprint(diagnostic, cli.DiagnosticText(message))
	return 2
}
