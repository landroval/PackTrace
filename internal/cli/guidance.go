package cli

// Fixed presentation text only. Never interpolate paths, arguments, source data
// or a proposed new pin into diagnostics or suggested commands.
const AdvisoryDatabaseExplanation = "Security advisory database (intel): local reports of malicious packages and vulnerabilities; not artificial intelligence."

// Ages are validated evidence labels, not a second freshness evaluator. DIR is
// deliberately a placeholder: portable reports cannot expose a selected path,
// and maintenance commands do not inherit the state directory saved for scans.
func AdvisoryDatabaseNext(state, checkAge, fullAge string) string {
	if state == "unavailable" {
		return "Effect: advisory checks lack usable local data; this does not mean no threats.\nNext: inspect the reviewed store with packtrace intel status --state-dir DIR. DIR is a placeholder for that store, not the target.\nPreparation is separate: intel sync downloads public data and writes the store; offline import also writes it. Neither is run by scan/setup."
	}
	if checkAge == "expired" || fullAge == "expired" {
		command := "packtrace intel sync --state-dir DIR"
		if fullAge == "expired" || fullAge == "unknown" {
			command = "packtrace intel sync --full --state-dir DIR"
		}
		return "Effect: advisory data may omit recent reports or corrections.\nNext: after reviewing network/disk work, explicitly authorize " + command + ". DIR is a placeholder for the same reviewed store. This downloads data and writes the store; it is not run automatically.\nAn update cannot fix unreadable manifests, unknown origins or tool qualification. Keep existing snapshot pins; selecting a new generation needs separate review."
	}
	if checkAge != "current" || fullAge != "current" {
		return "Effect: advisory data age or source designation is unverified, not proven current.\nNext: review the original store and independently designated snapshot with packtrace intel status --state-dir DIR. DIR is a placeholder; copied markers or a newly computed pin do not establish trust."
	}
	return ""
}

// The first line remains the original diagnostic code. Unknown codes receive no
// guessed remedy. The observed scan writer separately enforces its allowlist.
func DiagnosticText(code string) string {
	help := ""
	switch code {
	case "cli: missing-command", "cli: unsupported-command":
		help = "Next: run packtrace --help to choose a task. Existing commands are unchanged; intel means the security advisory database."
	case "cli: missing-root", "cli: invalid-root", "cli: extra-argument":
		help = "Effect: a required path/identifier is missing or invalid, or an extra operand was supplied.\nNext: check the selected command in packtrace --help. For scans use packtrace scan --help: options precede one project path. Intel import needs FILE; pin/unpin need a generation ID."
	case "cli: unsupported-option", "cli: repeated-option", "cli: missing-option-value", "cli: invalid-option-value", "cli: enforcement-outside-checks":
		help = "Next: check packtrace --help and packtrace scan --help for accepted options; do not repeat flags or combine --verbose/--interactive with JSON/SARIF or each other. Policy requirements cannot be weakened by flags."
	case "scan: invalid-policy", "scan: unsupported-or-conflicting-options":
		help = "Effect: the selected policy, pin or requested options could not be admitted.\nNext: review the external policy, required checks and privacy with packtrace scan --help. Do not replace the saved pin to approve changed bytes silently."
	case "scan: user-setup-invalid; run packtrace setup --help":
		help = "Effect: saved configuration, its policy or the original root binding could not be verified.\nNext: preserve the files and review packtrace setup --help; setup does not overwrite existing registration. A separately reviewed explicit --policy bypasses saved defaults."
	case "scan: intelligence-binding-unavailable":
		help = "Effect: the security advisory store could not be admitted; absence of findings would not establish coverage.\nNext: check the reviewed path and supported persistent filesystem using packtrace intel status --state-dir DIR (DIR is a placeholder). Do not copy markers, delete state or initialize a replacement to bypass this refusal."
	case "scan: saved-setup requires stdout; use --format json without --output":
		help = "Next: omit --output and use --format json or --format sarif on stdout. Shell redirection is not guarded publication: it may truncate or follow links before scanning."
	case "setup: configuration unavailable or already exists; existing configuration was not replaced":
		help = "Effect: existing setup was preserved or the destination could not be admitted.\nNext: use packtrace setup --help; there is no overwrite/reset command. Keep the original registration and use a separately reviewed explicit --policy for another profile."
	case "setup: select a policy once with packtrace setup --policy FILE [--state-dir DIR]":
		help = "Next: review an external policy before running setup; see packtrace setup --help. Setup registers data, not a project script, and does not prepare the advisory database."
	case "intel: execution-unavailable":
		help = "Effect: the database operation could not produce a usable result.\nNext: preserve existing state and inspect the selected path, ownership and platform support. Do not delete state or retry a download automatically; command syntax is in packtrace --help."
	}
	if help == "" {
		return code + "\n"
	}
	return code + "\n" + help + "\n"
}
