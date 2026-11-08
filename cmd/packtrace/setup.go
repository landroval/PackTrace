package main

import (
	"context"
	"io"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/execution"
)

const setupHelp = `packtrace setup --policy FILE [--state-dir DIR] [--privacy local|portable]
Goal: save your reviewed scan rules and source locations for packtrace scan ROOT.
Policy = external JSON selecting required checks and finding enforcement, not a project script.
Register an explicitly selected external policy once for this OS user.
Policy bytes are designated by this command; their SHA-256 pin is stored internally.
Later scans verify the saved pin, never automatically approve changed policy bytes.
Default saved privacy: local (names/versions/IDs; not upload permission).
Default checks: the selected policy's required checks; enforcement remains policy-controlled.
Optional --trusted-snapshot-digest SRI fixes a generation; otherwise scan uses current local state.
No target scan, cache discovery, intelligence initialization, downloads or renewal.
Configuration is written exclusively to the OS user-config directory/packtrace/setup.json.
One active policy/manager profile; existing setup is never overwritten.
The policy stays at its original location so relative references retain their meaning.
scan ROOT reuses setup; explicit --privacy/--checks/--state-dir override defaults subject to policy.
An explicit --policy selects a standalone policy, without merging saved settings.
Saved setup initially supports stdout only (terminal/json/sarif); --output FILE is refused.
Without saved setup, scan retains no-grant built-in defaults and portable privacy.
Next: packtrace scan /path/to/project
`

func runSetup(request cli.SetupArgumentRequest, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := execution.RunSetup(ctx, request); err != nil {
		// The setup boundary returns fixed codes, never arbitrary I/O errors.
		code := "setup: configuration-unavailable; run packtrace setup --help"
		if err == execution.ErrSetupPolicy || err == execution.ErrSetupWrite || err == execution.ErrUserSetup {
			code = err.Error()
		}
		return failure(diagnostic, code)
	}
	if !writeOutput(out, []byte("User setup saved. No scan or download performed.\nRun: packtrace scan /path/to/project\n")) {
		return failure(diagnostic, "cli: output-failed")
	}
	return 0
}
