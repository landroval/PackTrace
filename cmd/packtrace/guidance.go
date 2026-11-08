package main

import "packtrace/internal/cli"

const mainGuidance = `PackTrace — investigate JavaScript dependencies without executing them

Scan a project (offline)
  Already configured: packtrace scan /path/to/project
  First setup: review an external policy and prepared data, then packtrace setup --help.
  More evidence: packtrace scan --verbose /path/to/project

Prepare security advisory data
  intel = security advisory database, not artificial intelligence.
  Read existing local state: packtrace intel status --state-dir DIR
  Preparation is separate: intel sync downloads public data and writes the store;
  intel import writes an offline bundle into the store. Neither runs during scan/setup.
  DIR is a placeholder for your reviewed external store; maintenance does not inherit saved scan settings.

Understand a result
  Findings met selected evidence rules, not proof of execution.
  Candidates are leads, not confirmed vulnerabilities; verify origin and applicability.
  Incomplete means needed evidence is missing, not another malicious package.
  Integrity means file comparison against a prepared reference, not a safety certificate.
  Project-analysis gaps and PackTrace validation are shown separately; both can affect exit 3.
  Help: packtrace scan --help | Full evidence: --format json

Advanced command reference
`

const scanGuidance = "Start here: scan reads project evidence without executing or repairing it.\n" + cli.AdvisoryDatabaseExplanation + `
Read Summary, Packages to review, project-analysis limits, then PackTrace validation.
Finding = selected evidence rules met; candidate = version lead, not confirmed applicability;
integrity difference = changed bytes, not automatically malware. Zero findings is not safety.
If something is missing, read Effect/Next guidance; no download, fix or approval is automatic.
Use --verbose for original technical evidence; JSON/SARIF semantics and exit codes are unchanged.

Options and technical boundaries
`
