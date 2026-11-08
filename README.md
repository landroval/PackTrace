# PackTrace

**Investigate JavaScript dependencies without running the project.**

[Español](README.es.md) · [Complete user manual](docs/user-guide.md) · [Manual en español](docs/user-guide.es.md)

PackTrace is a read-only, offline investigation CLI. It helps answer:

1. **Which dependency needs attention?** Package and observed version.
2. **Why?** A malicious-package advisory, vulnerability advisory, or installed-file difference.
3. **What supports that result?** Separate lockfile, installed-manifest, advisory and reference evidence.
4. **What should I verify next?** Applicability, missing evidence, or a correction boundary recorded by the advisory.

> **Experimental software, not a qualified release.** There are no published
> installation packages or production-qualified platform guarantees. macOS remains
> deferred. Zero findings never means that a project or machine is safe.

## Start here

Not sure which command you need? `packtrace --help` starts with **Scan a project
(offline)**, **Prepare security advisory data**, and **Understand a result**.
The advanced command list comes afterwards; no wizard or automatic preparation runs.

**Already configured?** This is the normal command:

```bash
packtrace scan /path/to/project
```

**First time?** Build the binary, prepare or obtain an intelligence store, and
register an external policy once. Follow the [first-run walkthrough](docs/user-guide.md#3-first-run-walkthrough).
`setup` is not an installer, policy wizard, or data downloader. Once those external
sources have been prepared and reviewed:

```bash
packtrace setup --policy /operator/config/policy.json --state-dir /operator/state/intelligence
packtrace scan /path/to/project
```

From an existing checkout **outside the project you intend to investigate**, using
an already-installed Go toolchain compatible with `go.mod` (currently Go 1.27.1):

```bash
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off go build -o ./packtrace ./cmd/packtrace
./packtrace --help
```

Move/install that binary into a directory on your `PATH` according to your OS.
Do not install it as a dependency of the investigated JavaScript project. Public
examples use Bash; the manual includes Nushell exit-status examples.

## Daily commands

| Task | Command |
| --- | --- |
| Readable scan | `packtrace scan .` |
| Full technical decisions | `packtrace scan --verbose .` |
| Structured local evidence, with saved local setup | `packtrace scan --format json .` |
| Portable JSON for review before sharing | `packtrace scan --privacy portable --format json .` |
| SARIF | `packtrace scan --format sarif .` |
| Scan options | `packtrace scan --help` |
| One-time setup options | `packtrace setup --help` |

Options go **before** the final project path. A scan never downloads advisory data,
installs dependencies, runs package scripts, or repairs the target.

## Understand the result

The CLI now explains concepts and missing evidence, not just technical states:
**Effect** describes what a limitation means; **Next** gives a scoped action.
Common errors keep their original diagnostic code on the first line. Suggested
commands do not run automatically; `DIR` in guidance is a placeholder for the same
reviewed external store, not a project path.

- **Finding:** evidence met the selected finding rules. It is not proof that code executed.
- **Candidate / `[REVIEW]`:** an identity/version match worth investigating;
  origin or applicability remains unconfirmed. It is **not** a confirmed vulnerability
  or an enforcement-eligible finding.
- **`[INCOMPLETE]`:** something needed for the check is missing or not established.
  It does not mean another package is malicious.
- **`[NOT RUN]`:** that optional check was not performed. It did not pass.
- **`[OK]`:** that specific check completed, not “the project is safe.”

The default shows grouped package tables and up to five attributed advisory
examples with **Advisory says**, **Why**, and **Next**. These examples are not a
severity ranking; `--verbose` and local JSON retain all captured details.
Unknown descriptions, severity, and fixes remain unknown. A recorded `fixed`
boundary is not a guarantee that upgrading to that version resolves every issue.

**Read project limitations separately from tool assurance.** Unreadable manifests
or expired intelligence limit investigation of the project. Platform qualification
and pending final-lifecycle evidence concern PackTrace itself. The default report
now separates **Project checks** from **PackTrace validation (tool assurance, not
project defects)**. Both remain part of required coverage and exit selection. Several incomplete
lines can describe the same missing evidence, not independent dependency failures.

A count such as “23 advisory records” is not severity 23, 23 incidents, or 23
confirmed vulnerabilities. See [reading a report](docs/user-guide.md#5-read-the-report-without-confusing-counts-with-risk).

## What is supported?

| Input | Current bounded interpretation |
| --- | --- |
| npm 10.x / 11.x | Stable versions, lockfile v2/v3; shrinkwrap precedence |
| npm 12.x | Stable versions, lockfile v3 only; shrinkwrap ignored, no fallback |
| Bun 1.3.x | Text `bun.lock` v0/v1; config absent/0/1 |
| Older explicit profiles | npm 8.19.4; Bun 1.4.2 |
| Workspaces | Explicit relative members and bounded one-level patterns; ambiguous ownership remains a gap |

This is format interpretation, **not** a guarantee for every producer, layout,
filesystem or platform. Binary Bun locks, npm lockfile v4, prerelease/unknown
producer hints, unsafe links and unsupported layouts remain explicit gaps.
The optional Linux Bun-cache profile admits only a verified **exactly two-name**
manifest hardlink pair; three or more names stay unreadable.

[Inventory evidence](docs/inventory-compatibility.md) · [Intelligence evidence](docs/intelligence-compatibility.md) · [Release gates](docs/pre-1.0-features.md)

## Privacy and exit codes

Without setup, output defaults to **portable** and no origin/candidate/reference
grants. An explicitly registered setup defaults to **local** detail unless chosen
otherwise; a policy can require portable output. Local output is not upload
permission. Review reports before sharing them.

| Exit | Meaning |
| --- | --- |
| `0` | Completed under the selected policy; not a safety verdict |
| `1` | An unaccepted finding met the enforcement policy |
| `2` | Arguments, policy, operation, report or output failed |
| `3` | Required coverage is incomplete; a useful partial report may exist |
| `130` | Interrupted |

Precedence: interruption → operation/output failure → incomplete coverage → enforced
finding → success. Report-only mode does **not** turn incomplete coverage into `0`.

## Experimental intelligence lifecycle

**Intel means the security advisory database, not AI:** locally stored reports of
malicious packages and vulnerabilities. `intel status` explains record counts,
source-check/reconciliation ages and unresolved evidence; these are not counts of
installed packages or confirmed vulnerabilities. Current dates alone are not complete coverage.

Scanning is offline. Preparing intelligence is a separate operator action:
`intel sync` is online; import/export, status, retention pins and prune operate on
local state. Neither `scan` nor `setup` initializes or refreshes it. Saved scan
settings do not apply to these maintenance commands: pass the same `--state-dir`
explicitly. See [data preparation and maintenance](docs/user-guide.md#4-prepare-and-maintain-intelligence).

## Local development

The root Go module uses only the standard library. With the required toolchain
already installed, run from this repository (not an investigated target):

```bash
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOENV=off GOTELEMETRY=off
export GOMAXPROCS=2
go test -p=1 -parallel=4 -count=1 -timeout=180s ./...
go vet ./...
```

Check each command's exit status. These environment settings are not a network
sandbox. Root tests use owned fixtures; separate `probes/` modules, producer
execution, live targets, downloads and native qualification are separate scopes.

## Contributing and technical documentation

- [English manual](docs/user-guide.md) / [Manual en español](docs/user-guide.es.md): first run, all commands, policies, reports and troubleshooting.
- [Design decisions](docs/design-decisions.md) and [development guidelines](docs/development-guidelines.md): engineering and security contracts.
- [GitHub collaboration](docs/github-collaboration.md): ownership, scoped `jj` changes and PR review.
- [Increment records](docs/increments/) and [shared ledger](.pi/README.md): historical evidence, not current execution permission.
- [Advisory data licenses and attribution](internal/intelstore/licenses/README.md): upstream data notices, not a blanket license for all advisory publishers.

No automatic remediation, target code execution, credential discovery, host safety
verdict, or production qualification is implied by a successful scan or merged PR.
