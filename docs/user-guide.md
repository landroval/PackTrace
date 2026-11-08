# PackTrace user manual

[Español](user-guide.es.md) · [Project home](../README.md)

This manual describes the current experimental binary, not a promise of a
production release. Commands and output labels are English. Shell examples use
Bash unless marked otherwise. Paths such as `/operator/config/policy.json` are
placeholders: choose your own private, externally located paths before running
commands. Examples are instructions for the operator, not automatic authorization
for downloads, deletion, target access or native qualification.

## Contents

1. [Purpose and boundaries](#1-purpose-and-boundaries)
2. [Build and prerequisites](#2-build-and-prerequisites)
3. [First-run walkthrough](#3-first-run-walkthrough)
4. [Prepare and maintain intelligence](#4-prepare-and-maintain-intelligence)
5. [Read the report](#5-read-the-report-without-confusing-counts-with-risk)
6. [Scan command reference](#6-scan-command-reference)
7. [Policies, references and exceptions](#7-policies-references-and-exceptions)
8. [Privacy and report files](#8-privacy-and-report-files)
9. [Exit codes and automation](#9-exit-codes-and-automation)
10. [Troubleshooting](#10-troubleshooting)
11. [Supplied-input tools](#11-supplied-input-tools)
12. [Limits and technical references](#12-limits-and-technical-references)

## 1. Purpose and boundaries

Start with `packtrace --help` if you do not know a command. It presents **Scan a
project (offline)**, **Prepare security advisory data**, and **Understand a result**
before the advanced tools. `packtrace scan --help` explains the result concepts
before technical options. Existing commands, flags and trust rules are unchanged;
there is no automatic wizard, network action or repair.

PackTrace investigates dependency evidence. It does not run the project, install
packages, execute lifecycle/build/test scripts, repair dependencies, quarantine
files, inspect target registry credentials, or certify that a machine is clean.
`scan` makes no network requests. Separate `intel sync` explicitly uses the network.

Three questions are different:

| Check | Question | Not established by a positive result |
| --- | --- | --- |
| `malicious` | Does supported advisory evidence identify a known malicious package/version? | That the payload executed |
| `vulnerability` | Does supported advisory evidence match the observed version? | That the vulnerable feature is reachable in this application |
| `integrity` | Do mapped installed files differ from a validated prepared reference? | That a difference is malware, or that equal bytes are benign |

The result keeps **declared** dependency intent, **locked** resolutions and
**observed installed** evidence separate. A lockfile entry does not prove installation;
an installed manifest does not authenticate the contents or publisher.

### Plain-language glossary

| Term | What it means here |
| --- | --- |
| `intel` / intelligence | The local security advisory database; not artificial intelligence |
| Advisory | A source's report about a malicious package or vulnerability; not proof of application impact |
| Snapshot / generation | One fixed version of prepared local advisory data |
| Origin | Where a dependency is recorded as coming from; a claim is not publisher authentication |
| Candidate | An identity/version lead with unconfirmed origin/applicability; not a confirmed vulnerability |
| Finding | Evidence met the selected rules; not proof that code executed |
| Coverage | Which required checks were established, and which remain incomplete |
| Policy / enforcement | External reviewed rules choosing required checks and which unaccepted findings fail the run |
| Reference / integrity | A prepared comparison baseline / comparing files against it; equal bytes are not a safety verdict |

Run as an ordinary user. Keep policy, intelligence, references and reports outside
the target. Physical containment/ownership checks can refuse paths even when their
spelling looks correct. Do not weaken those checks to obtain a green result.

## 2. Build and prerequisites

There is no published installer or qualified release binary. Use a reviewed
checkout and an already-installed toolchain compatible with `go.mod` (Go 1.27.1).
The root application uses only the Go standard library; npm and Bun are **not**
needed to run a scan and must not be run against a suspicious target for preparation.

From the PackTrace checkout, not the target project:

```bash
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off go build -o ./packtrace ./cmd/packtrace
./packtrace --help
./packtrace --version
```

Install the built binary on your `PATH` using your OS's normal procedure. The
remaining examples assume the command is `packtrace`. On Windows a local binary
may need `.\packtrace.exe` depending on your shell;
the examples below use Unix paths. Cross-compilation does not establish native
support. Linux/Windows safeguards have bounded evidence; macOS qualification is deferred.

You also need **prepared intelligence** for advisory checks. A fresh build does
not include a live advisory corpus. Integrity comparison separately needs reviewed
reference mappings and prepared archives; it is not enabled merely by having a lockfile.

## 3. First-run walkthrough

### A. Select prepared local intelligence

If an operator already prepared a store, check that exact store without changing it:

```bash
packtrace intel status --state-dir /operator/state/intelligence
```

If none exists, choose [explicit online preparation or offline import](#4-prepare-and-maintain-intelligence).
Do not create an arbitrary directory and expect `scan` to adopt or repair it.
State must be on a supported persistent filesystem, outside the investigated project.

### B. Create and review an external policy

Save the following JSON as `/operator/config/policy.json`, in a private directory
outside the project. This is a **report-only candidate-investigation example** for
Bun 1.3.x. It explicitly allows local identity/version lookups with unknown origins;
it does not authenticate origins or grant network access.

```json
{
  "version": 1,
  "designation": "user-designated",
  "reason": "Investigate recorded dependency identities and versions offline",
  "provenance": "Operator-reviewed external report-only policy",
  "manager": "bun@1.3.x",
  "requiredChecks": ["malicious", "vulnerability"],
  "failOn": [],
  "requireHardMemoryLimit": false,
  "minimumAssurance": "lockfile-consistent",
  "references": [],
  "advisoryCandidates": true
}
```

For npm, use `"manager": "npm@10-11"` or `"npm@12.x"` as appropriate. Select the
actual supported interpretation; do not misdeclare the manager to bypass a refusal.
This example intentionally omits integrity references and public-origin grants.
Do not use it to claim a complete integrity assessment or confirmed vulnerabilities.

For Linux Bun installations whose manifests are hardlinked into a known cache,
you may explicitly add `"bunCacheDirectory": "/absolute/operator-selected/bun-cache"`
to that JSON before review and setup. The root must be physically disjoint from
the target and other required source roots. This optional profile reads manifests
only through a verified, unchanged pair of exactly two names/links. It does not
trust cache contents as publisher evidence. More than two links remain refused;
no automatic cache discovery or blanket cache authorization occurs.

### C. Register it once

```bash
packtrace setup --policy /operator/config/policy.json --state-dir /operator/state/intelligence
```

`setup` reviews the policy's shape, captures a SHA-256 pin for the explicitly
selected bytes and writes per-user configuration. It does **not** scan a target,
create a store, download, refresh or prune intelligence.

To save portable output instead of the default local detail:

```bash
packtrace setup --policy /operator/config/policy.json --state-dir /operator/state/intelligence --privacy portable
```

Choose one setup command, not both: existing setup is never overwritten.
The saved check selection comes from the policy's `requiredChecks`. Enforcement
remains controlled by policy. Optional `--trusted-snapshot-digest SHA256_SRI` fixes
one independently designated generation; without it scans use the current existing
local generation. A pin is not publisher authentication.

Configuration is stored at `os.UserConfigDir()/packtrace/setup.json`: normally
`$XDG_CONFIG_HOME/packtrace/setup.json` or `~/.config/packtrace/setup.json` on Linux,
`%AppData%\packtrace\setup.json` on Windows, and the corresponding OS location
elsewhere (location is not a platform-support claim). Its private owner/root
binding is checked. Never copy `setup.json` between roots/machines as a setup method.
The original policy stays in place; relative reference paths retain that directory.

### D. Use the short command

```bash
packtrace scan /path/to/project
packtrace scan --verbose /path/to/project
packtrace scan --format json /path/to/project
```

Choose the package/workspace root that contains the relevant manifest and lockfile.
No package-manager install is required or performed. Exit `3` can accompany useful
partial evidence; read the coverage explanation before assuming failure or safety.

### E. Changing settings later

There is currently one saved policy/manager, no profile wizard, overwrite, reset or
uninstall subcommand. Editing the pinned policy makes ordinary scans fail rather
than silently approving the new bytes. Do not delete evidence or edit the saved pin
just to clear the error.

For a separately reviewed policy use a one-off explicit selection:

```bash
packtrace scan --policy /operator/config/another-policy.json --trusted-policy-digest "$POLICY_SRI" --state-dir /operator/state/intelligence --privacy local /path/to/project
```

Here `POLICY_SRI` must be the canonical SRI of the independently reviewed policy.
An explicit `--policy` bypasses, rather than merges, saved settings, including their
state/privacy/snapshot defaults. A newly computed hash of unreviewed bytes is not approval.
Ordinary `--privacy`, `--checks` and `--state-dir` override saved defaults only where
the effective policy permits. Policies cannot be weakened by flags.

## 4. Prepare and maintain intelligence

**Only `intel sync` goes online.** These commands do not use the state directory
saved by `setup`; supply the same `--state-dir` explicitly. Otherwise their default
is `os.UserCacheDir()/packtrace` (normally `~/.cache/packtrace` on Linux).
All paths must satisfy ownership, persistence and separation checks.

### What status tells you

`packtrace intel status --state-dir DIR` reads the selected store; replace `DIR`
with your reviewed store path, not the project root. Terminal output calls it
**Security advisory database (intel)** and explains the record count, independent
24-hour source check and seven-day full reconciliation, source designation and
unresolved evidence. Advisory records are not installed packages or confirmed
vulnerabilities. Current dates do not resolve unknown identities or establish
complete investigation coverage.

If data is unavailable, the output explains that advisory checks lack usable local
data, **not** that no threats exist. If dates are expired it shows an explicit sync
suggestion and its network/disk effects. Expired full reconciliation needs `--full`;
an unknown source designation instead needs review, not a guessed trust pin.
Suggestions never execute automatically. Updates cannot fix unreadable manifests,
unknown dependency origins or PackTrace qualification gaps. Existing scan snapshot
pins stay in force until a separately reviewed generation selection.

### Online preparation — explicit network and disk work

If you authorize acquiring public OSV npm intelligence:

```bash
packtrace intel sync --full --state-dir /operator/state/intelligence
```

For a later incremental synchronization:

```bash
packtrace intel sync --state-dir /operator/state/intelligence
```

These are substantial operations, not a lightweight package query. The profile
bounds an operation to 900 seconds, total managed logical storage/reservations to
32 GiB, per-operation staging reservation to 16 GiB, and sync responses to 2 GiB.
These ceilings are **not** required free-space estimates, physical usage guarantees
or automatic retries. Review storage, licensing and network authorization first.
No target names/package list are submitted; sync prepares the admitted public feed.
Unknown required publishers or invalid data can block preparation. Failure does not
authorize a retry or silently discard the previous known-good generation.

Source-check age is 24 hours and independent full-reconciliation age is seven days;
the boundary itself is current, later is expired. Incremental checks do not renew
the independent full age. Importing or pinning data does not make it fresh.

### Offline transfer

With a prepared source store and a **new**, outside-store output destination:

```bash
packtrace intel export --state-dir /operator/state/intelligence --output /operator/transfer/snapshot.bundle
```

At the receiving store, using a descriptor digest obtained independently:

```bash
packtrace intel import --state-dir /operator/state/imported --trusted-snapshot-digest "$SNAPSHOT_SRI" /operator/transfer/snapshot.bundle
packtrace intel status --state-dir /operator/state/imported --format json
```

`SNAPSHOT_SRI` is one canonical SHA-256 SRI of the snapshot descriptor, **not** the
bundle file's checksum. The bundle does not designate its own trust. Import can
initialize a fresh owned store; it rebuilds projections from original records but
does not inherit another installation's local acquisition seal or renew source ages.
Existing unmarked directories are not adopted. Export does not overwrite files.

### Retention and deletion

`GENERATION_HEX` below is the exact nonzero, lowercase 64-character generation ID,
not an SRI. Retention pins prevent eligible data being pruned; they do not pin the
scan selection or change freshness.

```bash
packtrace intel pin --state-dir /operator/state/intelligence "$GENERATION_HEX"
packtrace intel unpin --state-dir /operator/state/intelligence "$GENERATION_HEX"
packtrace cache prune --state-dir /operator/state/intelligence --format json
```

The last command is **preview only**. The following is a separate destructive
operation: review the exact preview, approve deletion and supply its unchanged digest.
Do not run it merely because this example exists.

```bash
packtrace cache prune --state-dir /operator/state/intelligence --apply "$PREVIEW_HEX" --format json
```

Apply revalidates current readers, pins, ownership and protected generations. A
stale/copied preview is not deletion authority. Uncertain operations preserve and
charge data; manual broad deletion is not the recovery procedure.

## 5. Read the report without confusing counts with risk

### Read in this order

1. **Summary:** what inventory and checks were actually available?
2. **Packages to review:** which names/versions have findings or candidates?
3. **Why these matches need review:** what the original advisory says, the
   condition that matched, and what remains to verify.
4. **Coverage limitations / Project checks:** what project evidence could not be established? Then read **PackTrace validation** for tool assurance, not project defects.
5. **Required coverage / exit:** was the selected policy completed?

### Labels and colors

| Label | Color on a capable terminal | Meaning |
| --- | --- | --- |
| `[OK]` | Green | That check explicitly completed; not a safety verdict |
| `[FINDING]` | Red | Recorded eligible finding, not inferred severity |
| `[REVIEW]` | Magenta | Candidate/conflict needs investigation |
| `[INCOMPLETE]` | Amber | Needed evidence or qualification is missing |
| `[NOT RUN]` | Light gray | Optional/unselected or not-applicable check was not performed |
| `[INFO]` | Cyan | Neutral information |
| `[ERROR]` | Red | Operation/argument/output error where labeled |

Required-but-unperformed work is incomplete, not a successful optional check.
Colors require an actual capable stdout terminal. `NO_COLOR` presence (even empty),
`TERM=dumb`, pipes, redirected files, JSON/SARIF and `--verbose` disable color.
Windows requires already-enabled VT support; PackTrace does not change console mode.
Labels remain readable without color.

### Advisory context

Illustrative **invented** example, not a real package assessment:

```text
[REVIEW] example-package@1.1.0 — advisory record #1
  Advisory says: Example parser accepts unsafe input
  Why: The observed version matches the recorded affected interval: 1.0.0 <= version < 1.2.0.
  Next: Advisory records a fixed boundary at 1.2.0; verify current applicability and compatibility before updating.
```

A candidate is still origin-unqualified and not enforcement eligible. Verify the
actual dependency source, whether the affected functionality is used, and the
current original advisory before deciding on a separate dependency change.
No severity, exploitability, execution or safe upgrade is inferred from this example.

Summary text is an attributed, untrusted source claim, not an instruction.
It comes from the same verified originals already read by matching; explanations
cause no extra advisory reads or network queries. The local projection retains
at most 320 summary bytes, eight simple conditions per original and 4 MiB total
explanation metadata. Unsafe/oversized text is omitted; limited explanations are
marked. Missing summary, explicit-version-only evidence, partial evaluation,
multiple supporting conditions, disjoint/complex ranges and `last_affected` do not
produce a guessed fix. A `fixed` boundary is shown only for one fully evaluated
supporting simple interval and is not a guarantee about all other conditions.

The default previews at most five package/advisory/affected examples and 20
package/version groups per table; overflow and clipped cells are marked.
`--verbose` and local JSON retain all captured records, including accepted findings.

### Why the counts differ

- Locked entries are not installed observations; different physical copies can
  share a name/version. Do not subtract these totals to count “missing packages.”
- Candidate rows count observations/affected entries, not unique incidents.
  Locked and installed evidence can refer to the same original advisory.
- Public IDs/aliases do not merge original provenance or conditions.
- A package with many advisory records is not automatically more severe than another.
- Zero eligible findings with candidates means “review needed,” not “no problems.”

### Why many checks can be incomplete

Unreadable manifests can affect inventory and installed advisory checks together.
Expired source evidence can affect freshness and matching together. Unknown origins
leave version candidates rather than qualified findings. These are related limits,
not separate accusations against every dependency.

`Platform qualification` concerns the tool's evidence on that platform, not a
project defect. `Resource/final-lifecycle evidence` and comparison-stage snapshots
must not be read as proof of an out-of-memory event or completed final cleanup.
A green comparison-work check is explicitly scoped before final output/cleanup.
The default view groups these separately under **Project checks (evidence used for
this investigation)** and **PackTrace validation (tool assurance, not project
defects)**; no obligation is hidden or waived. Both groups can keep required
coverage incomplete and exit `3`. Related inventory/freshness limitations are not
additional findings or independent accusations against packages.
Refreshing intelligence cannot fix unsupported hardlinks, unknown origins,
unselected integrity checks or product qualification gaps.

## 6. Scan command reference

```text
packtrace scan [options] ROOT
```

`ROOT` is exactly one project path. Put all options before it; `--` ends option
parsing if the path starts with a dash. Repeated flags and unknown options fail.
`--help` must be used on its own as `packtrace scan --help`.

| Option | Values / behavior |
| --- | --- |
| `--manager` | `auto`, `npm`, `npm@10-11`, `npm@12.x`, `npm@VERSION`, `bun`, `bun@1.3.x`, `bun@VERSION`; only admitted stable profiles |
| `--checks` | Nonempty comma-separated subset of `malicious,vulnerability,integrity`; no spaces or repeats |
| `--fail-on` | `none` or selected categories; cannot weaken required policy enforcement |
| `--policy` | Explicit external version-1 JSON policy; bypasses saved setup |
| `--trusted-policy-digest` | One canonical SHA-256/384/512 SRI of reviewed policy bytes |
| `--state-dir` | Existing prepared external intelligence store; no initialization |
| `--trusted-snapshot-digest` | One canonical SHA-256 SRI of independently designated snapshot descriptor |
| `--privacy` | `portable` or policy-permitted `local` |
| `--format` | `terminal` (default), `json`, `sarif` |
| `--verbose` | Terminal only; no value; incompatible with JSON/SARIF |
| `--output` | New file in admitted existing outside directory; restrictions below |

Without saved setup or explicit policy: all three checks are selected, enforcement
is report-only, privacy is portable, and there are no reference/origin/candidate
lookup grants. This can inventory supported inputs but should not be mistaken for
a fully configured advisory/integrity investigation.

Manager selection interprets formats, never authenticates a producer or origin.
`auto` accepts an unambiguous supported root without requiring a producer hint.
Competing npm lockfiles without a hint need explicit npm selection; mixed npm/Bun
or unsupported hints stay gaps. npm 10/11 use shrinkwrap precedence and v2/v3;
npm 12 ignores shrinkwrap, never falls back to it, and admits v3 only. Bun 1.3.x
admits text lock v0/v1 with config absent/0/1. Binary locks, npm v4, unsupported
extensions/prereleases and unsafe/ambiguous ownership remain incomplete.

## 7. Policies, references and exceptions

Policies are data, not executable project configuration. No `.npmrc`, project
policy or credential discovery occurs. Parsing is strict: canonical field names,
no unknown/duplicate keys, no null grants, maximum 256 KiB.

| Fields | Meaning |
| --- | --- |
| `version`, `designation` | `1` and `user-designated` |
| `reason`, `provenance` | Nonempty operator rationale; statements are not proof of independence |
| `manager` | Supported concrete/range profile, not bare `auto`/`npm`/`bun` |
| `requiredChecks`, `failOn` | Required coverage and enforced categories; arrays, `failOn` may be empty |
| `requireHardMemoryLimit` | Currently must be `false`; no unsupported hard-RSS guarantee |
| `minimumAssurance` | `lockfile-consistent` or `independently-anchored` |
| `references` | Required array, empty when no prepared references are selected |
| `advisoryCandidates` | Optional explicit ambiguous-origin local lookup; not origin qualification |
| `bunCacheDirectory` | Optional explicit absolute Bun-cache root; Linux closed-pair profile only |
| `npmOrigins` | Up to 64 exact npm location/name/version/origin correspondences; not blanket authenticity |
| `npmRegistry` | Optional reviewed public npm registry grant; not a network grant or proof of installed bytes |
| `requirePortable` | Refuses local output when true |
| `exceptions`, `maxExceptionDays` | Exact reviewed acceptance, never a coverage waiver |

An independent policy pin is required for candidates, Bun cache, npm origin/registry
grants, exceptions and independently anchored references. `setup` records that
explicit designation once. A one-off scan must supply its reviewed pin separately.
Do not mark private/unknown packages public merely to obtain eligible findings.
Bun candidate investigation does not establish public npm origin.

### Integrity references

Integrity needs an explicit mapping for each admitted installed scope and a
prepared archive. Each reference object has `location`, `lockKey`, `name`,
`version`, `origin`, `classification` (`public|private|unknown`), `expectedSRI`,
`archive` and `context` (`none|patch|generated`). Scope/archive paths are bounded
relative selectors; archive paths resolve from the policy directory.

A lockfile SRI normally hashes a published **archive**, not the installed directory.
An arbitrary cache/archive is not automatically an authenticated reference.
`lockfile-consistent` and `independently-anchored` are different assurance levels;
merely placing files elsewhere or hashing them does not establish the latter.
Patch/build context never executes a transformation or erases observed drift.
PackTrace provides no general artifact-download command; prepare trusted references
separately. See the [integrity/policy contract](increments/issue-8-trusted-policy-and-exceptions.md).

### Reviewed exceptions

An exception has `id`, `reason`, `owner`, UTC `approvedAt`/`expiresAt`, exact `scope`
and an evidence-bound `acceptance` fingerprint. Scope includes `project`, `category`,
`rule`, `class`, `package`, `version`, `origin`, `instance`, `path`, `advisory` and
`change`; fields are exact, not wildcards. Use reviewed evidence, not invented
fingerprints or package-name-only exclusions.

There are at most 64 exceptions. The default maximum duration is 30 elapsed UTC
days; an explicitly pinned override is at most 365. Future, expired, mismatched or
changed evidence accepts nothing. Accepted findings remain visible; candidates
cannot become accepted alerts, and no exception completes a missing check.

## 8. Privacy and report files

**Portable** hides identities, absolute host paths, credentials, source keys/MACs
and authority pins. It retains opaque evidence references, counts, states and gaps.
**Local** permits bounded names/versions, public advisory IDs, original hashes,
relative locations, fingerprints and advisory explanations. It is still not raw
source/advisory export or upload permission. A policy can require portable output.

```bash
packtrace scan --privacy portable --format json /path/to/project
packtrace scan --format sarif /path/to/project
```

JSON operational schema is **1.7**, with optional bounded local explanation fields.
Historical report 1.0–1.6 support and supplied-input schemas are separate. All views
use the same validated result, not separate detectors. SARIF does not promote
unqualified candidates to vulnerability alerts. A saved JSON report cannot recreate
PackTrace's private authority context for authoritative rerendering.

Saved setup and the optional Bun-cache profile currently support **stdout only**:
`--output FILE` is refused. Explicit standalone-policy file publication requires
an existing directory physically disjoint from target, store and references,
a new filename, and the admitted Linux native publication mechanism. It never
creates missing directories or overwrites a report; ancestor/common-parent or
unsupported destinations are refused.

Shell `>` redirection is **not** PackTrace's guarded publication. The shell opens
or truncates the destination before scanning and can write into the target or
follow a link. Use it only after independently reviewing an outside destination,
with appropriate no-clobber handling, and check the process's final exit status.
Do not publish private reports in GitHub issues or PRs without explicit approval.

## 9. Exit codes and automation

| Code | Meaning |
| --- | --- |
| `0` | Completed under selected policy, not safety |
| `1` | Enforced, unaccepted finding |
| `2` | Argument/policy/operation/report/output failure |
| `3` | Required coverage incomplete, possibly useful partial evidence |
| `130` | Interruption |

Priority is `130` → `2` → `3` → `1` → `0`. A report's comparison exit can precede
later output/cleanup failure: use the final process status. Report-only affects
finding enforcement, not incomplete coverage or operational errors.

Bash, capturing the status immediately:

```bash
packtrace scan --format json /path/to/project
status=$?
printf 'PackTrace exit: %s\n' "$status"
```

Nushell:

```nu
packtrace scan --format json /path/to/project
let status = $env.LAST_EXIT_CODE
print $status
```

For CI, decide explicitly whether a partial report should block your job. Do not
hide failures with unconditional `|| true`, use `--fail-on none` to waive coverage,
or interpret absence of SARIF alerts as a completed investigation. A reviewed
policy can require `failOn` categories; command-line flags cannot weaken them.
There is no guarantee this experimental binary will produce exit `0` on a real
project while qualification/coverage gates remain incomplete.

## 10. Troubleshooting

Frequent errors keep their fixed diagnostic code on the first line, followed by
**Effect** (what could not be done) and/or **Next** (a scoped step). Human guidance
does not change exit codes, add private paths, approve new pins or bypass the
observed diagnostic writer. Machine JSON/SARIF on stdout is unchanged; error
explanations stay on the diagnostic stream. Unknown errors receive no guessed
remedy. `DIR` in suggested maintenance commands is a placeholder; scan setup does
not supply defaults to maintenance commands.

| Symptom | Meaning and safe next step |
| --- | --- |
| `command not found` | Build/install outside the target and check `PATH`; not an npm package |
| `cli: unsupported-command` for `intel --help` | There is no separate intel help dispatcher; use `packtrace --help` and this command reference |
| Missing names | Portable mode intentionally hides them; explicitly select policy-permitted local output |
| `scan: user-setup-invalid; run packtrace setup --help` | Changed/missing/corrupt configuration, policy mismatch or ownership/root admission issue; preserve originals and review, do not hand-edit the saved pin |
| Existing setup was not replaced | Setup is exclusive; use a reviewed explicit policy for a one-off alternative |
| `scan: unsupported-or-conflicting-options` | Policy/check/privacy/manager/pin disagreement; do not weaken the policy blindly |
| `scan: intelligence-binding-unavailable` | Missing, unsafe, incompatible or unqualified state binding; verify the selected external store and supported filesystem, not a copied marker |
| Expired source check | An explicitly authorized sync can renew a successful source check; a separately needed full reconciliation remains independent |
| `installed-manifest-unavailable` | Missing, unreadable, unstable or inadmissible manifest, including extra hardlink names; not necessarily an absent package |
| Bun manifests have more than two links | Outside the closed-pair profile; do not unlink, copy to launder evidence, or relax the link guard |
| `lock-version-unsupported` | Unsupported lock format; report the gap, do not install/migrate dependencies as part of scanning |
| Zero findings but candidates | Version investigation without qualified origin/applicability; inspect context, do not relabel as confirmed vulnerabilities |
| Many incomplete checks | Several may share an inventory/freshness limit; platform/final-lifecycle qualification is tool evidence, not a target defect |
| Integrity `[NOT RUN]` | No selected comparison; select/review checks and prepared mappings, never treat as passed |
| File output refused | Saved setup/Bun-cache stdout restriction, unsupported platform, existing file or unsafe destination; see report-file rules |
| `--verbose` rejected | Do not combine with JSON/SARIF, repeat it, or give it a value |
| No color | Expected for pipes/files, verbose/machine output, `NO_COLOR`, dumb/unsupported terminal; labels still carry meaning |

Do not run with elevated privileges, change target ownership, reinstall dependencies,
refresh data, or remove state automatically to “fix” an investigative refusal.

## 11. Supplied-input tools

These are advanced, bounded **stdin** experiments, not alternatives that secretly
scan the target. Obtain authorized metadata separately; examples use invented data.
All support terminal or JSON, not SARIF. Usable investigative reports remain exit
`3`; invalid arguments/input/output failures are `2`. `--help` exits `0` without
reading stdin. The demo's usable scenarios also remain incomplete.

| Command | Supplied input / purpose |
| --- | --- |
| `inspect` | JSON object with `lockfile` and `advisory`; npm metadata hypotheses |
| `inspect-batch` | `lockfile` and `advisories` (1–16); bounded supplied batch |
| `inspect-bun` | Original `lockfile_text` string and `advisory` object |
| `inspect-bun-batch` | `lockfile_text` and `advisories` (1–16) |
| `compare-npm-root` | `manifest` and npm v2/v3 `lockfile` objects; textual root requirements |
| `compare-bun-root` | `manifest` object and original `lockfile_text`; textual root requirements |
| `check-reference-digest` | Raw stdin bytes and `--integrity SRI`; digest equality only |
| `demo` | Built-in owned synthetic scenario, no stdin/project access |

npm `inspect`/`inspect-batch` optionally accept `--identity-profile explicit-only`
(default) or `npm-lock-v2-v3`; Bun equivalents do not. Batch wire limit is 1 MiB,
64 tuples/lock records, 64 total affected slots and 4096 pairs. Root comparison
wire limit is 1 MiB; textual differences are not semantic range equivalence.
Digest input defaults to at most 512 MiB (`--max-bytes` decimal 0–536870912).
Only one canonical SHA-256/384/512 token can match/mismatch; unsupported/multiple
claims remain unknown without reading input. Equality is not reference authenticity.

```bash
packtrace demo --scenario candidate
packtrace demo --scenario no-version-match --format json
printf '%s' abc | packtrace check-reference-digest --integrity 'sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=' --format json
printf '%s' '{"manifest":{"dependencies":{"example":"^1"}},"lockfile":{"lockfileVersion":3,"packages":{"":{"dependencies":{"example":"1.x"}}}}}' | packtrace compare-npm-root --format json
```

Demo scenarios: `candidate`, `no-version-match`, `unsupported`, `withdrawn`,
`different-identity`, `malformed`. For each stdin tool's exact envelope run, for
example, `packtrace inspect --help`; help is available per supplied-input command.

## 12. Limits and technical references

Current interpretation covers stable npm 10/11 v2/v3, npm 12 v3, bounded Bun 1.3.x
text formats and the explicitly retained older profiles. It does not qualify every
producer patch, layout, operating system, filesystem, external store or runtime.
Installed evidence is not a complete runtime-resolution or dependency-reachability graph.

Matching is bounded (64 active observations, 4096 work/decision rows, 512 MiB actual
matching reads); a scan worker has a five-minute deadline. These are not whole-process
hard-memory guarantees; `requireHardMemoryLimit: true` is not admitted. Resource,
publication, native ownership and confirmed cleanup are independent checks. Source
license and freshness rules also remain mandatory; do not increase limits to hide
unsupported inputs.

- [Design decisions](design-decisions.md): authoritative scope and safety decisions.
- [Inventory compatibility](inventory-compatibility.md): scoped producer/layout evidence.
- [Intelligence compatibility](intelligence-compatibility.md): source, licensing, maintenance and budgets; historical evidence is labeled by increment.
- [Policy and publication](increments/issue-8-trusted-policy-and-exceptions.md): exact exception and file-output contracts.
- [Origin candidates](increments/issue-6-offline-origin-candidates.md): why version candidates are not confirmed findings.
- [Release checklist](pre-1.0-features.md): remaining qualification, not implied by issue closure.
- [Upstream data licenses](../internal/intelstore/licenses/README.md): attribution and supported publisher notices.

For contributor checks see [Local development](../README.md#local-development).
