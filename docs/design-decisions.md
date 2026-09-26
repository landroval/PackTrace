# PackTrace technical design decisions

## Status and approval boundary

These are user-approved design directions, not the complete technical
specification or implementation plan. Production implementation, dependency
installation, new probes, native runner provisioning, and publication remain
unapproved. Review and approve the written specification and implementation plan
before separately authorizing production work.

This record carries forward the decisions made after the
[SCALIBR evaluation](inventory-evaluation-results.md). It supersedes the earlier
selective-extractor-reuse recommendation and three-platform qualification proposal
in [inventory compatibility](inventory-compatibility.md), not its historical
probe scope or results. Other existing constraints remain in force.

Related: [roadmap](development-roadmap.md),
[engineering guidelines](development-guidelines.md).

## 1. Inventory adapter ownership

**Approved choice:** PackTrace-owned, field-preserving adapters rather than
retaining SCALIBR extractors or waiting for upstream extensions.

- Use standard Go JSON decoding for npm lockfiles and manifests, with explicit
  supported-version and shape validation.
- Evaluate existing JSONC handling for Bun; no dependency has been selected or
  authorized for production installation.
- Maintain one authoritative projection of required observations. Do not add a
  second lossy extraction path without a demonstrated benefit.
- Own format compatibility tests and maintenance. Preserve the probe corpus as
  evaluation evidence; do not silently promote the probe into production.

The evaluation demonstrated lost source, digest, layout, and relationship data.
Supplementary field handling would be necessary even with SCALIBR reuse. The
selected approach avoids reconciling two parsers' outputs, at the cost of owning
format handling. This is not approval for a parser framework or a general
package-manager resolver.

## 2. Native pilot qualification targets

| Operating system | Architecture | Status |
| --- | --- | --- |
| Ubuntu 24.04 | amd64 | Planned |
| Ubuntu 24.04 | arm64 | Planned |
| macOS 15 | arm64 | Planned |
| macOS 15 | amd64 | Planned |
| Windows Server 2022 | amd64 | Planned |

These are target test environments, not asserted minimum OS requirements or
validated support claims. The earlier synthetic Linux probe does not qualify
these rows. Record actual runner image, filesystem, architecture, and toolchain
when separately authorized native qualification runs occur. Cross-compilation
alone is insufficient.

## 3. Evidence and coverage model

**Approved direction:** terminal, versioned JSON, and SARIF consume one structured
result, rather than separate detection pipelines.

### Distinct observations

| Observation | Retained information |
| --- | --- |
| Declared | Manifest, dependency key/alias, original requirement, dependency group, workspace |
| Locked | Effective lockfile and entry location, recorded identity, source, digest, available relationships |
| Observed installed | Physical location, manifest-claimed identity, link information, observation method |

Observed installation establishes presence, not authenticity or execution.
Reconciliation links records without overwriting disagreements. Two physical
instances with the same name and version remain distinct. Declared requirements,
lockfile relationships, and observed filesystem links have different relationship
types. Unknown ownership or resolution stays unknown.

### Evidence

Each observation references relative source locations, field/entry locators,
digests of the bytes actually inspected, reader versions, and diagnostics.
Truncated reads are explicitly partial; their digests must not be presented as
complete-file hashes. Raw contents and credential-bearing URLs are not copied
into reports by default. Portable evidence remains subject to the existing
privacy and redaction requirements.

### Per-scope check outcomes

Each check records its scope, whether policy requires it, evidence, and outcome:

| Outcome | Meaning |
| --- | --- |
| Completed | Finished its defined scope; findings may exist |
| Incomplete | Attempted, but gaps prevent completion |
| Not run | Unavailable, unsupported, excluded, or blocked, with an explicit reason |
| Not applicable | Evidence establishes that the check does not apply |

Exclusion does not satisfy a required check. An unreadable directory leaves
applicable discovery incomplete. Do not claim a completion percentage when the
total inventory is unknown. The approved scan defaults and exit-code precedence
are recorded in section 5 below.

Findings independently reference observations, evidence, advisory/reference
provenance, and limitations. Missing references or stale intelligence cannot erase
findings already obtained, nor count as verification.

**Required acceptance example, not yet executed:** two observed copies of an
affected package retain two instance records. When another directory is unreadable,
known matches remain visible and the affected discovery scope is incomplete.

## 4. Filesystem and parser safety boundaries

**Approved direction:** a root-contained reader and supervised worker processes
using the same PackTrace binary. Exact platform mechanisms and numerical limits
remain to be specified and qualified.

- Open the explicitly selected project root once. Use handle-relative,
  traversal-resistant access, not string-prefix checks.
- Permit supported in-root workspace/store links with cycle detection. Record
  outside-root links without following them. Mount points and Windows reparse
  points require explicit handling; lexical containment alone is insufficient.
- Never run package managers, scripts, executable configuration, or target
  binaries. Target access is read-only.
- Keep reports, temporary files, snapshots, and caches outside the investigated
  tree. Reject destinations that alias back into it.
- Inspect supported directories and regular files only. Platform-specific opening
  rules must prevent special-file races from turning reads into FIFO/device
  access. Unsupported link or file types produce coverage gaps.
- Bound input bytes, total reads, entry counts, depth, archive expansion, worker
  output, concurrency, and duration. Supervised parser/archive jobs let failures
  and timeouts become diagnostics rather than destroy the entire report.
- A subprocess is not a security sandbox. Go's memory target is not a hard memory
  limit. OS-enforced limits require native qualification; do not claim those
  controls merely because a child process exists.
- Use opened handles and before/after identity/metadata checks to detect changing
  files. Detected changes invalidate affected comparisons. This is a live
  observation, not an immutable snapshot; unchanged metadata does not prove
  absence of concurrent tampering.
- Inspect archives without extraction. Reject unsafe names, conflicting entries,
  unsupported special types, and resource-limit violations.
- Block affected operations when required safety checks cannot be enforced;
  never silently downgrade protection.

**Required native acceptance coverage, not yet executed:** escaping links,
junctions/reparse points, cycles, special files, changing inputs, archive attacks,
worker crashes, and resource limits on every target platform. No protection from
an attacker controlling the host is claimed.

## 5. Scan defaults and exit codes

**Approved choice:** require all three detection categories by default, with
explicit narrower scopes rather than silent skipping. These commands and flags
are design contracts, not implemented commands.

- `packtrace scan PATH` runs offline: inventory, malicious-package matching,
  vulnerability matching, and integrity comparison using local inputs.
- Missing intelligence or references never trigger downloads. Applicable checks
  become incomplete or not run, with recorded reasons.
- `--checks malicious,vulnerability` explicitly selects an advisory-only
  investigation. Report integrity as excluded; do not describe the result as a
  complete three-category investigation.
- Inventory collection is a prerequisite, not an optional check.
- Findings alone do not fail a completed scan by default. `--fail-on` enables
  enforcement for selected finding categories.
- Reject attempts to disable policy-required checks through project settings or
  narrower command-line selection.

### Exit contract

| Code | Meaning |
| --- | --- |
| `0` | Required checks completed; no enforced, unaccepted findings |
| `1` | Required checks completed; enforced, unaccepted findings exist |
| `2` | Invalid invocation/policy or operational failure prevents producing the requested report |
| `3` | Required coverage is incomplete, regardless of findings |
| `130` | Interrupted by the user; preserve a partial report where possible |

For ordinary completion, precedence is operational failure, then incomplete
required coverage, then enforced findings, then success: `2 > 3 > 1 > 0`.
Interruption has its own outcome. Reports retain all applicable conditions even
though the process returns one code. No exit value asserts that a target is safe.

A first scan without prepared local intelligence or applicable references will
usually return `3`. A completed report-first scan may return `0` with findings
prominently displayed. Check-level failures that can be represented in a report
remain coverage gaps; they do not automatically prevent report production.

**Required acceptance examples, not yet executed:**

| Scenario | Expected code |
| --- | --- |
| Required checks complete; findings present; enforcement disabled | `0` |
| Required checks complete; unaccepted finding in an enforced category | `1` |
| Required integrity reference missing; enforced advisory finding also present | `3` |
| Requested report cannot be written; findings and coverage gaps also present | `2` |
| Policy requires integrity; invocation attempts to exclude it | `2` |
| User interrupts scan | `130` |

## 6. Configuration, policy authority, and output

**Approved choice:** explicit static JSON policy selection and no automatic
project-policy or per-user configuration discovery.

- Ship documented built-in defaults. Accept an optional policy through
  `--policy FILE`; never execute configuration or load target `.npmrc`
  credentials.
- Manifests and lockfiles supply investigation evidence only. Their settings
  cannot authorize networking, suppress findings, or weaken required coverage.
- Command-line options select the target, requested checks, enforcement
  categories, local inputs, and output format. A supplied trusted policy sets
  constraints: required checks, mandatory enforcement, freshness requirements,
  resource ceilings, and approved exceptions.
- Flags may strengthen policy. Conflicting attempts to weaken it fail validation
  with exit `2`. Invalid policy never silently falls back to built-in defaults.
- Exceptions come from the explicitly supplied policy and remain visible. They
  require scoped evidence, a reason, and expiry; they cannot make an unperformed
  check complete. Exact exception schema and evidence-binding rules remain to be
  specified under the existing engineering constraints.
- Record effective settings, their origins, and the policy digest in the result,
  with sensitive values redacted.

### Authority limitation

`--policy` means the operator explicitly selected a policy. A file is not
organization-approved merely because it exists outside the project. CI must
control the policy source and invocation. The local CLI cannot prevent an
operator from omitting an organization's policy. A policy digest identifies the
selected bytes; it is not proof of organizational approval.

### Output routing

Use `--format terminal|json|sarif`, with terminal as the default. Machine-readable
output goes to stdout; diagnostics go to stderr. An explicit output-file option
must reject unsafe or in-target destinations. Caller-managed shell redirection
remains the caller's responsibility; application destination checks do not
control a shell opening redirected stdout before PackTrace starts.

**Required acceptance coverage, not yet executed:** policy precedence, weakening
conflicts, invalid-policy handling, target configuration unable to grant authority,
recorded effective policy, visible exceptions, output-channel separation, and
unsafe explicit output destinations.

## 7. Intelligence acquisition sources

**Approved choice:** OSV's aggregated npm export is the pilot's single acquisition
source, including the OpenSSF Malicious Packages records it aggregates. No direct
OpenSSF synchronization path is planned for the pilot. Match locally; never
submit the investigated project's package list.

The alternative, OSV plus direct OpenSSF acquisition, could reduce dependence on
OSV's import delay for malicious-package reports, but requires a second update
path, duplicate handling, and conflict reconciliation. The selected approach
accepts the documented aggregator limitations rather than hiding them.

- Record acquisition source separately from advisory publisher, with snapshot
  identity, timestamps, hashes, and licensing/attribution.
- Distinguish malicious-package reports from vulnerabilities through supported
  source metadata, not summary-text heuristics. Ambiguous classification remains
  a diagnostic; exact source mappings require qualification.
- Describe detections as advisory matches, not proof of malware execution.
  OpenSSF permits some borderline reports and acknowledges false positives.
- Apply withdrawals and corrections to new scans while preserving historical
  reports' original evidence.
- Distinguish HTTPS transport, downloaded-byte hashes, and publisher authenticity.
  Computing a hash does not produce a publisher signature.
- Do not bundle the full dataset into the binary. Source-specific licensing and
  attribution obligations still require review.

### Source limitations

[OSV's export documentation](https://google.github.io/osv.dev/data/) lists OpenSSF
Malicious Packages among its aggregated sources and describes full/per-ecosystem
exports, including withdrawn records. It also lists source-specific licenses;
there is no assumption that every publisher shares one license.

[OSV's FAQ](https://google.github.io/osv.dev/faq/) states that deletion handling
differs by import mechanism. Records deleted from Git/REST sources can remain
active but orphaned. A recent synchronization cannot guarantee every upstream
correction has propagated. Full reconciliation against OSV cannot repair facts
that OSV itself still publishes incorrectly.

[OpenSSF's scope and false-positive guidance](https://github.com/ossf/malicious-packages#scope)
allows some empty/trivial spam or typosquatting reports and describes withdrawals
and version-level corrections. The interpretation of supported correction fields
must be specified and tested; absence of an understood correction is not proof
that a report is accurate.

## 8. Synchronization and recovery

**Approved direction:** full bootstrap, incremental updates, and periodic full
reconciliation. Establish full-refresh correctness first; implement incremental
updates and reconciliation before pilot qualification. This preserves the
roadmap's incremental-update requirement.

- A separate `packtrace intel sync` command explicitly authorizes fetching the
  configured public feed. It takes no project target and sends no target-derived
  package identities. This command is a design contract, not implemented code.
- Download into staging outside investigated trees. Validate archive structure,
  resource limits, record identities, supported schemas, and source metadata
  before publishing.
- Atomically publish a complete local snapshot. Each scan pins one snapshot for
  its entire run; synchronization cannot change its evidence midway.
- Failed updates preserve the last known-good snapshot and do not refresh its
  successful-check timestamp. Never activate a partially downloaded snapshot.
- Start from the full npm export. Incremental updates use OSV change listings and
  track previously known IDs that move outside the npm directory. OSV documents
  that records without an ecosystem, commonly withdrawn records, are exported
  under `[EMPTY]`; polling only npm's change listing is insufficient.
- Commit an update cursor only with its validated snapshot. Handle timestamp
  ties, duplicate records, retries, and interruptions without losing changes.
- Periodically reconcile against a full export. A disappeared record is not
  automatically withdrawn: establish its current disposition. Unresolved
  disappearance is a data-quality gap, not a silently inferred withdrawal.
- Retain withdrawal/correction provenance. New reports use the newly selected
  snapshot; historical reports are not rewritten.
- Do not follow arbitrary URLs embedded in advisory records.

Exact download/expansion limits, snapshot layout, validation and classification
rules, cursor semantics, and reconciliation checks remain to be specified and
qualified. OSV export/change-list behavior is documented in the source link above;
this approval does not claim a transactional upstream export or guarantee that
change timestamps alone detect every upstream change.

**Required acceptance coverage, not yet executed:** interrupted and corrupt
updates, atomic publication, pinned concurrent readers, last-known-good recovery,
timestamp ties and retries, corrected records, withdrawals moving to `[EMPTY]`,
record disappearance, and reconciliation. No real feed archive has been imported
or synchronization implementation authorized by these design decisions.

## 9. Intelligence freshness policy

**Approved defaults:** maximum successful source-check age of 24 hours, plus
successful full reconciliation at least every seven days.

- Both advisory categories use the same pinned snapshot and acquisition
  freshness policy.
- Measure age from the last successful source check establishing the snapshot's
  currentness, not local file modification/copy time or an individual advisory's
  `modified` date.
- Successful unchanged-source revalidation may refresh the check time. Failed or
  partial updates may not.
- Copying/importing a snapshot preserves its original provenance and times.
  Missing, untrustworthy, or future-dated freshness metadata means unknown
  freshness, not fresh data.
- Exceeding either the source-check age or full-reconciliation interval makes
  required intelligence coverage incomplete. Continue matching against usable
  local data and retain findings; a scan with this gap returns `3` unless a
  higher-precedence operational failure occurs, or the user interrupts it.
- Unknown freshness likewise prevents complete required intelligence coverage.
  Missing/corrupt snapshots make matching unavailable, not successfully empty.
- Synchronization remains explicit. These intervals do not create a background
  network task.
- An explicitly selected trusted policy may set different intervals. Command-line
  options cannot weaken the selected policy.

Here, fresh means checked against the selected source within policy. It does not
mean OSV has received every upstream report or correction. Report source/export
timestamps separately so acquisition freshness does not hide upstream lag.

The offline team workflow is explicit snapshot preparation, distribution without
resetting its age, and scanning without networking.

**Required acceptance coverage, not yet executed:** freshness boundaries, failed
updates not renewing age, successful unchanged revalidation, imported/copied
snapshots retaining age, unknown/future timestamps, overdue full reconciliation,
and findings retained when coverage becomes incomplete.

## 10. Advisory matching semantics

**Approved direction:** three evaluation outcomes: match, no match, and
indeterminate. No match requires complete evaluation of the applicable case.

- Compare ecosystem, package identity, concrete version, and supported origin
  correspondence. Package aliases retain both the local name and target identity.
- A declaration such as `^1.2.0` does not identify an installed version. Do not
  resolve it or substitute a minimum version.
- Follow [OSV's evaluation semantics](https://ossf.github.io/osv-schema/):
  enumerated affected versions OR affected ranges. Respect `introduced`, `fixed`,
  `last_affected`, and `limit` boundaries.
- Use SemVer ordering for `SEMVER` ranges, including prereleases. Do not substitute
  npm dependency-selection constraint rules for vulnerability-range evaluation.
- Evaluate `ECOSYSTEM` ranges only with qualified npm semantics. Do not reconstruct
  Git histories. An unsupported condition that prevents ruling out affectedness
  makes the result indeterminate, not negative.
- Preserve valid positive matches even when other conditions remain unevaluated,
  with the limitations visible. This does not permit ignoring a withdrawal or
  correction that could invalidate the positive match.
- Withdrawn records do not generate new active findings. Unknown or contradictory
  corrections must not be silently ignored.
- Advisory aliases may group presentation but must not automatically merge ranges,
  severities, or provenance.
- Retain the observation supporting each match: locked and observed-installed
  evidence remain distinct. A match based on a mutable manifest does not
  authenticate its contents.

Possible matches with ambiguous origin correspondence remain visible candidates,
not confirmed findings eligible for enforcement. If the required correspondence
cannot be established, coverage remains incomplete. Here, confirmed means the
matching conditions were supported, not that malicious behavior or vulnerable
code execution was independently demonstrated.

**Required acceptance coverage, not yet executed:** inclusive/exclusive boundaries,
prereleases, invalid versions, package/advisory aliases, withdrawals, corrections,
partially supported conditions, and ambiguous-origin candidates remaining visible
without being treated as enforcement-eligible confirmed matches.

## 11. Source classification and network authorization

**Approved direction:** separate observed origin from permission to download.
Source classification is evidence, not a network grant.

- Record the observed source mechanism: registry, Git, archive URL, local
  archive/directory, or workspace.
- Classify origin as public, private, or unknown using explicit rules and validated
  evidence. Preserve conflicts. A scoped package name or URL containing `npm` is
  insufficient.
- Associating a package with public npm advisories requires supported origin
  correspondence. A private mirror requires an explicit equivalence rule; shared
  name/version alone does not prove equivalence.
- A manipulated lockfile cannot authorize queries or downloads. Keep `scan`
  offline.
- Prepare public references through a separate operation requiring explicit
  selection of public requests and authorization to disclose their identities
  and URLs. Exact request representation and command syntax remain to be specified.
- Restrict HTTPS to authorized destinations. Validate port, URL, DNS resolution,
  and the actual connection address. Block local, private, and cloud-metadata
  destinations in this public-fetch flow.
- Revalidate each redirect and bound redirect count. Do not accept implicit proxies
  or project credentials. Any proxy requires explicit trusted configuration.
- Private or unknown sources use local references or prepared caches without
  automatic public queries. Authenticated private-registry fetching remains
  outside the pilot.

Validate the actual destination used, not only a URL before a separate DNS
resolution chooses the connection address. Proxy handling must preserve the
approved destination restrictions; its enforcement mechanism requires design and
qualification rather than an assumed bypass.

**Required acceptance example, not yet executed:** a private package sharing a
public package's name must not cause a public query or an affectedness assertion
based only on that name. Additional checks cover conflicting origin evidence,
mirror equivalence, redirect escapes, DNS changes, reserved destinations, and
implicit credentials/proxies.

## 12. Integrity references and assurance

**Approved default:** accept `lockfile-consistent` as the minimum assurance level,
with explicit limitations. A trusted policy may require `independently anchored`.

### Reference provenance

- Lockfile-consistent means the reference artifact matches the project's recorded
  digest. It cannot resist an attacker changing both installed files and lockfile.
- Independently anchored means the expected digest comes from an explicitly
  designated trusted baseline with identity, version, origin, and a reason for
  trusting it. Merely storing the baseline outside the project is insufficient.
- Downloaded or cached artifacts gain no trust from their location. Verify their
  bytes against the applicable expected digest before installation comparison.
- Admit SHA-256, SHA-384, and SHA-512 for these assurance claims. Preserve weak
  hashes as evidence but do not use them to declare a verified reference. A weak
  digest must not compensate for failure of a strong digest.
- Preserve baseline/lockfile disagreements and distinguish which reference
  supports each comparison. Never claim both assurance levels were satisfied
  when their evidence conflicts.

The more restrictive alternative, independently anchored by default, would improve
resistance to joint lockfile/content manipulation but require baseline preparation
before complete required coverage. It was not selected as the built-in default.

### Comparison scope

Compare published files for modification, absence, addition, and relevant type or
link changes. Delimit nested packages, bundled content, and generated metadata
using specific qualified rules, not blanket exclusions.

Patches and build outputs provide context but are not executed or reconstructed.
Differences remain integrity drift, not automatic evidence of malware. An integrity
match likewise does not establish benignness.

A comparison can be complete only for its explicit scope. Unreadable/changing
files, exclusions without sufficient justification, or inadequate references
prevent verification of that scope. The selected minimum assurance must be met;
a weaker comparison does not satisfy a policy requiring an independent baseline.

**Required acceptance coverage, not yet executed:** weak/missing/wrong digests,
strong-digest failures not rescued by weak digests, baseline/lockfile conflicts,
mutable caches, identity/source binding, policy-required independent assurance,
modified/missing/added/type/link changes, nested and bundled ownership, generated
metadata, patches, and unreadable/changing/excluded content.

## 13. Remaining design work

The approvals above do not settle the following contracts:

- Component/data-flow details, effective-input selection, and per-format schemas.
- Exact filesystem/worker mechanisms and enforceable per-platform limits.
- Complete CLI and policy schemas, local-input locations, and validation rules.
- Concrete matching library/rules and source/classification/correction mappings,
  licensing review, and exact snapshot/update/reconciliation mechanics.
- Exact public-fetch requests, origin/mirror rules, DNS/proxy enforcement, baseline
  format, multi-digest handling, and per-layout integrity comparison rules.
- Report schema, fingerprints, redaction details, and evidence-bound exceptions.
- Resource/performance thresholds and executable acceptance checks.

These decisions authorize neither live synchronization nor artifact-fetch execution.
Review the remaining sections before producing the complete written specification.
Written-spec approval then permits implementation planning, not implementation.
