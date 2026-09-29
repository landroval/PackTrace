# PackTrace technical design decisions

## Status and approval boundary

These are user-approved design directions, not a complete technical specification
or implementation plan. The user has changed the development approach to small,
verifiable increments: approve the written specification for an increment, then
its implementation plan and execution. Closing every remaining product-wide
design question is no longer a prerequisite for unrelated increments.

This supersedes earlier statements requiring a complete product-wide specification
before any production development. Safety and release requirements remain intact;
native feasibility still gates the affected native mechanisms, not an in-memory
parser. Dependency installation, native probes/runners, and publication retain
their separate authorization boundaries. The first eleven implementation increments were
individually approved and explicitly authorized for inline implementation and
local synthetic verification. Their authorization does not extend to further
increments or native probes.

Implemented bounded deliverables: the
[npm v3 reader](increments/01-npm-v3-reader.md), its
[npm v2/v3 extension](increments/02-npm-v2-reader.md),
[typed locked records](increments/03-npm-locked-records.md),
[manifest declarations](increments/04-manifest-declarations.md),
[locked requirements](increments/05-locked-requirements.md),
[root requirement comparison](increments/06-root-comparison.md),
[bounded OSV record reading](increments/07-osv-reader.md),
[OSV temporal projection](increments/08-osv-times.md),
[OSV affected identities](increments/09-osv-affected.md),
[explicit OSV versions](increments/10-osv-versions.md), and
[OSV ranges and events](increments/11-osv-ranges.md). `ParseNPMLock` retains
raw evidence; `ProjectNPMLock` exposes explicit scalar claims and field states,
without semantic resolution or installed-state inference. The projection has its
own approved 20,000-record bound, including root/workspace/link entries; this does
not change raw-reader limits or redefine the installed-instance budget.
`ParseManifest` and `ProjectManifest` retain declared requirements separately,
without resolution or group merging. Manifest reads have a 2 MiB limit, and each
manifest projection has a separate 20,000-membership bound across its four groups.
Both readers share strict JSON validation; controlled errors use `inventory: CODE`.
Locked records also expose their own four requirements groups through the shared
projector. A separate 20,000-membership bound applies across the whole lockfile
projection, not per record; these claims are not current manifest declarations or
resolved edges, and the legacy tree remains separate.
`CompareRootRequirements` compares explicitly paired successful projections at lock
location `""`, retaining both digests, differences, and indeterminacy. Its at most
40,000 rows are textual evidence comparisons, not semantic/installed drift or threat
findings; its completeness says nothing about scan coverage or package safety.
`ParseOSVRecord` starts the internal intelligence reader with a 4 MiB/128-container
bound, nonempty string `id`/`modified`, raw fields, and original digest. Shared strict
validation now lives in `internal/jsoninput`; inventory errors stay unchanged, while
intel errors use `intel: CODE`. `ProjectOSVTimes` now retains modified/published/
withdrawn text, supported UTC instants, uninterpretable states, and a source withdrawal
claim. It does not infer active status, temporal ordering, or acquisition freshness.
`ProjectOSVAffected` retains positional ecosystem/name/PURL claims and hierarchy
states, distinguishing unavailable children from observed absence. Its separate
20,000-entry bound counts null/invalid slots and duplicates, without filtering.
Each affected entry also retains its own `versions` list, independent of package
usability; a separate cumulative 20,000-version-slot bound applies across the advisory.
Strings, positions and duplicates remain uninterpreted, not concrete-version qualification.
Affected ranges now retain type/repo claims, ordered events and all event fields
(including unknown/multiple bounds), with a separate combined 20,000-unit budget
counting range slots, event slots and event fields. Unsupported shapes remain explicit;
no interval construction or range-semantic qualification is performed.
Full OSV schema/identity/range/correction interpretation, matching, synchronization,
and advisory qualification remain unimplemented.
A twelfth increment adds a [Bun text lockfile reader](increments/12-bun-lock-reader.md),
reviewed through its pull request. `ParseBunLock` normalizes JSONC with a
length-preserving, stdlib-only scanner, then reuses `internal/jsoninput`; it retains
raw fields, workspace records, and package tuples with the original-byte digest.
Duplicate keys and non-integer versions are rejected, which is stricter than Bun.
Tuple projection, workspace/override semantics, and Bun producer qualification remain open.
A thirteenth increment adds [typed Bun locked records](increments/13-bun-lock-projection.md).
`ProjectBunLock` splits names at the first `@` after index 0 and classifies a tuple only
when both its resolution form and exact shape match Bun's writer; mismatches stay
`BunKindUnknown` records with their raw tuple in the document. It reuses `FieldState` and
`LockField[T]` but not npm's `LockedRecord`. INFO contents, workspace/override semantics,
a common npm/Bun model, and Bun producer qualification remain open.

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
- Use the pinned JSONC candidate and qualification requirements in section 24
  for Bun. No production dependency installation is authorized.
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

Initial download/expansion budgets are recorded in sections 20 and 21. Snapshot
layout, validation and classification rules, cursor semantics, and reconciliation
checks remain to be specified and qualified. OSV export/change-list behavior is documented in the source link above;
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

## 13. Report contract

**Approved direction:** versioned JSON represents the complete result model, with
terminal and SARIF as projections of that same model. Exported values remain
subject to the explicit privacy rules below; complete model coverage does not mean
an unredacted forensic export.

- Start with `schemaVersion: "1.0"`. Breaking changes increment the major version;
  minor changes are additive.
- Include execution, scope, inputs/snapshots used, inventory, evidence, coverage,
  findings, candidates, diagnostics, and effective policy. Exact field definitions
  remain to be specified in the written schema.
- Relate records through identifiers rather than duplicating all supporting
  evidence inside every finding. Keep unknown values explicit.
- Separate execution outcome from findings. An incomplete report may contain
  valid detections.
- Use stable ordering for comparisons. Timestamps and duration do not form part
  of finding identity.
- Keep severity and confidence distinct: preserve source severity when available
  and explain confidence through evidence, without invented probabilities.

### Terminal and SARIF

Terminal output summarizes coverage and findings, then limitations and next steps.
Never label the target safe or clean.

SARIF 2.1.0 represents findings as results, with locations only when available and
permitted. Coverage and diagnostics use execution metadata and notifications.
Ambiguous candidates must not become confirmed results. A consumer may hide those
metadata/notifications: an empty alert UI is not evidence of complete coverage.

Do not invent a physical installed location for a lockfile-only package. Preserve
exception acceptance state in every projection. Apply privacy rules to messages
and diagnostics, not only structured fields.

**Required acceptance coverage, not yet executed:** JSON/SARIF schema validation,
version compatibility, stable ordering, unknown values, lockfile-only locations,
separate candidates, and agreement between terminal/JSON/SARIF on findings,
coverage, exception status, and process outcome.

## 14. Report privacy profiles

**Approved default:** `portable` for all formats. The operator must explicitly
select `local` for additional investigative detail. These are presentation
profiles, not permissions to transmit data.

### Common restrictions

- Do not include credentials, tokens, raw file contents, or secret-bearing URLs.
- Omit absolute host paths and escape untrusted text.
- Apply the rules to errors, messages, references, and worker output, not just
  structured path fields.

### Portable

- Hide private/unknown-origin identities, sensitive URLs, and internal project
  paths.
- Replace sensitive references with opaque identifiers within the report,
  preserving relationships, counts, and coverage states.
- Do not publish sensitive evidence hashes or fingerprints that could expose names
  through dictionary attacks.
- Omit SARIF locations when showing them would reveal protected information. Do
  not substitute fictitious filesystem paths.
- Prevent messages or candidate details from reintroducing hidden fields.

Portable output reduces exposure but does not guarantee anonymity: counts, public
advisories, and other patterns can support inference. Its opaque identifiers do
not promise correlation across runs. Redacted exports are not interchangeable with
full local evidence for reviewing or creating exceptions.

### Local

- Show identities and relative paths needed for investigation, plus evidence
  hashes/fingerprints.
- Continue to prohibit secrets, raw contents, and absolute host paths.
- Treat the report as sensitive. Selecting local does not authorize uploading it
  to a service.

A trusted policy may require portable and prevent flags from weakening it.
Redaction changes presentation, not matching, coverage, or enforcement.

**Required acceptance coverage, not yet executed:** every output format under both
profiles; hidden fields absent from free-text diagnostics/candidates as well as
structured data; opaque references preserving relationships; omitted sensitive
hashes/fingerprints and SARIF locations; policy-enforced portable output; and equal
underlying decisions across profiles.

## 15. Evidence-bound exceptions

**Approved direction:** explicit temporary exceptions in the selected policy,
never coverage waivers. The default maximum lifetime is 30 days, explicitly
configurable by trusted policy.

Each exception includes:

- Identifier, reason, approval owner, and approval/expiry timestamps in UTC.
- Exact rule/advisory, package, version, origin, and project/instance scope.
- A fingerprint of the accepted evidence, not only a package name.

The lifetime runs from approval to expiry, not from each scan or snapshot refresh.
Approval-owner text and timestamps record policy assertions, not a cryptographic
proof of organizational approval; the policy-authority boundary still applies.

### Evidence binding

For advisories, bind the relevant observation and the evaluated advisory record.
Corrections changing that evidence require renewed review. A snapshot-only update
with unchanged bound evidence does not automatically renew or invalidate an
exception.

For integrity, bind the file/instance, reference and assurance level, expected
digest, and observed digest. Explicitly represent absence, addition, and type
changes when there is no comparable digest.

Maintain separate fingerprints:

1. Tracking fingerprint: correlate the same kind of finding across runs.
2. Acceptance fingerprint: establish that the evidence still matches what was
   reviewed.

A tracking fingerprint alone cannot transfer acceptance to new evidence. Sensitive
fingerprints are omitted in portable output. Canonical encodings and exact bound
fields remain to be specified and tested.

### Evaluation

- Expired, future, or evidence-mismatched exceptions do not accept findings.
- Malformed exceptions invalidate the policy with exit `2`. Structurally valid
  but inapplicable exceptions remain visible with their disposition.
- Accepted findings remain visible; acceptance only removes their contribution to
  finding enforcement.
- Do not admit permanent, global, or broadly wildcarded exceptions.
- Exceptions cannot confirm candidates or make incomplete checks complete.

**Required acceptance coverage, not yet executed:** lifetime limits and timestamp
boundaries, expired/future/malformed exceptions, exact scoping, evidence changes,
unchanged evidence across snapshot refresh, reference-assurance changes,
missing/added/type-change evidence, accepted findings remaining visible, and
coverage/enforcement independence.

## 16. Execution architecture

**Approved direction:** a modular monolith with a supervisor and one sequential
scan worker, both using the same executable. No services, plugin framework, or
initial database. Create concrete internal modules only as their features are
implemented, not empty scaffolding.

| Responsibility | Owns |
| --- | --- |
| `inventory` | Discovery, effective-input selection, adapters, reconciliation |
| `intel` | Pinned snapshots and local matching; separate synchronization operation |
| `integrity` | References, digest validation, comparisons |
| `policy` | Requirements, exceptions, exit decision |
| `report` | Privacy and terminal/JSON/SARIF projections |
| Safe file access and shared types | Small supporting modules without speculative abstractions |

### Supervisor/worker flow

1. The supervisor validates arguments, policy, destinations, and budgets.
2. It starts the worker with explicit configuration and a reduced environment,
   not arbitrary inherited target configuration.
3. The worker keeps the selected root open, observes inventory, and performs local
   matching/comparisons with inputs pinned for the run.
4. It sends bounded records and check-completion messages over pipes. The
   supervisor validates sizes, structure, and references.
5. The supervisor applies exceptions/enforcement, privacy, and rendering.

Parsing and archive work occur inside this supervised scan worker; the design
does not require a separate process for every file. A failure can stop the worker,
so retain already validated results and mark checks lacking a valid completion
message incomplete. EOF, panic, and timeout never imply success. Capture and bound
worker stderr rather than forwarding it unfiltered.

Start with one worker and sequential work. Add parallelism only if measurements
justify its added memory and I/O cost. The worker isolates failures, not security
privileges: it is not an OS sandbox. Scan paths must not invoke networking or
execute target code; verify with network-denied runs and inert fixtures.

## 17. Portable and strict memory controls

**Approved default:** portable work limits, Go runtime soft targets, and external
resident-memory monitoring. Trusted policy may additionally require a qualified
OS-enforced hard memory limit.

[Go documents SetMemoryLimit as a soft limit](https://pkg.go.dev/runtime/debug#SetMemoryLimit),
not a hard resident-memory ceiling. Do not conflate the two.

- Enforce byte, entry, depth, message, and time budgets in the portable mode.
- Set runtime soft targets and monitor supervisor plus worker consumption
  externally. Stop work on observed threshold violations and preserve a partial
  report where possible.
- Record the actual mechanism and limitations. Sampling may detect a peak late
  and does not guarantee preventing it.
- If policy requires a hard OS limit and no qualified mechanism is available,
  refuse the operation before reading the target.
- Portable operation must not silently depend on systemd, containers, privilege
  elevation, or extra tools.
- Filesystem, path, and network safeguards remain mandatory in either mode.

Requiring a hard OS ceiling for every scan was not selected: that alternative
would make the entire native matrix depend on demonstrating such a mechanism on
every platform. Exact monitoring, termination, and optional hard-limit mechanisms
still require platform-specific design and native qualification.

## 18. Initial scan budgets and acceptance targets

**Approved values:** initial design limits for `scan`, not measured capabilities
or performance guarantees. A failed qualification requires fixing the work or
explicitly reviewing limits, not silently increasing them.

| Resource | Default |
| --- | --- |
| Total scan duration | 5 minutes |
| Individual manifest / lockfile | 2 MiB / 64 MiB |
| Cumulative target manifest/lockfile metadata reads | 256 MiB |
| Individual content file | 256 MiB, streamed |
| Total target reads | 16 GiB |
| Local intelligence reads, including verification and rereads | 8 GiB |
| Visited entries / installed instances | 500,000 / 20,000 |
| Path depth / JSON nesting | 64 / 128 |
| Worker message / cumulative protocol traffic | 1 MiB / 64 MiB |
| Captured worker stderr | 64 KiB |
| Go soft target: worker / supervisor | 512 MiB / 128 MiB |
| Observed aggregate resident threshold | 1 GiB, sampled every 100 ms |

Count rereads and do not reset budgets between phases. Budget exhaustion must
produce diagnostics and incomplete affected coverage, never silent omissions.
Resident usage can exceed the observed threshold between samples. Deadline,
termination, and cleanup behavior need native qualification; instantaneous OS
termination is not implied.

Synchronization, downloads, and reference-archive expansion have separate budgets
in sections 20 and 21. Do not accidentally apply a manifest-size cap to a feed
archive. Section 25 clarifies target-metadata versus local-intelligence accounting;
section 26 counts protocol traffic across both pipe directions.

### Functional and platform acceptance

- Require exact expected outcomes for inventory, matching, integrity, policy, and
  privacy fixtures.
- Exercise adversarial paths, file types, parsers, IPC, and cancellation.
- Execute on all five approved OS/architecture pairs. Cross-compilation cannot
  substitute for native execution.

### Performance qualification target

Use a fixed corpus containing 1,000 installed instances, 50,000 files, and 1 GiB
of content, with prepared local intelligence and references. Record a reference
environment of 4 vCPU, 8 GiB RAM, and SSD storage.

- Median of five executions: at most 90 seconds.
- Conservative sum of individual supervisor/worker peak resident-memory values:
  at most 1 GiB. This is a qualification metric, not a portable hard runtime cap.
- Record cache conditions and system state; do not disguise a warm-cache result
  as cold-cache performance.
- A run skipping work because of limits is not a passing benchmark.

Exact corpus contents, intelligence/reference identities, native measurement
methods, and reproducible execution instructions belong in the specification and
acceptance plan before implementation approval. No benchmark or new native probe
has been authorized or executed by approving these targets.

## 19. Effective-input selection and scope

**Approved direction:** automatic selection only when there is a unique coherent
interpretation. Otherwise preserve evidence and require an explicit selection;
do not guess an effective dependency tree.

- `PATH` defines the root. Do not ascend to discover parent projects or
  automatically include independent nested projects.
- Retain the approved anchors: npm 8.19.4/10.9.4/11.6.2 and Bun 1.3.2/1.4.2.
  Recognizing a lockfile version does not expand the support claim.
- Target `packageManager` metadata is a hint, not independent producer proof or
  authorization.
- In the supported npm profile, `npm-shrinkwrap.json` takes precedence. If present
  but unreadable, invalid, or unsafe to access, do not silently substitute
  `package-lock.json`.
- If npm/Bun inputs coexist, or precedence depends on an unknown manager version,
  require `--manager`. Record the selected interpretation and conflicts. The flag
  cannot make an unsupported format compatible; section 28 defines the family
  and explicit-profile syntax.
- npm 12, Yarn, pnpm, and `bun.lockb` remain outside initial support. Never convert
  files or execute package managers to make them scannable.
- Validate Bun `lockfileVersion`, `configVersion`, and used structures separately.
- Preserve the workspace baseline: explicit relative paths and `packages/*` /
  `apps/*` patterns. Overlaps, escapes, and unsupported patterns create coverage
  or attribution gaps.
- npm's hidden lockfile is auxiliary evidence, not a substitute for the effective
  root lockfile or physical observation.
- Without a usable lockfile, preserve manifests and installed observations; mark
  checks depending on that lockfile incomplete.
- Do not reinterpret unreferenced store content as active dependencies. Preserve
  additional observed packages and bundled content with their context.
- Reject relevant structural ambiguity, including duplicate JSON keys, rather
  than silently relying on last-key-wins decoding.

**Required acceptance coverage, not yet executed:** conflicting inputs, unreadable
and invalid shrinkwrap without fallback, ambiguous manager semantics, unsupported
formats despite explicit selection, separate Bun version validation, workspace
boundaries, absent lockfiles, extra/unreferenced/bundled content, and duplicate
keys. Producer-generated qualification still requires separate authorization.

## 20. Intelligence synchronization budgets

**Approved initial limits for `intel sync`:** qualify against real feed data before
pilot release; these are design values, not measured consumption.

| Resource | Limit |
| --- | --- |
| Operation duration | 15 minutes |
| Cumulative HTTP response bytes, including retries | 2 GiB |
| Individual compressed ZIP / change-list CSV | 1 GiB / 256 MiB |
| Individual advisory record | 4 MiB |
| Expanded/processed advisory data | 8 GiB |
| Candidate snapshot entries | 2,000,000 |
| Simultaneous operation staging occupancy | 16 GiB |
| Total HTTP requests | 10,000 |
| Connection / response headers / complete request | 10 s / 30 s / 5 min |
| Redirects / total attempts per request | 3 / 3 |

- Also apply the approved memory controls; they are not a portable hard ceiling.
- Count actual received/expanded bytes, not only declared lengths.
- Do not reset counters during retries or strategy changes.
- An incremental update may switch to a full update only within the remaining
  budget. Otherwise fail while preserving the previous snapshot.
- Exceeding a limit prevents candidate publication and freshness renewal. Never
  remove records merely to make a snapshot fit.
- Staging occupancy excludes earlier retained snapshots. It is not a global quota
  for all retained historical storage; section 22 defines the separate global
  quota and retention policy.

### Public metadata observation

Only public object metadata was read during this design review; the archives and
change listing themselves were not downloaded or processed.

| Object | Declared size in bytes | Observed object generation |
| --- | --- | --- |
| npm `all.zip` | 216,647,962 | `1790386541792347` |
| Global `modified_id.csv` | 131,604,135 | `1790432844955195` |

Sources: [npm ZIP metadata](https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o/npm%2Fall.zip)
and [global change-list metadata](https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o/modified_id.csv).
These observations informed initial caps; they do not measure expansion, memory,
entry counts, transactional consistency, or future feed sizes.

**Required acceptance coverage, not yet executed:** response and expansion budgets,
false declared sizes, retries/redirects counted correctly, non-resetting strategy
changes, staging exhaustion, and no activation or freshness renewal after any
budget failure. Approval does not authorize live synchronization now.

## 21. Artifact preparation and reference inspection budgets

**Approved direction:** separate online preparation from offline reference
inspection during `scan`.

| Resource | Initial limit |
| --- | --- |
| Public preparation duration / requested artifacts | 30 minutes / 1,000 |
| Cumulative HTTP response bytes, including retries | 8 GiB |
| Individual compressed artifact | 512 MiB |
| Simultaneous preparation staging occupancy | 4 GiB |
| Reference reads per scan, including rereads | 16 GiB |
| Expansion per reference archive / aggregate per scan | 2 GiB / 8 GiB |
| Entries per reference archive | 100,000 |
| Individual expanded published file | 256 MiB |

Reuse the HTTP connection, header, complete-request, redirect, and attempt limits
in section 20 without resetting counters. Each scan also retains its own deadline
and memory controls.

- Inspect reference archives without extracting their paths into the filesystem.
- Count actual expansion, headers, and entries. Small declared sizes cannot bypass
  limits.
- Validate the artifact digest before claiming comparisons are supported by it.
- Reject unsafe paths, collisions, contradictory entries, and unsupported types;
  do not skip them and declare equality.
- Truncated downloads and wrong-digest artifacts are not verified references.
- Within a preparation batch, retain individually verified artifacts, but report
  every failure and do not claim complete batch success. This differs deliberately
  from atomic publication of a complete intelligence snapshot.
- Inspection limits make the affected comparison incomplete without erasing
  previous findings.
- Transfer/staging limits are distinct from the global quota and retention policy
  in section 22; both sets of limits apply.

Private/unknown sources still use local references. These budgets neither widen
network authorization nor authorize executing artifact downloads now.

**Required acceptance coverage, not yet executed:** compressed/expanded/entry
limits, repeated reads, truncated downloads, wrong digests, unsafe archive entries,
partially successful batches, and incomplete comparisons retaining earlier
findings. Qualify numeric defaults rather than silently increasing them.

## 22. Global cache quota and retention

**Approved default:** a 32 GiB quota for PackTrace-managed storage, with explicit
historical cleanup rather than automatic eviction.

- Count managed snapshots, artifacts, indexes, and staging against the global
  quota. Per-operation budgets still apply; their individual maxima need not all
  fit at the same time.
- Reserve capacity before writing and coordinate concurrent writers. If capacity
  is insufficient, fail without replacing the valid snapshot or silently raising
  limits.
- Protect the active snapshot, the previous valid snapshot, objects used by active
  scans, and explicitly pinned objects.
- Freshness expiry affects coverage; it does not automatically delete data.
- `cache prune` first presents a preview. Applying cleanup requires explicit
  authorization and revalidation of candidates, managed-store ownership, and
  active use. This is a design contract, not an implemented command.
- Never prune investigated targets, reports, baselines, or user-owned external
  references.
- Automatically clean up only the operation's own temporary data whose ownership
  is established. Report uncertain leftovers rather than deleting blindly.

Historical cleanup can prevent reproducing an old report even when that report
retains hashes and provenance. The preview must explain this risk. Automatic
eviction of unprotected historical objects was considered but not selected.

Exact quota accounting, reservations, pinning, crash recovery, and deletion
mechanisms require specification and native qualification. No existing cache,
probe data, or other files are authorized for deletion by this design approval.

**Required acceptance coverage, not yet executed:** concurrent quota reservations,
global versus per-operation budgets, full storage preserving a valid snapshot,
protected objects, active readers, preview/apply revalidation, uncertain ownership,
external paths, and explicit historical-reproduction warnings.

## 23. Online preparation scope clarification

The earlier shipping checklist called for explicit online scans. The user resolved
that requirement in favor of separate, explicitly authorized intelligence/artifact
preparation followed by offline scanning. Do not add an online mode to `scan` or
an additional integrated online-investigation command for the pilot.

The [shipping checklist](pre-1.0-features.md) and
[engineering guidelines](development-guidelines.md) reflect this scope decision.
Preparation retains all approved destination, privacy, trust, and budget controls;
selecting this workflow does not itself authorize executing network operations.

## 24. Toolchain and dependency baseline

**Approved design baseline:** official Go 1.27.1, pinned for initial qualification,
with `CGO_ENABLED=0`. The local probe host reports `go1.27.1-X:nodwarf5`; that
modified toolchain does not establish an official reproducible build. The
[official Go release catalog](https://go.dev/dl/?mode=json) listed Go 1.27.1 as
stable when reviewed. Only release metadata was retrieved, not toolchain archives.
Record actual toolchain artifacts, checksums, build settings, and native results
when their acquisition and qualification are separately authorized.

Use the standard library for CLI parsing, JSON, HTTP, hashes, and archives. The
following pinned candidates cover gaps rather than introducing a framework:

| Module | Pin | Intended use | Declared license |
| --- | --- | --- | --- |
| `github.com/tidwall/jsonc` | `v0.3.3` | Bun comment/trailing-comma normalization | MIT |
| `deps.dev/util/semver` | `v0.0.0-20260529052642-cf1e78d92744` | Version parsing and comparison | Apache-2.0 |
| `golang.org/x/sys` | `v0.44.0` | Native OS controls | BSD-3-Clause |

Their sources were already present in the isolated probe cache; pins and module
checksums are recorded in the probe's existing `go.mod` and `go.sum`. The three
candidate `go.mod` files declare no additional module requirements. This is source
inspection, not a new production build, complete license audit, security approval,
or proof that every required platform mechanism is available.

### Narrow adapters and contract tests

- JSONC normalization is not original-input validation. Retain the original-byte
  digest and field provenance, enforce input/depth limits, reject structural
  ambiguity and relevant duplicate keys, and validate accepted syntax separately.
- Source inspection of `jsonc.ToJSON` shows that its closing-container comma
  removal can also remove the comma in `{,}` or `[,]`. Those malformed inputs
  must not become accepted empty containers. These cases have not been executed
  in a new probe; require regression tests alongside valid comments, trailing
  commas, strings/escapes, invalid encodings, and unterminated comments.
- Parse and validate concrete versions before comparing parsed values. Do not
  treat `System.Compare` ordering invalid strings as a valid advisory comparison.
  Wildcards and missing concrete-version information cannot become versions.
- Neither the accommodating `DefaultSystem` parser nor npm constraint helpers
  independently define PackTrace's OSV semantics. Own the supported syntax and
  event evaluation; qualify ordering, prereleases, build metadata, invalid values,
  boundaries, and unsupported conditions. Do not replace OSV intervals with
  `MatchVersionPrerelease` or infer installed versions from declared constraints.
- `os.Root` is a containment building block, not the complete filesystem safety
  boundary: its documentation explicitly excludes protection against filesystem
  crossings, Linux bind mounts, `/proc` special files, and Unix device access.
  Native safeguards and their acceptance tests remain mandatory.

Adoption depends on passing the relevant contract tests and completing license,
notice, and security review. If a candidate requires excessive compensating code
or fails qualification, review its replacement rather than weakening contracts.
Do not add SCALIBR, a CLI framework, YAML, or a database by default. Approval does
not create a production module or authorize installation, probes, or toolchain
changes.

## 25. Filesystem-backed snapshot and object layout

**Approved direction:** immutable JSON/JSONL data and SHA-256-addressed objects,
without SQLite or a custom binary index.

- Use a user state directory outside the investigated root; allow an explicit
  `--state-dir` override. Section 29 defines platform defaults and CLI path
  resolution. Preserve the existing alias/safe-access
  requirements; a different path string alone does not establish separation.
- Store verified artifacts and intelligence blocks under `objects/`, using names
  derived from their digests rather than untrusted feed paths.
- Store small manifests under `snapshots/`; reference objects and record source,
  hashes, counts, and freshness timestamps. A digest identifies bytes, not
  publisher authenticity or independent trust.
- Partition matching projections into 256 JSONL blocks by identity hash. Stream
  required blocks instead of loading the complete feed into memory. Preserve
  enough identity information to verify a lookup, not merely a hash prefix.
- Keep original advisory records separate from matching projections and bind them
  by digest. Projections cannot discard relevant corrections or uncertainty.
- Publish the active manifest only after its required objects validate. Qualify
  native atomic publication, durability, and crash recovery; a generic rename
  call alone is not evidence that all requirements hold.
- Permit one writer per store and protect objects used by readers. Cleanup must
  account for surviving references and pins, not age alone. Apply section 22's
  preview/authorization and active/previous-snapshot protections.
- Count objects, indexes, manifests, and staging under the approved 32 GiB global
  quota. Shared references must not become permission to delete still-used data.

### Explicit scan read accounting

The 256 MiB target-metadata budget covers manifest/lockfile metadata reads, which
also count toward the 16 GiB target-read budget. Local intelligence is separate:
**8 GiB of actual reads per scan**, including verification and rereads. Local
reference reads retain their separate section 21 budget. The scan deadline,
soft targets, resident guard, and global storage quota continue to apply.

Block scanning trades some I/O for a simpler format. Measure against the existing
benchmark before changing the index or adding a database. A limit or benchmark
failure is not authorization to increase budgets silently.

**Required acceptance coverage, not yet executed:** projection/original bindings,
complete candidate retrieval, identity-hash collisions, required-block corruption,
read/reread accounting, bounded streaming, interrupted publication, writer/reader
coordination, and reachable/pinned-object protection. Exact manifest/projection
schemas, hash encoding, reservations, locks, and recovery mechanisms remain to be
specified and qualified.

## 26. Supervisor/worker wire contract

**Approved transport:** versioned JSONL over private stdin/stdout pipes. No socket,
RPC framework, or additional dependency is required.

Each envelope carries protocol version, sequence, message type, and a typed
payload. Validate the worker's version/build handshake before sending target
configuration. This consistency check is not binary authentication or a sandbox.
Use the same trusted executable described in section 16.

Allowed message families are configuration, check start, evidence, observation,
relationship, finding/candidate, diagnostic, check closure, and run completion.
The full per-type fields and lifecycle state machine belong in the written spec.
The channel is internal, not a public extension or generic command interface.

- Enforce 1 MiB per message and 64 MiB cumulative traffic **across both
  directions**, including separators and actual encoded bytes. Keep captured
  stderr under its separate 64 KiB cap. Do not allocate from unchecked lengths.
- Reject duplicate JSON keys, unknown types, unsupported versions, invalid
  sequences, nonexistent references, and contradictory check closures. Bound
  decoding before accepting records into the result model.
- Do not transmit complete original input files or introduce generic fragmentation
  to bypass message limits. If required evidence cannot be represented within
  the bounded schema, emit a limit diagnostic and leave affected coverage
  incomplete rather than silently losing significant data.
- The worker cannot select output redaction, accept exceptions, decide the public
  exit code, or instruct the supervisor to download, mutate targets, or delete
  files. Those actions are not worker message capabilities.
- Preserve previously validated results only while their supporting evidence
  remains valid. A later invalidation cannot leave a confirmed result based on
  evidence that failed verification. Unclosed or invalidly closed checks remain
  incomplete after truncation, panic, timeout, or protocol failure.
- Require coherent check closures, a valid run-completion message, EOF, and normal
  termination before accepting successful execution. Neither a completion message
  nor process exit `0` independently proves coverage. Preserve independently
  completed work without disguising an abnormal run as overall completion.
- With a usable requested report, protocol failure makes required execution
  coverage incomplete and ordinarily returns `3`; inability to produce the
  requested report returns `2`. Existing interruption semantics and exit
  precedence remain unchanged.
- Never forward raw stderr. Replace error text not certified for output with
  controlled codes/diagnostics, and apply the common privacy/escaping rules to
  any rendered error information.

**Required acceptance coverage, not yet executed:** invalid/oversized envelopes,
partial lines, sequence/reference errors, duplicate keys, mismatched builds,
contradictory closure, a false completion followed by panic or extra traffic,
interruption, backpressure, pipe failure, cumulative limits, and sensitive errors.

## 27. Native feasibility gate

**Approved next design step:** prepare a bounded native feasibility probe plan
before fixing the unresolved filesystem/resource mechanisms in the consolidated
specification. The user selected this over further source-only exploration or
changing macOS scope. Retain all five native targets and the mandatory safeguards;
no unsafe fallback or reduction in qualification requirements was approved.

The [Probe B plan](native-safety-probe.md) starts with macOS safe file opening,
then expands only if a credible mechanism is available. It also covers portable
memory observation and process termination. The user subsequently approved the
written scope, limits, and stop conditions **only**. Prototype creation, runner
setup, privileged actions, downloads, and execution remain separately gated and
are not authorized.

The user reports that no macOS 15 runner is available. Native macOS execution is
blocked by that prerequisite; it was not attempted and did not fail a test.
Independent design work may continue, without reducing the matrix, changing the
probe order, or treating another platform as a substitute.

Source inspection identified reasons not to assume feasibility:

- `Lstat` before opening and `Fstat` afterwards can detect a type substitution too
  late to prevent a device-open side effect. Nonblocking/event-only flags are not
  established metadata-only guards. The pinned XNU `spec_open` inspected in the
  probe plan does not have an `O_EVTONLY` bypass of device driver opening.
- Linux cgroup charged memory, Windows Job committed memory, process resident
  samples, and Go soft targets are different quantities. Late placement into a
  cgroup/Job does not establish startup-wide accounting; Linux also documents
  temporary `memory.max` overruns.

These are source-level constraints, not native qualification results or proof
that macOS support is impossible. No production mechanisms, build changes, extra
dependencies, production limits, or strict-mode availability are selected by this
plan. Keep its approved probe budgets separate from production budgets.

## 28. Core scan command and argument validation

**Approved interface:** `packtrace scan [options] PATH`. This is a command contract,
not an implemented CLI or approval of the complete specification.

| Option | Values and default |
| --- | --- |
| `--manager` | `auto` by default; `npm`, `bun`, or an explicit profile below |
| `--checks` | Comma-separated `malicious`, `vulnerability`, `integrity`; all three by default |
| `--fail-on` | `none` or a comma-separated category list; without policy requirements, `none` by default |
| `--format` | `terminal` by default; `json` or `sarif` |
| `--privacy` | `portable` by default; `local` if policy permits |
| `--policy FILE` | Explicit static JSON policy; no automatic discovery |
| `--state-dir DIR` | Override the external managed-store location from section 29 |
| `--output FILE` | A new output file; `-` means stdout and is the default |

Inventory remains a prerequisite, not an optional `--checks` category. Separate
preparation commands and selectors/formats for local references and snapshots
still require specification; this section does not invent their interfaces.

### Manager selection

- `auto` retains section 19's unique/coherent-interpretation requirement. `npm`
  and `bun` restrict the family but do not resolve remaining version ambiguity.
- Explicit interpretation profiles are `npm@8.19.4`, `npm@10.9.4`, `npm@11.6.2`,
  `bun@1.3.2`, and `bun@1.4.2`. If family selection remains ambiguous, require an
  explicit supported profile rather than assuming the newest anchor.
- A profile declares how to interpret evidence. It is not producer proof, a
  package-manager invocation, a version-resolution request, or an expansion of
  qualified support. Never download or run that manager.
- Preserve target `packageManager` hints, observed structure, and conflicts
  separately from the operator's choice. Selecting a profile cannot make an
  unsupported format or relevant incompatible semantics supported.
- Unknown profile values are invocation errors (`2`). Unsupported target input
  discovered under a valid selection is evidence/coverage failure, not permission
  to silently change profiles or discard observations.

### Parsing, policy, and output

- Require exactly one `PATH`; never substitute the current directory implicitly.
  Place options before `PATH`, and support `--` to terminate option parsing.
- Reject repeated options, unknown values, empty category lists, duplicate list
  entries, and extra positional arguments. `none` cannot be mixed with enforcement
  categories. Reject enforcement for checks excluded from the effective scope.
- Omitted/default values do not disable trusted-policy requirements. An explicit
  setting that weakens them fails validation with `2`; preserve section 6's
  policy-authority limitation and provenance rules.
- `--output FILE` must not overwrite an existing file. Do not add an initial
  `--overwrite` escape hatch. An existing/unsafe explicit destination is an
  operational output failure (`2`), not a reason to silently switch to stdout.
  Safe no-clobber publication under races still requires native qualification.
- Apply the shared privacy and escaping rules to invocation errors; do not echo
  raw arguments or unfiltered parser error text into output.
- No `--online` option exists. `--help` and `--version` do not investigate the
  target, initialize state, or fetch data. Existing scan exit semantics apply to
  scans, not to a successful help/version display.

**Required acceptance coverage, not yet executed:** argument count/order, `--`,
repeated options, invalid/duplicate/empty category lists, unsupported profiles,
family ambiguity, explicit interpretation without invented producer provenance,
policy/default precedence, excluded enforcement, protected output destinations,
no-clobber races, error privacy, and help/version without investigation.

## 29. Default state directory and CLI path resolution

**Approved default:** `os.UserCacheDir()/packtrace`, with explicit `--state-dir`
override. This uses the Go standard library, not a new path/configuration library.

| OS | Default location |
| --- | --- |
| Linux | `$XDG_CACHE_HOME/packtrace`, otherwise `$HOME/.cache/packtrace` |
| macOS | `$HOME/Library/Caches/packtrace` |
| Windows | `%LocalAppData%\packtrace` |

- Resolve relative CLI path arguments against the invocation working directory,
  not the investigated `PATH`. Keep this base stable across worker startup.
- Require an absolute default path. If the environment cannot supply one, require
  `--state-dir` rather than falling back to the target, current directory, or a
  silently chosen temporary store. An explicitly relative override uses the
  invocation-directory rule above.
- Lexical normalization is not a safety check. Validate managed state and explicit
  output destinations against the opened target and native alias protections;
  reject locations inside it or aliasing back into it. Required safeguards remain
  blocking when unavailable.
- A scan does not initialize a missing store or download its missing contents.
  Preserve observable inventory and represent unavailable intelligence/references
  as incomplete/not-run checks under the normal report/exit rules.
- State data does not supply an automatically discovered policy. Do not expand
  environment variables inside policy contents or execute configuration files.
  Platform environment variables used by `UserCacheDir` select a location, not
  policy authority.
- Verify restrictive permissions and store ownership; being beneath a user cache
  directory is not sufficient evidence of either. Concrete native checks remain
  part of the safety/storage specification.

### Retention boundary

PackTrace's active/previous-snapshot, reader, and pin protections constrain its
own cleanup. They cannot prevent deletion by the OS or unrelated tools. For
long-lived retention, choose persistent storage explicitly with `--state-dir`;
do not rely on managed cache as the sole copy of an irreplaceable trusted baseline.
A missing object remains unavailable, not fresh, safe, or automatically fetched.

**Required acceptance coverage, not yet executed:** platform defaults, missing or
relative environment paths, relative CLI paths with a different target root,
overrides, target aliases, missing/corrupt/inaccessible state, permission/ownership
failures, no configuration discovery, and external deletion without silent repair.

## 30. Remaining design work

The approvals above do not settle the following contracts:

- Per-format schemas, exact interpretation-profile behavior, and complete typed
  IPC payloads/lifecycle states.
- Exact filesystem, monitoring, termination, and strict-mode OS mechanisms,
  informed by the separately reviewed/authorized native feasibility work.
- Preparation/local-input command interfaces, complete policy/reference schemas,
  and their validation rules. Core scan arguments and default state locations are
  fixed above; additional selectors and input formats are not yet complete.
- Qualification of candidate dependencies, exact matching rules and
  source/classification/correction mappings, full licensing/notice review, and
  exact snapshot/update/reconciliation mechanics.
- Snapshot/manifest/projection schemas and hash encodings; native publication,
  quota/reservation/locking/retention/recovery mechanisms.
- Exact public-fetch requests, origin/mirror rules, DNS/proxy enforcement, baseline
  format, multi-digest handling, and per-layout integrity comparison rules.
- Concrete JSON/SARIF field mappings, canonical fingerprint encodings, redaction
  field rules, exception schemas, and compatibility fixtures.
- Fixed benchmark corpus and executable acceptance checks.

These decisions authorize neither live synchronization nor artifact-fetch execution.
Review the remaining sections before producing the complete written specification.
Written-spec approval then permits implementation planning, not implementation.
