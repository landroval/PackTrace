# PackTrace development roadmap

## Status and approval boundaries

This document records the proposed development route for a usable team pilot.
It is not the detailed technical design, an executable implementation plan, or
approval to start production implementation.

Creating this documentation is authorized. Production code, dependency
installation, compatibility probes, publication, and releases are not authorized
by the existence of these documents.

- Review the design and detailed implementation plan before implementation.
- Obtain separate approval for the exact scope, inputs, and safety boundaries of
  any runnable compatibility probe before creating or executing it.
- Keep probe code isolated from production code; do not silently promote it.
- Do not claim that a format, platform, or security property has been validated
  without recording the relevant executed checks and results.

Read this alongside [the development guidelines](development-guidelines.md) and
[approved technical design directions](design-decisions.md). The latter records
post-probe decisions; it is not the complete specification or implementation plan.

## 1. Product goal and confirmed scope

Build a read-only, offline-by-default Go CLI that investigates existing JavaScript
projects for supply-chain threats. Distribute a standalone binary implemented as
a modular monolith with internal implementation packages and no public Go API
compatibility commitment.

The pilot must support and execute tests on Linux, macOS, and Windows. It must
cover npm and modern text-based `bun.lock`, including single projects and
workspaces/monorepos. Exact version and layout compatibility is a Phase 0 decision
and must be demonstrated before release.

Provide three distinct detection categories:

1. Known malicious-package advisory matches.
2. Known vulnerability advisory matches.
3. Installed-file integrity drift against authenticated reference artifacts.

Produce terminal, versioned JSON, and SARIF reports from one structured result.
Preserve evidence, confidence, provenance, limitations, and coverage. Findings
and coverage are independent: findings may exist in an incomplete investigation.

### Explicit non-goals

- pnpm, Yarn, and legacy binary `bun.lockb` support initially.
- Host-compromise detection, endpoint protection, and proof of payload execution.
- Generic suspicious-code heuristics, AI classification, or dynamic analysis.
- Installation interception, automated remediation, deletion, or quarantine.
- Hosted services, microservices, dashboards, or a public plugin SDK.
- Authenticated private-registry fetching in the first release.
- SBOM export initially.

Detect unsupported inputs and explain their impact. Never convert lockfiles or
install dependencies to make an existing target scannable.

## 2. Development strategy

Build the smallest complete investigation flow, then expand compatibility.
Introduce safety controls and coverage accounting with the first working slice;
do not defer them until release hardening.

Use ordinary internal Go packages, concrete types, filesystem-backed snapshots
and caches, and bounded concurrency. Reuse suitable SCALIBR extractors behind
narrow adapters. Write custom inventory or parser logic only for demonstrated
gaps. Avoid a database unless measured storage/query needs justify one.

## 3. Milestones

### Phase 0 — Agree on the investigation contract

**Purpose:** resolve decisions that materially affect correctness, security,
compatibility, or implementation cost.

**Scope and deliverables:**

- A technical design covering architecture, data flow, trust boundaries,
  normalized observations, CLI/configuration contracts, and report schemas.
- An explicit compatibility matrix: package-manager versions, lockfile versions,
  workspace structures, installed layouts, operating-system versions, and CPU
  architectures. Distinguish planned, experimental, validated, and unsupported.
- Decisions on required checks, source classification, explicit network
  authorization, freshness policy, resource limits, and trusted baselines.
- A precise exit-code contract covering report-first behavior, enforcement,
  operational failure, incomplete coverage, and findings coexisting with gaps.
- Policy precedence and narrowly scoped, expiring exceptions.
- A proposed compatibility probe and a phased implementation plan with runnable
  acceptance checks. Revise the design and plan after probe evidence if needed.

**Demonstrated checks:** review each requirement against a design section and
acceptance check. Identify unresolved decisions explicitly; do not pretend that
review establishes runtime compatibility.

**Known limitation:** no supported format or platform is yet validated.

**Completion criterion:** the design, compatibility targets, and detailed
implementation plan receive explicit approval. Probe approval alone does not
meet this gate.

### Phase 1 — Evaluate and prove inventory compatibility

**Purpose:** determine whether SCALIBR can supply the required observations.
An approved isolated probe may occur during Phase 0 before final design approval.

**Scope:** evaluate the npm lockfile, Bun lockfile, and package-manifest extractors
at a pinned revision. Assess their APIs, dependency footprint, licenses, partial
results, diagnostics, platform constraints, and ability to retain required data.

The proposed probe must cover:

- npm lockfile versions selected for the matrix and npm-shrinkwrap precedence.
- Modern Bun lockfile versions, configuration variants, hoisted layouts, and
  isolated layouts selected for the matrix.
- Single projects, workspaces, aliases, multiple versions, optional/platform
  dependencies, local/workspace links, bundled packages, and non-registry sources.
- Declared dependencies, locked/resolved dependencies, and actually observed
  installed packages as separate evidence classes.
- Identity, resolved source, workspace ownership, known logical edges, physical
  locations, digests and their sources, observation methods, and uncertainty.
- Malformed input, unsupported versions, partial extraction, and limit failures.
- Actual execution on Linux, macOS, and Windows.

**Safety boundary:** use checked-in synthetic or pinned known-benign fixtures.
Invoke extractors only; never install, build, test, import, or execute dependency
code from an investigated target. Any package-manager operation needed to
create additional fixtures must be described and approved separately. State
whether fetching the pinned probe's own Go dependencies is permitted.

**Deliverable:** an adoption/gap report mapping each required field and matrix
entry to evidence. Reuse suitable extractors; propose minimal custom handling
only where evidence demonstrates a gap.

**Known limitation:** a successful lockfile parse is not evidence of installation
or of complete dependency relationships. An installed manifest is untrusted.

**Completion criterion:** required fields and compatibility rows have recorded
results or explicit gaps, and the chosen adapter/custom-handling approach has
been incorporated into the approved design and plan.

### Phase 2 — Deliver the first offline investigation slice

**Purpose:** make a narrow end-to-end scanner useful without overstating results.

**Scope:** safe discovery, normalized inventory, offline advisory matching,
coverage accounting, a terminal report, and versioned JSON. Begin with approved
baseline layouts, then cover the remaining pilot matrix entries.

Evaluate OSV-format vulnerability data and OpenSSF Malicious Packages. Design
explicit synchronization around selected datasets, measured download/storage
sizes, source authenticity, transport integrity, licensing, and redistribution.
Support atomic snapshots, last-known-good recovery, timestamps, freshness,
corrected/withdrawn records, incremental updates, and periodic reconciliation.
Scans must not synchronize implicitly.

**Demonstrated checks:**

- Execute with outbound networking denied and prepared local data.
- Match exact versions and affected ranges, including relevant npm prerelease
  semantics; test nonmatches and unsupported version forms.
- Exercise withdrawn/corrected records and stale, missing, or malformed snapshots.
- Verify that lockfile-only packages are not labeled observed installed.
- Verify that parsing failures, exclusions, and unreadable inputs affect coverage.
- Preserve findings when another check is incomplete.

**Known limitation:** advisory matches reflect the selected sources and snapshot;
they do not prove execution or establish complete knowledge of threats.

**Completion criterion:** approved inventory and matching fixtures pass, with
correct coverage and evidence in both terminal and JSON output.

### Phase 3 — Add reference validation and integrity comparison

**Purpose:** compare installed content while keeping authenticity separate from
benignness.

**Scope:** user-supplied local artifacts, prepared caches, explicit public
artifact fetching, digest validation before comparison, and two labeled levels:

- **Lockfile-consistent:** the reference artifact matches the project's digest.
- **Independently anchored:** the expected digest is supported by a user-designated
  trusted baseline outside the project's evidence, with recorded trust provenance.

Report modified, missing, added, and relevant file-type/link differences.
Separate published files from package-manager-generated layout metadata. Include
known patch/build context without executing or reconstructing transformations.
Prefer archive inspection without extraction.

**Demonstrated checks:**

- Reject incorrect reference digests and leave absent/untrusted references
  unverified; an arbitrary archive is not an authenticated reference.
- Detect every supported injected change class.
- Exercise traversal, duplicate/conflicting archive paths, unsafe links,
  expansion limits, changing files, and case/path collisions.
- Verify destination and redirect restrictions during explicit fetching.
- Verify private-source handling never invokes public lookup implicitly.
- Confirm generated files and intentional patches are not labeled malware merely
  because their contents differ.

**Known limitation:** neither assurance level proves benignness. An attacker who
changes both installed files and the lockfile can defeat lockfile-only checks.
Mutable shared caches do not provide independent proof.

**Completion criterion:** comparison outcomes identify the authenticated
reference, expected-digest provenance, exact comparison scope, and limitations.

### Phase 4 — Complete policy and reporting contracts

**Purpose:** make investigations predictable in team and CI workflows.

**Scope:** report-first defaults, optional finding enforcement, distinct
incomplete/operational outcomes, organization-approved policy precedence,
evidence-bound exceptions, and SARIF from the common structured result.

**Demonstrated checks:**

- Test combinations of findings, incomplete required checks, operational errors,
  policy enforcement, and accepted/expired/invalid exceptions.
- Require reason, expiry, narrow advisory/rule and package/version scopes, plus
  artifact/file digest scope for integrity exceptions.
- Keep accepted findings visible; changed evidence cannot inherit acceptance.
- Ensure project-local settings cannot silently weaken approved policy.
- Validate JSON and SARIF; test fingerprints, provenance, redaction, and escaping.
- Confirm exceptions cannot convert unperformed checks into verified checks.

**Known limitation:** exit-code success describes completion under the selected
policy, not absence of threats.

**Completion criterion:** structured results, terminal summaries, SARIF, and exit
codes agree for every documented outcome.

### Phase 5 — Qualify the cross-platform pilot and release

**Purpose:** demonstrate actual support, acceptable performance, and verifiable
delivery.

**Scope:** execute the full supported matrix on native Linux, macOS, and Windows
runners; run security regressions and a read-only pilot on consenting projects.
Measure a fixed benchmark corpus under documented conditions.

Exercise platform-specific permissions, paths, case sensitivity, symlinks and
junctions, installation differences, cancellation, changing files, and report
output locations. Fuzz owned parser/archive/path logic. Run race detection where
supported. Verify scanner behavior without elevated privileges.

Deliver standalone binaries outside the investigated dependency tree, with
versioned source, pinned dependencies, checksums, verifiable signatures/provenance,
license notices, and documented verification/installation procedures. Publish
known limitations and the executed compatibility evidence.

**Known limitation:** pilot results apply to the stated corpus, platform matrix,
and investigation scope; they cannot prove all projects or machines safe.

**Completion criterion:** native platform checks pass, pilot thresholds are met,
release verification succeeds, and unresolved limitations are disclosed. Release
publication itself requires explicit authorization.

## 4. Proposed pilot acceptance criteria

These are acceptance targets, not measured results.

| Area | Criterion |
| --- | --- |
| Inventory | Every expected installed instance is identified in the supported fixture corpus; zero locked-only entries mislabeled installed. |
| Advisory matching | All reviewed matches and nonmatches pass, including range boundaries, withdrawals, and relevant prerelease semantics. |
| Integrity | Every supported injected change type is detected; zero false verification outcomes for missing, invalid, or untrusted references. |
| Benign scenarios | Zero malicious-package classifications caused solely by optional-package absence, generated content, or intentional patches. |
| Coverage | Every injected unsupported input, read/parse failure, exclusion, missing reference, freshness failure, and limit condition is represented. |
| Offline/privacy | Zero outbound requests in offline tests; no unauthorized disclosure of private identities, credentials, local paths, or file contents. |
| Policy/reports | All documented outcome combinations pass; JSON and SARIF validate and retain visible accepted findings. |
| Platforms | Required suites execute successfully on each claimed supported operating-system and architecture row. |
| Performance | Before implementation approval, fix the corpus, hardware class, cache conditions, elapsed-time ceiling, and peak-memory budget. Publish measured results before pilot release. |

A fixture pass rate is not a claim about real-world detection recall or false
positive rates. Review pilot findings against documented ground truth separately.

## 5. Detailed-plan requirements and approval order

The subsequent implementation plan must give each task a bounded scope, concrete
file responsibilities, runnable acceptance commands, expected results, known
limitations, and a completion criterion. Include security checks in the task that
introduces the relevant boundary.

The baseline Go commands below are planned checks, not currently executable
project tests: no Go module or production implementation has been created.

```text
go test ./...
go vet ./...
```

Add targeted integration, fuzz, network-denial, schema, and platform checks in the
detailed plan. Do not replace actual runtime evidence with cross-compilation.

Approval order:

1. Review the roadmap and development guidelines.
2. Review the technical design and material Phase 0 decisions.
3. Separately approve any compatibility probe before creating or executing it.
4. Record probe evidence and revise the design as necessary.
5. Approve the design and review/approve the detailed implementation plan.
6. Obtain explicit authorization to start production implementation.
7. Separately authorize publication/release operations.

## 6. Primary-source inspection and evidence status

Relevant primary sources inspected during the initial discussion:

- [SCALIBR npm lockfile extractor](https://github.com/google/osv-scalibr/blob/main/extractor/filesystem/language/javascript/packagelockjson/packagelockjson.go)
  contains npm-shrinkwrap precedence handling. This is a candidate behavior to
  test, not demonstrated compatibility with our matrix.
- [SCALIBR Bun lockfile extractor](https://github.com/google/osv-scalibr/blob/main/extractor/filesystem/language/javascript/bunlock/bunlock.go)
  exists for text-based Bun lockfiles. Its normalized output must be evaluated
  against our provenance, layout, relationship, and digest requirements.
- [SCALIBR package manifest extractor](https://github.com/google/osv-scalibr/blob/main/extractor/filesystem/language/javascript/packagejson/packagejson.go)
  is a candidate for installed metadata observations, not independent identity
  authentication.
- [SCALIBR README](https://github.com/google/osv-scalibr/blob/main/README.md)
  describes macOS and Windows support as experimental.

These links point to moving upstream branches. Pin a revision and record it in
the compatibility evaluation. No probe, product test, or platform execution has
been performed as part of preparing these documents.
