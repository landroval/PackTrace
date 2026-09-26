# PackTrace: features to ship before 1.0

## Purpose and status

This is the proposed pre-1.0 shipping checklist, derived from the confirmed
product scope. It defines what must be delivered, not how to implement it.
Check a top-level item only when its own acceptance criterion is met.
Documentation-only contracts may be checked with linked approved documentation;
that does not establish runtime implementation. Product behaviors and release
gates still require executed acceptance evidence. Checked nested milestones show
narrower progress and do not close their unchecked parent.

**Current evidence review:** two documentation contracts are complete; no executable
product capability is qualified for shipping. The internal npm v2/v3 reader and
typed-record projection pass synthetic tests; their narrower milestones, the bounded
Linux probe, and reviewed design/budget milestones do not establish full product
acceptance.

The first delivery target remains a usable team pilot. Develop the capabilities
incrementally during 0.x; do not label an intermediate inventory-only build as the
complete pilot. The required capabilities below belong in the pilot, with evidence
from pilot use informing readiness for 1.0. No additional speculative features are
required merely to reach 1.0.

Related documents:

- [Development roadmap](development-roadmap.md): sequencing and approval gates.
- [Development guidelines](development-guidelines.md): engineering and safety rules.
- [Approved design directions](design-decisions.md): reviewed decisions, not the
  complete specification or implementation plan.
- [Inventory evaluation results](inventory-evaluation-results.md): bounded probe
  evidence and explicit gaps.

Development now proceeds through small increments, each with an approved written
specification, implementation plan, and explicit execution authorization. Global
design completion is not a prerequisite for unrelated increments. Documentation
alone does not authorize probes, dependency installation, or publication.

## 1. Project discovery and dependency inventory

- [ ] **npm projects:** inspect the approved npm/lockfile versions, honor
  `npm-shrinkwrap.json` precedence, and report effective lockfile selection.
  - [x] Internal npm v3 byte reader implemented: raw-field preservation, original
    SHA-256, strict input rejection, size/depth bounds, 38 passing synthetic tests
    and `go vet`. See the [increment](increments/01-npm-v3-reader.md). Discovery,
    manager semantics, effective selection, and native/producer qualification
    remain open.
  - [x] The [v2/v3 extension](increments/02-npm-v2-reader.md) reuses that reader,
    preserves legacy and location-based data separately, and passes 103 root
    tests/subtests plus `go vet`. No reconciliation, installed-inventory, or
    producer/native support claim follows from this internal parser milestone.
  - [x] [Typed locked records](increments/03-npm-locked-records.md) preserve explicit
    scalar claims, four field states, source digests, and deterministic locations;
    enforce a 20,000-record projection bound. The root suite has 139 passing
    tests/subtests plus `go vet`; inferred identities, installation, semantic
    reconciliation, and matching remain outside this milestone.
- [ ] **Bun projects:** inspect modern text-based `bun.lock` versions and installed
  layouts in the approved compatibility matrix.
- [ ] **Workspaces and monorepos:** discover supported workspace structures and
  retain workspace attribution where actually known.
- [ ] **Separate evidence classes:** distinguish declared dependencies,
  locked/resolved dependencies, and physically observed installed packages.
- [ ] **Installed instances:** retain physical locations and multiple versions or
  copies rather than collapsing all packages with the same identity.
- [ ] **Dependency relationships:** report logical edges and dependency paths only
  when supported by evidence; preserve unknown relationships as unknown.
- [ ] **Source and identity provenance:** retain ecosystem, name, version, resolved
  source, available artifact digests and their sources, observation method,
  conflicting evidence, and uncertainty.
- [ ] **Dependency variants:** explicitly handle aliases, optional/platform-specific
  packages, local/workspace links, bundled dependencies, and non-registry sources.
  Unsupported verification remains explicit rather than producing invented results.
- [ ] **Unsupported input detection:** identify pnpm, Yarn, legacy `bun.lockb`, and
  unsupported format versions/layouts; explain their coverage impact without
  converting lockfiles or installing dependencies.

**Shipping condition:** locked entries are never presented as proof of
installation, installed manifests are not treated as independently trustworthy,
and expected optional-package absence is not classified as malware.

## 2. Known-threat detection

- [ ] **Malicious-package matching:** match applicable package identities and
  versions against selected malicious-package advisory data.
- [ ] **Vulnerability matching:** match applicable identities and affected versions
  against selected OSV-format vulnerability intelligence.
- [ ] **Ecosystem-correct matching:** handle approved npm version/range semantics,
  including boundary and prerelease cases; disclose unsupported matching cases.
- [ ] **Distinct categories:** keep malicious-package advisories, vulnerabilities,
  and integrity drift separate, even when they concern the same package.
- [ ] **Match evidence:** retain advisory identifiers, affected-version evidence,
  source provenance, snapshot identity, and freshness information.
- [ ] **Corrections and withdrawals:** incorporate changed or withdrawn advisories
  without silently retaining obsolete active findings in new scans.

**Shipping condition:** a feed match identifies reported exposure in the observed
scope; it never claims that a malicious payload executed.

## 3. Offline intelligence lifecycle

- [ ] **Offline scans by default:** investigate using prepared local intelligence
  and references without making network requests.
- [ ] **Explicit synchronization:** provide a user-authorized operation to acquire
  and update selected intelligence independently of scanning.
- [ ] **Documented sources:** evaluate OSV-format vulnerability data and OpenSSF
  Malicious Packages; record selected datasets, licensing, attribution,
  redistribution constraints, and measured storage/download sizes.
- [ ] **Reliable snapshots:** validate updates, publish atomically, and retain a
  last-known-good snapshot when synchronization fails.
- [ ] **Incremental updates and reconciliation:** incorporate modifications,
  withdrawals, corrections, and removals without indefinitely retaining stale data.
- [ ] **Freshness visibility:** report snapshot identity, acquisition and available
  upstream timestamps, freshness policy, and unavailable or stale intelligence.
- [x] **Source authenticity:** document the trust placed in data sources and
  transport, and distinguish it from locally computed integrity hashes.
  **Documentation evidence:** [approved source/trust contract](design-decisions.md#7-intelligence-acquisition-sources)
  separates acquisition source, publisher, HTTPS, and local hashes, and records
  aggregator limitations. This closes the documentation requirement only;
  runtime networking/authenticity controls remain unimplemented and unqualified.

**Shipping condition:** unavailable or unacceptable intelligence produces an
incomplete applicable check, not a successful no-findings result.

## 4. Reference artifacts and integrity comparison

- [ ] **Local references:** accept user-supplied artifacts or a prepared local cache,
  including references for private dependencies.
- [ ] **Explicit public fetching:** fetch missing public reference artifacts only
  with authorization and validated destination/source rules.
- [ ] **Explicit online preparation workflow:** provide separately authorized
  intelligence/artifact preparation followed by offline scanning, without weakening
  destination restrictions or private-package privacy rules.
  **Approved scope clarification:** [separate preparation, no online scan mode](design-decisions.md#23-online-preparation-scope-clarification)
  replaces the earlier integrated-online-scan wording; the workflow is not yet
  implemented.
- [ ] **Reference validation:** validate the artifact against an expected digest
  with recorded provenance before comparing installed contents.
- [ ] **Lockfile-consistent assurance:** label comparisons whose reference matches
  the digest recorded by the project.
- [ ] **Independently anchored assurance:** support user-designated trusted
  baselines outside the project's evidence, recording the provenance of the trust
  decision and the identity/digest that the baseline authenticates.
- [ ] **Modified files:** identify content differing from the validated reference.
- [ ] **Missing files:** identify reference files absent from the installed content.
- [ ] **Added files:** identify installed files absent from the reference scope.
- [ ] **File-type and link changes:** report relevant changes without following
  unsafe links or treating layout metadata as published artifact content.
- [ ] **Patch/build context:** preserve known intentional patch or generated-content
  context without executing scripts or reconstructing transformations.
- [ ] **Comparison scope:** state what was compared, excluded, unreadable, unstable,
  or unexplained, and identify unavailable or untrusted references as unverified.

**Shipping condition:** an arbitrary archive or mutable shared cache is not
independent proof. A lockfile digest generally authenticates the published
artifact, not the installed directory. Neither assurance level proves benignness;
changing both the lockfile and installed files can defeat lockfile-only checks.
Differences are not automatically classified as malicious.

## 5. Findings and coverage reporting

- [ ] **Terminal report:** provide a readable summary with findings and coverage
  presented independently.
- [ ] **Versioned JSON:** provide a documented machine-readable result contract.
- [ ] **SARIF:** generate valid SARIF from the same structured results.
- [ ] **Actionable findings:** include stable identifiers, detection category,
  package identity/source, installed location, workspace attribution, known
  dependency paths, advisory/rule identifiers, evidence/provenance, next steps,
  limitations, and exception status.
- [ ] **Severity and confidence:** represent impact and strength of evidence
  separately, without fabricated probability estimates.
- [ ] **Coverage accounting:** record attempted/completed checks, unsupported
  inputs, unreadable/changing files, missing references, parsing failures,
  unavailable/stale intelligence, and exclusions with their consequences.
- [ ] **Partial results:** retain findings when other checks fail or remain
  incomplete, subject to what can be safely reported.
- [ ] **Portable report privacy:** redact unnecessary sensitive paths/content and
  safely encode untrusted data in terminal and structured output.
- [ ] **Scoped conclusions:** distinguish an inspected inventory with no detected
  findings from an incomplete investigation; never issue a safe/clean verdict.

**Shipping condition:** terminal, JSON, SARIF, and process outcomes agree about
findings and completeness. An empty findings array cannot hide failed checks.

## 6. Team policy, CI, and reviewed exceptions

- [ ] **Report-first CI:** allow completed scans to report findings without failing
  CI by default.
- [ ] **Optional enforcement:** let approved policy enable finding-based failure.
- [x] **Precise exit-code contract:** distinguish operational failure, incomplete
  required checks, and enforcement outcomes, including precedence when findings
  coexist with incomplete coverage.
  **Documentation evidence:** [approved exit contract](design-decisions.md#5-scan-defaults-and-exit-codes)
  defines `0`, `1`, `2`, `3`, `130` and ordinary precedence `2 > 3 > 1 > 0`.
  Runtime behavior remains unimplemented; the policy/report acceptance gate below
  stays open.
- [ ] **Required coverage policy:** configure which checks and freshness
  requirements must complete; disclose exclusions and their effect.
- [ ] **Trusted policy precedence:** prevent untrusted project configuration from
  silently weakening organization-approved policy.
- [ ] **Scoped exceptions:** require a reason, expiry, and narrow rule/advisory plus
  package/version scope; require artifact/file digest scope for integrity findings.
- [ ] **Visible acceptance:** keep accepted findings in reports with exception status.
- [ ] **Evidence-bound acceptance:** prevent changed evidence from silently
  inheriting acceptance; expired or invalid exceptions must not suppress findings.
- [ ] **Coverage-preserving exceptions:** exceptions never turn an unperformed or
  incomplete check into a verified check.

**Shipping condition:** exit-code success means completion under the selected
policy, not absence of threats. Exact codes and configuration syntax must be
approved in the design rather than inferred from this checklist.

## 7. Mandatory scanner safety and privacy

These are required product behaviors, not optional hardening after feature work.

- [ ] **Read-only target handling:** do not modify the scanned tree; keep caches,
  reports, downloads, and temporary data outside it with validated destinations.
- [ ] **No target execution:** never execute project/dependency code, executable
  configuration, installation, build, lifecycle, test, or import operations as
  part of investigating a target.
- [ ] **Unprivileged operation:** do not require elevated privileges by default.
- [ ] **Bounded work:** enforce file-size, total-byte, archive-expansion, path-depth,
  concurrency, network-duration, and overall scan-duration budgets.
- [ ] **Safe cancellation:** honor cancellation and expose incomplete work rather
  than reporting successful verification.
- [ ] **Filesystem containment:** prevent path traversal, symlink/junction escapes,
  link cycles, and unsafe handling of special files or platform path collisions.
- [ ] **Archive safety:** prefer inspection without extraction; reject unsafe or
  ambiguous entries and enforce containment/limits if extraction is necessary.
- [ ] **Changing-file handling:** identify unstable observations and disclose the
  limitations of inspecting a live filesystem.
- [ ] **Restricted networking:** validate artifact destinations and redirects;
  never blindly fetch arbitrary lockfile URLs or forward credentials across origins.
- [ ] **Source classification:** establish public/private/unknown status through
  explicit trusted configuration and validated evidence, not scoped-name guesses.
- [ ] **Private-data protection:** do not implicitly send private identities,
  source files, credentials, or local paths to public services; avoid reading
  unnecessary secret contents.
- [ ] **No remediation side effects:** never automatically delete, quarantine,
  repair, or rewrite investigated content.

**Shipping condition:** malformed or hostile inputs cause bounded, explicit
failures or coverage gaps—not target execution, unauthorized access, or false
verification.

## 8. Platform support and standalone delivery

- [ ] **Linux support:** execute the required tests on supported Linux environments.
- [ ] **macOS support:** execute the required tests on supported macOS environments.
- [ ] **Windows support:** execute the required tests on supported Windows environments.
- [ ] **Published compatibility matrix:** state exact package-manager/lockfile
  versions, workspace structures, installed layouts, OS versions, and release
  architectures, with validation evidence and explicit limitations.
- [ ] **Standalone Go binaries:** distribute independently of the investigated
  JavaScript dependency tree; no hosted backend or public Go API is required.
- [ ] **Verifiable releases:** provide checksums, signatures/provenance, pinned
  dependencies, license notices, and installation/verification instructions.
- [ ] **Operator documentation:** explain offline preparation, explicit networking,
  reference trust, policy, exceptions, coverage, and result interpretation.

**Shipping condition:** cross-compilation alone does not establish platform
support. Validate actual release artifacts and document what was executed.

## 9. Evidence required before declaring 1.0 readiness

These are release gates, separate from the feature list. Do not mark a feature
shipped solely because code exists; link its executed acceptance evidence.

- [ ] **Approved design and implementation plan:** material compatibility, trust,
  configuration, report, and exit-code decisions are recorded and reviewed.
  - [x] **Design-direction milestone:** [reviewed decisions](design-decisions.md)
    record the approved contracts. The complete written specification and detailed
    implementation plan are still pending, so this gate remains open.
- [ ] **SCALIBR evaluation completed:** selected extractors are evaluated at a
  pinned revision for required observations, errors, platform behavior, API
  stability, footprint, and licensing; custom handling is justified by gaps.
  - [x] **Bounded Linux probe milestone:** [probe A and gap/adoption report](inventory-evaluation-results.md)
    evaluated the pinned extractors using synthetic inputs: 73 children executed,
    including three panics; two graph cases were blocked. This is not a passing
    product suite. Native macOS/Windows and producer-generated compatibility,
    broader platform assessment, and full licensing review remain outstanding;
    the broader gate stays open.
- [ ] **Inventory accuracy:** identify every expected installed instance in the
  supported fixture corpus, with zero locked-only entries labeled installed.
- [ ] **Detection correctness:** reviewed parser and matching tables pass,
  including range boundaries, aliases, withdrawals, and stale intelligence.
- [ ] **Integrity correctness:** detect every supported injected change type,
  with zero false verification for absent, invalid, or untrusted references.
- [ ] **Benign-case behavior:** optional-package absence, generated files, and
  intentional patches do not alone produce malicious-package classifications.
- [ ] **Coverage correctness:** every injected parse/read/permission failure,
  unsupported input, exclusion, reference/freshness gap, and limit condition is
  represented correctly, including changing-file cases.
- [ ] **Privacy/offline checks:** network-denial and private-package tests show no
  unauthorized requests or disclosure.
- [ ] **Policy/report checks:** verify exception expiry/evidence changes, exit-code
  combinations, and JSON/SARIF schema validity.
- [ ] **Adversarial-input testing:** use Go fuzzing for owned parser/archive/path
  logic and regression tests for containment and resource limits.
- [ ] **Native CI evidence:** run the required suites on Linux, macOS, and Windows;
  include workspace, link, permission, and platform-specific installation cases.
- [ ] **Measured resource use:** meet approved runtime and peak-memory budgets on
  a fixed, documented corpus and hardware/cache profile. Set numeric thresholds
  in the design before implementation approval, not after seeing results.
  - [x] **Budget-definition milestone:** [scan/benchmark targets](design-decisions.md#18-initial-scan-budgets-and-acceptance-targets),
    [intelligence budgets](design-decisions.md#20-intelligence-synchronization-budgets),
    and [reference budgets](design-decisions.md#21-artifact-preparation-and-reference-inspection-budgets)
    are approved. The exact benchmark corpus and production measurements remain
    pending; probe measurements do not close this gate.
- [ ] **Team-pilot review:** investigate consenting projects read-only, review
  findings against available ground truth, and document false positives, coverage
  gaps, usability issues, and unresolved limitations before release approval.
- [ ] **Release verification:** verify distributed artifacts and their provenance;
  obtain explicit authorization before publication.

Fixtures must be synthetic or pinned known-benign dependencies. Malicious-advisory
fixtures are inert data; never execute real malicious packages to create tests.
Fixture success is not a claim of universal detection recall or host safety.

## 10. Not required before 1.0

Do not expand this checklist with these items without a separate scope decision:

- pnpm, Yarn, or legacy binary `bun.lockb` support.
- Generic suspicious-code heuristics or AI-based malware classification.
- Dynamic execution, sandbox analysis, or proof of payload execution.
- Host-compromise detection or endpoint protection.
- Installation interception, automated remediation, deletion, or quarantine.
- Authenticated private-registry fetching.
- SBOM export.
- Hosted services, microservices, dashboards, or a public plugin SDK.
- A public Go API compatibility commitment.
- A database or elaborate task framework without demonstrated need.

## 11. Approved directions versus remaining qualification

The capabilities above remain the shipping target. The
[design-decision record](design-decisions.md) now settles substantial directions,
without establishing implemented or validated product support:

- npm/Bun anchors, baseline workspace/layout scope, and five native OS/architecture
  targets are recorded. Actual producer-generated and native qualification remain
  pending.
- OSV npm aggregation, update/reconciliation direction, 24-hour freshness, and
  seven-day full reconciliation are selected. Exact data handling and licensing
  review remain incomplete.
- Origin classification, explicit network authorization, baseline trust, and
  supported assurance digests have approved contracts; concrete mappings and
  native enforcement still need specification and tests.
- Scan/preparation budgets, benchmark targets, and a 32 GiB managed-storage quota
  with explicit historical cleanup are approved. Exact corpus, quota/retention
  mechanisms, and production measurements remain pending.
- Offline all-three-check defaults, explicit JSON policy, exit codes, JSON `1.0`,
  portable privacy, and evidence-bound exceptions are agreed. Complete schemas,
  encodings, worker protocol, and runtime behavior remain to be delivered.
- Each increment requires its own written-spec, plan, and execution approvals.
  The first three inventory increments completed that process; further increments and full
  product/release qualification are not implicitly approved.

Resolve remaining details through the roadmap's design and qualification process.
This checklist does not authorize implementation, a probe, downloads, or deletion.
