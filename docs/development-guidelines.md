# PackTrace development guidelines

## Status and purpose

These guidelines capture the project's confirmed engineering and security
constraints, together with recommended working practices. They accompany the
[development roadmap](development-roadmap.md).

They do not constitute approval of the detailed design or permission to create
production code, install product dependencies, execute compatibility probes, or
publish releases. Obtain the relevant explicit approvals first.

## 1. Product claims and terminology

PackTrace is a read-only project/dependency investigation CLI, not an endpoint
protection product or host-compromise detector.

- Keep malicious-package advisories, vulnerabilities, and integrity drift as
  separate categories.
- Never claim that a project or machine is safe or clean.
- Package presence does not prove malicious code executed.
- An integrity match does not prove code is benign.
- An empty findings list does not establish complete investigation coverage.
- Use scoped language, such as: "No known malicious packages detected in the
  inspected inventory," accompanied by coverage and snapshot information.
- Exit-code success means successful completion under the selected policy, not
  absence of threats.

## 2. Minimal architecture

Implement in Go as a standalone CLI and modular monolith. Keep implementation
packages internal; do not promise a public Go API.

Preserve these responsibilities without building a framework around them:

| Responsibility | Owns |
| --- | --- |
| CLI and orchestration | Validation, selected scope, cancellation, and resource budgets |
| Discovery and inventory | Effective lockfiles, workspaces, installed observations, and normalization |
| Threat intelligence | Explicit synchronization, local snapshots, freshness, and advisory matching |
| References and integrity | Reference provenance, digest validation, and file comparisons |
| Policy | Required coverage, finding enforcement, and reviewed exceptions |
| Reporting | Terminal, versioned JSON, and SARIF from one structured result |

Create packages when a working feature needs them, not as empty scaffolding.
Prefer concrete types and ordinary functions. Use interfaces only where genuine
substitution is needed, such as extractor and external-data boundaries.

Use filesystem-backed caches and advisory snapshots initially. Add a database
only after measuring a concrete storage or query problem. Use bounded worker
pools rather than a general task framework.

## 3. Inventory and evidence discipline

Keep three distinct observation classes:

1. **Declared:** dependency intent from manifests.
2. **Locked/resolved:** identities and resolutions recorded by lockfiles.
3. **Observed installed:** artifacts physically observed in the selected scope.

A lockfile entry is not proof of installation. An installed manifest is mutable
input supplied by the target, not independent authentication.

Preserve, where observable:

- Ecosystem, package name, version, resolved source, and alias identity.
- Workspace ownership and logical dependency relationships.
- Physical installed locations, including distinct instances of one identity.
- Artifact digests, algorithms, and the evidence source of each digest.
- Observation method, provenance, conflicts, and uncertainty.

Do not merge physical instances merely because names and versions match. Do not
invent dependency edges or workspace ownership when unavailable. Distinguish
logical dependency paths from filesystem paths.

Handle optional/platform-specific packages, bundled dependencies, links, multiple
versions, local packages, and non-registry sources explicitly. Expected absence
or unsupported relationships must not become unsupported malware conclusions.

## 4. SCALIBR and dependency adoption

Evaluate SCALIBR before writing custom inventory or lockfile parsers.

- Pin the evaluated revision and document its capabilities and limitations.
- Test relevant extractors against the approved compatibility matrix.
- Review API stability, transitive dependencies, licensing, platform behavior,
  partial-result semantics, and error reporting.
- Keep upstream types inside narrow adapters instead of coupling the result
  model to them throughout the application.
- Adopt only the extractors needed; do not enable unrelated scanning, network,
  resolution, or execution behavior by default.
- Implement custom handling only for demonstrated gaps.
- Preserve diagnostics: an extractor returning no packages does not necessarily
  mean successful inspection of an empty dependency set.

Do not reuse a library's source classification as network authorization without
review. The initially inspected SCALIBR npm extractor includes an HTTP URL
substring heuristic involving `npm`; that is not a trustworthy public/private
boundary. See the [upstream source](https://github.com/google/osv-scalibr/blob/main/extractor/filesystem/language/javascript/packagelockjson/packagelockjson.go).

Use the standard library first. Prefer maintained libraries for difficult format
and ecosystem semantics over incomplete homegrown implementations. Every added
dependency must have a concrete purpose and acceptable maintenance/license costs.

## 5. Offline behavior and privacy

Scanning makes no network requests by default. Keep network capability in
explicitly authorized synchronization/fetch paths rather than implicit helpers.

- Missing local intelligence or references makes applicable checks incomplete or
  unverified; it must not silently trigger a request.
- Provide distinct explicit operations/options for intelligence synchronization,
  public artifact fetching, and authorized online scans.
- Do not query public services with private package identities implicitly.
- Do not transmit source files, credentials, or local paths implicitly.
- Establish public/private/unknown source classification from explicit trusted
  configuration and validated source evidence, not package-name scope alone.
- Treat unknown classification conservatively; do not assume public access is
  authorized.
- Do not load registry credentials or execute configuration from the target.
- Restrict network destinations, redirects, connection duration, response sizes,
  and total network work. Never forward credentials to unrelated origins.
- Private dependencies use approved local references or a prepared local cache
  initially; authenticated private-registry fetching is out of scope.

## 6. Advisory data and matching

Keep malicious-package records and vulnerability records distinguishable even
when their formats, affected packages, or identifiers overlap.

- Evaluate OSV-format vulnerability intelligence and OpenSSF Malicious Packages.
- Record dataset selection, source URLs, licensing/attribution, snapshot identity,
  acquisition times, upstream timestamps where available, and freshness status.
- Measure dataset size rather than copying unverified estimates into guarantees.
- Validate data before atomically publishing a snapshot; preserve the last known
  good snapshot when updates fail.
- Handle incremental changes, withdrawals, corrections, and full reconciliation.
- Distinguish transport integrity, local digest checks, and source authenticity;
  computing a hash of downloaded data alone does not authenticate its publisher.
- Use ecosystem-appropriate affected-version semantics. Unsupported identities,
  versions, and ranges remain explicitly unmatched/unverified where relevant.
- Preserve the evidence for matches and the snapshot used. Do not silently
  reinterpret historical reports after an advisory changes.

Feed matches do not prove payload execution. Freshness policy affects coverage
independently of whether matches were found.

## 7. Reference and integrity trust model

Use two explicit assurance labels:

- **Lockfile-consistent:** the reference artifact matches the digest recorded by
  the project.
- **Independently anchored:** the expected digest comes from a user-designated
  trusted baseline outside the project's evidence, with provenance recording why
  that baseline is trusted and what it authenticates.

Merely placing a baseline elsewhere does not make it trusted. Neither level
proves benignness. An attacker changing both installed files and the lockfile can
defeat a lockfile-only comparison.

A lockfile integrity digest generally identifies the published archive, not the
installed directory. Verify the reference artifact first, then compare installed
content against the authenticated reference.

- An arbitrary local archive without a trusted expected identity/digest is not
  an authenticated reference.
- A mutable shared package cache is not independent proof.
- Missing or unavailable references remain unverified.
- Keep published files separate from package-manager-generated links and metadata.
- Report modified, missing, added, and relevant file-type/link changes.
- Record what was compared, excluded, unreadable, or unexplained.
- Preserve known patch/build context without executing scripts or reconstructing
  transformations automatically.
- Differences are evidence of drift, not automatic evidence of malware.

## 8. Untrusted-input and filesystem safety

Treat targets, metadata, archives, configuration, advisory data, and artifact
locations as untrusted inputs.

Never execute project/dependency code or executable configuration. Never run
install, build, lifecycle, test, or import operations against a suspicious target
as part of scanning. Do not request elevated privileges by default.

Do not modify the target tree. Keep reports, caches, temporary data, and downloaded
artifacts outside it; validate destinations so links cannot redirect writes into
the target.

Bound file size, total bytes read, archive expansion, entry counts, path depth,
concurrency, network duration, and total scan duration. Limit failures must affect
coverage rather than disappear silently.

Prevent path traversal, symlink/junction escapes, link cycles, and unsafe archive
handling. Handle absolute paths, platform-specific roots, conflicting entries,
and case/path collisions deliberately. String-prefix checks alone are not a
containment boundary.

Prefer archive inspection without extraction. If extraction is necessary, define
its containment, allowed entry types, and resource budgets before implementing it.
Never open device files, FIFOs, or other special files as ordinary package content.

Detect files changing during inspection and record their comparisons as unstable
or unverified. Document the limits of live filesystem observations; metadata
checks do not establish an immutable snapshot. Do not claim resistance to an
attacker who controls the host.

Avoid reading unnecessary secrets. Escape untrusted terminal text, and redact
sensitive paths/content in portable reports. No automatic remediation, deletion,
or quarantine.

## 9. Go implementation practices

Select and pin a supported Go baseline after checking dependency and platform
requirements. Keep builds reproducible and dependencies reviewable.

- Prefer readable concrete code over speculative abstractions and generators.
- Pass `context.Context` through potentially long operations and honor cancellation.
- Use bounded readers and explicit budgets at trust boundaries.
- Return contextual errors and preserve useful partial results with their errors.
- Never use an empty success result to hide parse, read, limit, or network failures.
- Do not panic on malformed external input; avoid silently recovering and claiming
  success after an internal fault.
- Avoid global mutable state and unbounded goroutine creation.
- Keep serialization deterministic where order is not semantically meaningful.
- Separate native filesystem paths from portable report/archive paths and test
  conversions on every supported platform.
- Do not introduce shell execution as a convenience for scanning.

Comment non-obvious trust assumptions and deliberate simplifications with real
ceilings. Do not add configuration, interfaces, or caching layers for speculative
future requirements.

## 10. Coverage, findings, policy, and reports

Make coverage part of the common result model from the first working slice.
Record attempted/completed checks, unsupported inputs, unreadable/changing files,
missing references, parsing failures, unavailable/stale intelligence, exclusions,
and the effect of those gaps on conclusions.

Each finding should retain a stable identifier, category, identity/source,
installed location, workspace attribution, known dependency path, evidence and
provenance, advisory/rule identifier, severity, confidence, next steps,
limitations, and exception status. Unknown fields remain unknown.

Severity describes potential impact; confidence describes strength of evidence.
Do not invent numerical probabilities. Explain confidence with evidence.

Terminal, JSON, and SARIF must be views of the same structured result, not separate
detection implementations. Version the JSON contract and validate SARIF. Define
stable fingerprints and evidence-sensitive acceptance behavior in the design.

Default CI adoption is report-first: completed scans can report findings without
failing CI. Operational failures and incomplete required checks have distinct
nonzero outcomes; configured policies may enforce findings. Specify precedence
when findings and incompleteness coexist before implementing exit behavior.

Project-local configuration must not silently weaken organization-approved policy.
Exceptions require a reason, expiry, narrow rule/advisory and package/version
scope, and artifact/file digest scope for integrity findings. Accepted findings
remain visible. Changed evidence must not inherit acceptance; expired or invalid
exceptions cannot suppress findings. Exceptions cannot verify unperformed checks.

## 11. Testing and compatibility evidence

Use table-driven tests for parsing, normalization, version matching, policy, and
exit outcomes. Use deterministic benign fixtures, inert malicious-advisory
records, and explicit expected observations. Never execute real malicious
packages to generate test data.

The test corpus must include:

- Supported npm/Bun versions and layouts, workspaces, aliases, links, bundled
  dependencies, multiple versions, and platform-specific package absence.
- Modified, added, missing, patched, generated, and file-type/link changes.
- Malformed input, unsupported versions, wrong/missing/untrusted references.
- Private-package privacy and offline network-denial tests.
- Withdrawn/corrected advisories, missing data, and stale snapshots.
- Permission failures, changing files, resource limits, and cancellation.
- Policy precedence, evidence changes, exception expiry, and exit-code combinations.
- JSON and SARIF schema validation and sensitive-data redaction.
- Go fuzzing for owned parser, archive, and path-handling logic.
- Actual Linux, macOS, and Windows execution, including relevant filesystem behavior.

Cross-compilation is useful but does not establish runtime support. Label matrix
entries planned, experimentally observed, validated, or unsupported, and attach
executed evidence to validated claims. Track locked versions separately from
observed installed instances in fixture expectations.

Performance checks need a fixed corpus, measured byte/file/package counts,
hardware class, cache conditions, wall-clock limit, and peak-memory budget.
Choose thresholds before implementation approval; report measurements, not guesses.

## 12. Development and review loop

For each approved implementation change:

1. Identify the behavior, trust boundary, and affected callers/data flow.
2. Add a reproducing test or fixture with a concrete expected outcome.
3. Confirm it fails for the intended reason when applicable.
4. Implement the smallest correct change.
5. Run targeted checks and the relevant broader regressions.
6. Review privacy, coverage, compatibility, and report-contract effects.
7. Update affected documentation and record limitations.
8. Commit approved changes progressively using `jj`, in small, scoped commits.
   Preserve unrelated work; do not substitute Git commits or publish automatically.

Once a Go module exists, baseline checks include:

```text
go test ./...
go vet ./...
```

Add race detection where supported, bounded fuzz runs, integration/security checks,
and native operating-system jobs as specified in the approved plan. These are
future checks; their presence here does not mean they have been executed.

Review parser, filesystem, network, integrity, and policy changes specifically for
false verification, silent coverage loss, and unintended trust expansion. Passing
unit tests alone is not a sufficient security review.

## 13. Documentation and release discipline

Keep project documentation inside `docs/`. This roadmap and these guidelines are
not substitutes for the subsequent approved design and detailed implementation
plan. Record material decisions and reasons without creating unnecessary process
artifacts.

Ship standalone binaries that do not require installation into the investigated
JavaScript dependency tree. Pin dependencies, document licenses, and provide
checksums plus verifiable signatures/provenance and verification instructions.
Test the release artifacts on the supported systems.

Do not claim reproducible builds, platform support, successful tests, validated
formats, or threat absence without the corresponding evidence. Clearly separate
verified facts, proposed choices, and unresolved decisions. Publication and
production implementation require explicit authorization.
