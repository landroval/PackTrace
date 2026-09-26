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
total inventory is unknown. Policy aggregation and exit-code precedence remain
separate decisions to specify before implementation.

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

## 5. Remaining design work

The approvals above do not settle the following contracts:

- Component/data-flow details, effective-input selection, and per-format schemas.
- Exact filesystem/worker mechanisms and enforceable per-platform limits.
- CLI/configuration, required checks, policy precedence, and exit statuses.
- Intelligence sources, synchronization, matching, freshness, and licensing.
- Source classification, network authorization, references, and baseline trust.
- Report schema, fingerprints, redaction details, and evidence-bound exceptions.
- Resource/performance thresholds and executable acceptance checks.

Review these sections before producing the complete written specification.
Written-spec approval then permits implementation planning, not implementation.
