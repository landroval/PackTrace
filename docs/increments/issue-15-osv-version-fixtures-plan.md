# Issue 15: isolated SemVer qualification implementation plan

> **For agentic workers:** use `superpowers:executing-plans` for the preserved
> inline workflow only after the relevant written approval and explicit execution
> authorization. Checkboxes distinguish pending work from observed preparation.
> The user **approved this written plan and its documentary publication** in
> draft PR #29. This is not permission to create, acquire inputs for or run a probe.

**Goal:** hand off a reviewable fixture contract and a gated plan to determine whether
one pinned candidate is useful as a concrete-version primitive, without adopting it.
**Architecture:** provenance/static-source gate first; direct full-profile adoption
already fails that gate. An optional separately approved primitive-only experiment
may confirm gaps. OSV event/aggregation implementation is a separate later increment.
**Tech stack:** Markdown now; future isolated Go module, standard-library harness and
`deps.dev/util/semver v0.0.0-20260529052642-cf1e78d92744`. No root-module dependency.
**Spec:** [approved fixture contract](issue-15-osv-version-fixtures.md), published as
`6c17814c9ebe13b35a14f117fb066630a2c6ee36` in draft PR #29.

## Global constraints

- Current permitted work: prepare/publish this documentary plan and inspect already
  cached candidate source. No probe implementation, compile/execution, acquisition,
  ready/reviewer request, CI/native work or merge is authorized.
- Keep the approved specification and its 114 expectations unchanged: 34 syntax,
  16 precedence, 28 SEMVER range, 20 aggregation and 16 abstention cases.
- The specification remains fixture authority. A future runnable snapshot cites
  row IDs and its exact source digest; it cannot regenerate expectations with the
  tested candidate or quietly change them to accommodate observed behavior.
- Strict SemVer text, exact literal-list membership and field-specific sentinels
  remain separate. No trimming, prefix removal, case folding, constraint/minimum
  inference, wildcard concrete query or machine-integer coercion.
- `ECOSYSTEM` npm comparison is not qualified by selecting the library's `NPM`
  mode. Parsed objects and successful structure checks are not matching eligibility.
- No original-source sorting/deduplication or implicit-limit source fabrication.
  A future derived event view retains original indices; alternative limits are OR.
- Same-precedence mixed status transitions abstain under the approved policy.
  Unsupported conditions cannot produce no-match or cancel a qualified positive
  alternative silently; incomplete evaluation remains explicit.
- Read-only/offline investigation remains unchanged. Only synthetic probe inputs are
  contemplated; no investigated projects, package-manager execution or real corpus.
- Development base is `89a76e5f`; pending PR #28 source is absent. Do not stack this
  task on that PR. Unrelated native scanner qualification remains separate.

## Review focus

1. Reserved int64 infinity rejects a grammatical core component even at `2^63-1`;
   report a candidate gap, never a normalized/clamped version or negative match.
2. Large prerelease numerals can lose numeric classification and compare lexically;
   different digit lengths must expose this, not just equal-width O13 values.
3. Accommodating parsing can accept omitted components, wildcard/prefix syntax or
   numeric prerelease zeroes. Raw parse success must not become strict qualification.
4. `System.Compare` orders invalid strings and can return equality after errors;
   no semantic sign may be emitted when either input is unqualified/unparsed.
5. Build-precedence equality, raw text and unavailable input states are distinct;
   never use canonicalization/Compare==0 as list membership or coerce null to empty.

Each class is mapped to the future primitive/control cases below. This task does
not leave an executable harness, and documentary checks are not semantic tests.

## Preparation evidence: source gate, not measured behavior

Under the separate source-inspection permission, selected files in the old isolated
probe cache were read without importing, compiling or executing the candidate.
Module origin metadata identifies [google/deps.dev commit
cf1e78d92744bdb220ccd02343042c45df976523](https://github.com/google/deps.dev/tree/cf1e78d92744bdb220ccd02343042c45df976523/util/semver).
The module declares Go 1.23.4 and no additional requirements. Its cached ZIP contains
an Apache-2.0 LICENSE and no member named NOTICE; this is not a complete legal or
repository-wide notice/security audit.

Recorded historical checksums are in [Probe A go.sum](../../probes/scalibr-inventory/go.sum):

```text
deps.dev/util/semver v0.0.0-20260529052642-cf1e78d92744 h1:Yg6n3A1/2vjSzdCm3Dz66FzwW+InVa6oWfpHs6ACZj0=
deps.dev/util/semver v0.0.0-20260529052642-cf1e78d92744/go.mod h1:jjJweVqtuMQ7Q4zlTQ/kCHpboojkRvpMYlhy/c93DVU=
```

Observed local raw ZIP SHA-256:
`18550f3239007ed7980e3e6abcb52125d03d24f9e3a9d33042adbedbcac8269c`.
Selected extracted go.mod, LICENSE, version.go and interval.go bytes matched their
ZIP members. That consistency and a historically recorded checksum are not a fresh
checksum-database verification or complete authenticity/security proof.

| Selected source | Static evidence | Qualification consequence |
| --- | --- | --- |
| version.go: System comment/version parser | DefaultSystem is accommodating; parser permits fewer than three core components and wildcard versions | Standalone Parse cannot define the strict syntax profile |
| version.go: NPM prefix/number paths | NPM strips leading v characters and permits core leading zeroes | NPM mode is neither canonical syntax nor producer qualification |
| interval.go: value/infinity; version.go: parseNum | Core storage is int64; ParseInt uses 64 bits; values at or above reserved 2^63-1 are rejected | S10/O12 prevent direct full-grammar adoption; no silent finite cap |
| version.go: isNumeric/compareElem | Prerelease ParseInt failure loses numeric classification; comparison can fall back to text | Different-width large numeric comparisons need explicit confirmation |
| version.go: System.Compare | Invalid strings are ordered below valid strings; errors on both sides can yield zero | Never consume this sign as a qualified comparison |
| version.go: Version.Compare/String | Build is ignored by comparison; String returns original input | Retain text independently; precedence equality is not list equality |

**Current disposition:** direct, unguarded adoption for the approved full strict
profile is **rejected by static inspection**. No raw candidate behavior was executed.
A library-assisted subset, a compensating parser or a replacement would require a
separate design/specification decision; this plan does not silently choose one.
A primitive probe is optional diagnostic work, not a prerequisite for admitting an
already visible incompatibility and not a promise that compensation is worthwhile.

## Task 1: obtain review of the documentary handoff

**Current files:** create only this plan; the approved specification stays byte-for-byte
unchanged. No production signatures, Go files, JSON fixture artifact or shared milestone.
**Consumes:** the approved 114-row contract and selected static-source findings above.
**Produces:** this proposed qualification scope and independently reviewable dispositions.

- [x] Author self-review mapped every specification section against the coverage table.
- [x] Author self-review covered the five source-risk classes, provenance limits and
  direct-adoption rejection. Source inspection is not measured test execution.
- [x] Documentary ID/JSON/link/scope checks and Nushell parse-only checks passed;
  the approved specification and existing tracked bytes stayed unchanged.
- [x] User approved the written plan and separately authorized draft publication;
  push only the issue bookmark and verified documentary files. None of these
  checks/approvals is independent peer review or probe execution authorization.
- [ ] Obtain separate ready/reviewer-request permission and an agreed second-person
  reviewer for final-head PR #29. Review must cover both contract and future gates.
  Resolve authorized feedback without treating author review/request as approval.
- [ ] Obtain separate integration/queue-cleanup authority after final-head peer approval.
  Keep #15 Preparation until its own gates advance; no parent/shipping closure.

## Task 2: future source preparation — separately authorized, not run

**Proposed future workspace:** `probes/osv-semver-primitives/`, a separate module.
This directory is not created now and no original Probe A file is modified.
**Proposed files:** `go.mod`, `go.sum`, `README.md`, `.gitignore`, `probe_test.go`;
bounded observations/report belong to that probe's own evidence scope, not production.
**Consumes:** the fixed module pin, source provenance and fixture-document digest.
**Produces:** verified isolated source/cache inputs or an explicit preparation blocker.

- [ ] First obtain an issue-specific future probe specification, this plan's approval
  and explicit implementation/source-preparation authority. None is implied by #15
  assignment, documentary publication, plan approval alone or a cached artifact.
- [ ] Record exact authorized source input: reuse the verified existing cached ZIP
  only under the permitted preparation scope, or separately authorize reacquisition.
  Missing/different artifacts stop preparation; no automatic download or pin upgrade.
- [ ] For separately authorized network preparation, use the single fixed Go proxy
  without direct fallback, normal TLS/checksum validation, isolated HOME/caches and
  no private module/credential configuration. Never disable verification to unblock it.
- [ ] Verify module path/pin/checksums, selected source-to-ZIP consistency, module
  requirements, LICENSE/notices and selected import graph. Record unresolved legal/
  security/authenticity gaps. Raw ZIP SHA and Go h1 have different meanings.
- [ ] Use the approved local toolchain without auto-acquisition. Record its exact
  version/checksum/settings. The current go1.27.1-X:nodwarf5 host is development
  evidence, not official Go/native qualification; official acquisition is separate.
- [ ] Write the proposed isolated module only under future implementation authority:

```text
module packtrace-semver-probe

go 1.27.1

require deps.dev/util/semver v0.0.0-20260529052642-cf1e78d92744
```

The future module's go.sum contains the two pinned entries above. Root go.mod,
root dependency absence and all inventory/intel/CLI/probe-A bytes remain unchanged.

## Task 3: optional primitive experiment — separately authorized, not run

**Proposed file:** the future probe's `probe_test.go`, not internal/intel.
**Consumes:** literal S01-S34/O01-O16 from the approved specification plus the proposed
source-risk controls below; both `DefaultSystem` and `NPM` are diagnostic modes.
**Produces:** raw bounded observations, gaps and a report, never advisory decisions.

Candidate interfaces inspected in the selected source are:
`func (sys System) Parse(str string) (*Version, error)`,
`func (v *Version) Compare(o *Version) int`, and `func (v *Version) String() string`.
Both strings must parse successfully before Version.Compare is called; null remains
unavailable, not an empty string. Parse success alone is not canonical qualification.
System.Compare is excluded from semantic results; any diagnostic invocation must be
isolated and labelled unsafe-for-qualification, not used to fill missing pair signs.
No constraint/minimum helper or OSV range adapter is introduced by this experiment.

- [ ] Define/approve the future harness contract before writing it: fixed row ID,
  system mode, input kind/text, parse-success flags, nullable pair sign, original-text
  retention, terminal execution status and elapsed/size evidence. A null sign is not
  numeric equality. Candidate diagnostics are bounded and synthetic, not target data.
- [ ] Freeze literal expected outcomes independently; include all 50 S/O rows and
  make a fixture-snapshot drift check fail on ID/input/expectation changes. Leave the
  authoritative Markdown unchanged. Additional controls are proposed tests of the
  same approved grammar, not measured results or an amendment to the 114-row artifact.
- [ ] Observe behavioral RED for harness correctness: a zero/no-op capture must fail
  fixed row/flag/sign/state checks before trusting observations. Native candidate
  incompatibility is recorded as a gap, not made GREEN by changing reference answers.
- [ ] Build/run only the own synthetic harness under the verified isolation below;
  do not run upstream test suites, original Probe A extraction/graph code or targets.
- [ ] Use one bounded child per row/system. Record returned errors, panic, timeout,
  cancellation, protocol failure and not-run distinctly; do not replace them with a
  sign or no-match. Preserve previous valid observations alongside incomplete coverage.
- [ ] Exercise the five review-focus classes and perform temporary harness mutations
  for ignored parse errors, forced sign zero, null-to-empty coercion and text loss.
  Capture the failing control, remove mutations, then rerun authorized harness checks.
- [ ] Report normative case count separately from mode observations: 50 primary rows,
  two modes (100 planned observations), plus five controls/two modes (10 planned
  observations). These are planned quantities, not executed/passed Go test counts.
- [ ] Preserve all gaps; do not select whichever mode happens to pass a row. No
  successful subset establishes full profile compatibility or qualified npm semantics.

### Proposed source-risk controls

| ID | Exact input/pair | Normative expectation | Source risk |
| --- | --- | --- | --- |
| C01 | "9223372036854775806.0.0" | within-profile | Last finite core slot before reserved infinity |
| C02 | "9223372036854775807.0.0" | within-profile | Grammatical value at the reserved ceiling |
| C03 | "1.0.0-9999999999999999999" versus "1.0.0-18446744073709551616" | less | Unequal-length numerals, both outside signed int64 |
| C04 | null versus "1.0.0" | indeterminate, no candidate comparison | Preserve unavailability; never synthetic empty input |
| C05 | "1.0.0+one" versus "1.0.0+two" | equal-precedence, distinct original strings | Do not replace text with canonical/precedence identity |

### Proposed experimental bounds and safety gate

These values are proposals for the future probe approval, not existing measurements
or scanner/native qualification. No root privileges, persistent security changes,
new runners or automatic tool installation are permitted.

| Resource | Proposed bound/action |
| --- | --- |
| Overall preparation/build/run | 10 minutes; stop and mark unfinished work not-run |
| Child work/concurrency | 10 seconds per child; one child at a time |
| Linux verified transient cgroup | MemoryMax 512 MiB, MemorySwapMax 0; no elevated setup |
| Go runtime target | GOMEMLIMIT 256 MiB, soft only; does not replace cgroup limit |
| Source/cache scratch disk | 2 GiB; no silent eviction or growth |
| Explicit network preparation | 64 MiB cumulative if separately approved; offline run |
| Individual observation/stderr | 64 KiB each; excess is a failure, not silent truncation |
| Raw evidence/report total | 8 MiB; preserve limits/unfinished IDs visibly |

- [ ] Before any dependency code execution, verify existing unprivileged network
  isolation and cgroup controls with own control processes. Bind staged source/cache
  read-only, use dedicated writable scratch/output, and do not expose HOME, credentials,
  SSH agent, investigated trees or writable aliases to immutable inputs. No-route and
  write-denial controls must actually trigger. Unsupported isolation means NOT RUN,
  not unsandboxed fallback. These checks do not qualify PackTrace's target filesystem.
- [ ] Run future offline checks only inside that approved isolation and future module.
  The following is a command template for the later authorized harness, not a command
  to run during #15 documentary preparation:

```nu
$env.GOTOOLCHAIN = "local"
$env.GOPROXY = "off"
$env.GOWORK = "off"
$env.CGO_ENABLED = "0"
$env.GOMEMLIMIT = "256MiB"
# Inside the approved isolated probe workspace only:
go test -count=1 -json -timeout=2m ./...
go vet ./...
```

The outer wall/child/cgroup/evidence limits remain mandatory. Probe test names and
build details must be fixed in its own approved specification; no current command
creates that harness. Compile/runtime errors or resource stops are evidence gaps.

## Task 4: scope dispositions and later OSV work — not run

**Current deliverable:** documentary coverage mapping, not a new evaluator/API.
**Consumes:** all approved row IDs, static findings and any separately authorized
primitive observations. **Produces:** explicit supported/gap/not-run evidence and
future scope decisions; no automatic production dependency/adoption.

| Authoritative rows | Future primitive scope | Required later work |
| --- | --- | --- |
| S01-S34 | Raw parsing observations, not a strict parser implementation | Independently qualified concrete syntax/operational limits |
| O01-O16 | Parsed-pair precedence/error/state observations | Qualified comparison, no invalid-string fallback |
| R01-R28 | NOT RUN by primitive probe | Own SEMVER events/sentinels/ties/limits and source ownership |
| A01-A20 | NOT RUN by primitive probe | Exact list membership and complete/partial OR aggregation |
| U01-U16 | NOT RUN as OSV decisions by primitive probe | Header/layout/provenance/uncertainty guards; ECOSYSTEM/GIT abstention |

- [ ] Keep R/A/U's 64 cases explicitly outside primitive execution; input-kind controls
  do not claim to execute their advisory scenarios. Map every one to the later scope.
- [ ] A later OSV increment needs its own approved specification, exact interfaces,
  plan and explicit execution authority. Its consumed inputs must be unchanged,
  same-document header/affected evidence with digest/layout/index/ownership guards,
  independent all-slot version/range budgets and explicit incomplete evaluation.
- [ ] That later increment must test each R/A/U row and original-source snapshots;
  mutations must fail on fixed/last_affected boundary inversion, npm prerelease
  filtering, metadata membership conflation, minimum-limit intersection and original
  source sorting/tie dependence. This plan does not create or approve that software.
- [ ] Review complete evidence against the fixture contract and license/security
  obligations. Prefer rejection or a separately reviewed alternative over excessive
  compensation; limited support stays visible, never a weakened expected answer.
- [ ] Obtain peer review and separate publication/integration permissions for any
  probe report or later implementation. Report actual executed counts/toolchain,
  never sums of branches, planned observations or source inspection as passing tests.

## Plan review and current handoff

Current preparation inspected source/provenance only. It did not execute the candidate,
create the future module, download artifacts, run new Go tests or qualify a parser.
The supplemental controls and resource bounds require written-plan review; later
probe implementation/preparation/execution still need their separate approvals.

Plan self-review must confirm all 114 authoritative IDs are mapped, the five review
classes have proposed controls, every later phase is gated, and no missing work is
hidden by candidate rejection or a partially successful primitive probe. Current
validation is documentary: local links/anchors, ID ranges, examples' syntax and
unchanged existing tracked files. The preserved method is inline, not invented
subagents; no extra worktree/scaffolding is introduced for this documentary phase.
