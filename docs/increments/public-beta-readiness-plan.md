# Public beta readiness and implementation plan

**Status: local planning proposal, not implementation or campaign authorization.**

**Goal:** deliver a useful, evidence-backed public beta on Linux and Windows with
bounded full npm/Bun investigation, genuine process completion, and pnpm explicitly
experimental. Preserve the current Go modular monolith, offline scan and native
capability boundaries; reuse existing engines, fixtures, runners and release tools.

**Tech stack:** existing Go1.27.1 internal packages, standard library, pinned YAML
adapter, filesystem-backed intelligence, native OS handles and `jj`; no new runtime
dependency or general-purpose qualification framework is proposed.

**Companion:** [static evidence matrix](public-beta-readiness-evidence.md).
**Existing contracts:** [engineering rules](../development-guidelines.md),
[design decisions](../design-decisions.md), [inventory](../inventory-compatibility.md),
[intelligence](../intelligence-compatibility.md),
[policy/exceptions](issue-8-trusted-policy-and-exceptions.md), and
[version policy](../releases/README.md).

## 1. Decisions and baseline

### Owner-selected requirements

- PUBLIC beta, not a closed-only beta; Linux and Windows both participate.
- npm/Bun form the beta core; pnpm remains partial/experimental. macOS is deferred.
- Actual complete scans must reach **0/1**. A permanently exit-3 diagnostic release
  does not meet this selected beta goal. Genuine incomplete scopes still return3.
- Bun needs a **bounded full flow**, including eligible advisories and valid-reference
  integrity. Candidates-only Bun is not an adequate substitution for this decision.
- Include the existing numeric performance target in section9 as a beta gate.
- These choices approve acceptance/planning scope only, not execution or deployment.

### Frozen inspection baseline

Integrated source: `c2ba5b93dc121ba7fd4615c11314203a947d1434`, tree
`cc73480cb264d9a929ad504c09a6c712297d3196`. Published alpha.2 source:
`1b8203e8172c5d9cc1aaab2a076f91e544dbc3d7`, tree
`c1cd127369dbf0609872b79a4a780cfaf12849ce`. The release differs in nine version/docs
paths; the only production Go change is the version string, not scanner behavior.
[Version PR113](https://github.com/landroval/PackTrace/pull/113) was rechecked OPEN
while preparing this plan. Integrating it needs its own authorization; publication
of the release did not merge it. Do not rewrite the immutable release tag.

The alpha.2 receipts record **5,904 passes, 7 skips, vet and154 owned Linux CLI
commands**. They are historical scoped evidence, not new executions during this
static audit. Its Windows executable is **cross-compiled only**. Closed native,
producer/acquisition campaigns and previous one-time review waivers grant nothing
here. A green PR or a closed capability issue is not beta acceptance.

## 2. Main findings and critical path

1. Current operational0/1 is unavailable: required native/resident coverage stays
   incomplete. Selected integrity and advisory coverage also have independent
   incomplete predicates. This is more than two booleans or stale wording.
2. Eligible advisory-origin qualification is npm-only. Bun candidate lookup exists,
   but it does not provide the newly required eligible Bun flow.
3. Native Windows acquisition/lifecycle code exists; the current Windows artifact
   has no runtime qualification. The old unfinished probe is not proof that all
   production Windows code is absent.
4. npm/Bun inventory, matching evaluators, reference comparison, intelligence,
   policies/exceptions and reporting already exist. Old unchecked shipping boxes
   must not be interpreted as instructions to rebuild those engines.
5. Public rights, security/support ownership, verification guidance and artifact
   authenticity need explicit decisions and documentation. Third-party notices
   are already packaged; they do not license PackTrace itself.

```text
B0 exact scope/current truth ──> B1 positive-completion/trust contract
                                  ├──> B2 bounded Bun eligibility ──> B3 completion integration
                                  └──> B4 causal acceptance assets ───────────┘
B0 ──> B5 native runner/readiness preparation ───────────────────────┐
B0 ──> B7 legal/security/docs/authenticity drafts ───────────────────┤
B2+B3+B4 ──> F freeze candidate identity (not publication) ──────────┤
F + approved campaign contracts ──> B5 native artifact acceptance ──┤
                                 ├──> B6 numeric benchmark ────────┤
                                 └──> B8 consented pilot ──────────┤
B5+B6+B7+B8 + independent review ──> B9 beta go/no-go and delivery
```

Pilot execution follows an initial passing owned-fixture/native baseline, not just
F. Candidate build/identity precedes artifact qualification; public release is NOT
its prerequisite. Fixes produce a new candidate and invalidate affected evidence;
no automatic rerun or renewed allowance follows. B5 setup can proceed before F,
but its final claims require the exact candidate. Shared production changes remain
single-writer, with fresh review at each independently testable package boundary.

## 3. Review focus and hard constraints

Five highest-risk cases must be pinned by acceptance work, not only prose:

1. Valid input is useful and can complete; equally plausible but ambiguous or
   unsupported input cannot be promoted into agreement, absence or a clean verdict.
2. Eligibility cannot come from a package name, target configuration, old policy
   pin, child boolean, exception, imported report or externally supplied receipt.
3. A successful comparison followed by failed output/close/query/reap changes final
   process status without rewriting emitted bytes or losing the first fault.
4. Windows desktop/native filesystem reality must match the claim: Server CI,
   emulation, Linux fixture replay and cross-compilation are different evidence.
5. A fresh-looking import, changed policy/evidence, unsupported store or unavailable
   metric must not inherit trust/freshness, repair itself, or fabricate a zero.

Mandatory throughout:

- Offline, read-only targets; no target scripts/config/hooks/install/repair or
  implicit network/source/store discovery. Explicit preparation stays separate.
- Retained originals, native leases, containment/disjointness, selected-lock/native
  witnesses, parent validation and frozen private policy/report authority remain.
- Generic hardlink refusal and the existing narrow Bun-cache allowance stay intact;
  completing Bun matching is not a generic shared-store or hardlink grant.
- Preserve `130 > 2 > 3 > 1 > 0`. Neither0 nor zero findings certifies safety.
- Exceptions affect enforcement, never evidence validity or required coverage.
- No cap increases, silent retries, privilege/security changes or missing-metric zeroes.
- No new package families, TUI/explorer, framework, dashboard, auto-updater or general
  artifact downloader is required by this plan. No complete pnpm or macOS campaign.
- Review report schema1.7 compatibility separately from application SemVer. Changed
  public reason strings/coverage/exit semantics are not automatically cosmetic.

## 4. B0 — Freeze exact beta claims and reconcile current truth

**Type:** decision/documentation. **Owner:** coordinator; no concurrent writers to
shared docs. **Depends:** none. **Output:** one approved support/acceptance contract,
not an invented runtime API or a blanket declaration of qualification.

**Files:** this plan/evidence matrix; later reconcile current-facing
`docs/design-decisions.md`, `docs/pre-1.0-features.md`,
`docs/development-roadmap.md`, `docs/inventory-compatibility.md` and EN/ES manuals.
Preserve dated increment histories, old failures and earlier narrow acceptances.

- [ ] Confirm/revise the proposed rows in section8, exact layouts/output modes,
  producer-evidence method, per-root filesystems and exclusions.
- [ ] Map each beta claim to implemented code, expected observation, evidence type
  and a PASS/FAIL/BLOCKED/NOT RUN acceptance cell; do not globally tick1.0 boxes.
- [ ] Record whether schema1.7 can express the B1 contract without changing its
  meaning; otherwise design an explicit compatible successor before implementation.
- [ ] Define the reference/prepared-intelligence workflow and source-trust decisions
  that a new user can actually perform without target execution or implicit grants.
- [ ] Handle PR113/version integration as a separately authorized prerequisite,
  preserving immutable tags. Do not duplicate its version/docs work.

**DoD:** the accepted contract includes genuine0/1, full bounded Bun, exact performance
target, Windows desktop status and every explicit exclusion. Historical count/schema
statements are labelled; current docs no longer claim the Go module/implemented
engines do not exist. No code gate, deployment, issue/Project state or security
configuration is changed by completing this documentary package.

## 5. B1–B3 — Close actual functional completion gaps

### B1 — Positive evidence and final-status design

**Type:** design-first, then separately approved implementation.
**Depends:** B0. **Single writer:** core reporting/execution owner.

**Existing interfaces:** `execution.RunScan`, `integrityscan.BuildReportWithPolicy`,
`RequiredCoverageIncomplete`, `ReportConditions`, `ScanRun.Checkpoint`,
`ScanRun.WriteReportOutput`, `ScanRun.Finish`, `cli.SelectScanExit`.

**Files:** `internal/integrityscan/{result.go,policy_report.go,advisory_report.go,intelligence.go}`,
`internal/execution/{scan.go,scan_lifecycle.go,scan_protocol_test.go}`,
`cmd/packtrace/{scan.go,scan_receipt_test.go}` and their existing tests.
The design may add a focused contract under `docs/increments/`; any new code
interface/signature is a design output, not assumed to exist in this plan.

- [ ] Specify positive completion predicates for EVERY selected required row:

| Obligation | Positive evidence needed; absence is not completion |
| --- | --- |
| Inventory | Usable selected interpretation; all admitted scope/instances accounted for; complete native inputs/traversal and original leases; unsupported/unstable parts remain gaps. |
| Malicious/vulnerability | Supported original category/activity/version interpretation, qualified explicitly admitted origin association and selected generation; full applicable scope accounted for, with no relevant unresolved index/source/read/limit gap. A qualified lookup with no known record differs from an unsupported or failed lookup; neither says benign. |
| Integrity/reference authority | Each required mapped instance/file has a validated reference and required assurance, actual native content/ownership and independent selected-policy binding. Missing/invalid/untrusted/ambiguous references do not become comparisons or nonapplicability. |
| Intelligence/access/freshness | Original generation/root binding, actual selected objects and valid independent freshness within the promised scope; import/pin/mtime cannot renew acquisition. State-usage observations stay unknown unless actually measured. |
| Native/tool qualification | Approved supported-target/source/artifact acceptance plus actual runtime prerequisites, bound through a reviewed parent-owned mechanism. No flag, env value, worker `Qualified` bit, JSON or user digest pin grants it. |
| Resource/execution | Observations successful for their stated window; actual output, joins, source checks and owned reap/finalization must satisfy the final caller decision. Sampling is not a hard-RSS guarantee or proof of unobserved closes. |

- [ ] Distinguish real nonapplicability from an unselected optional check and from a
  required unsupported case. Do not remove a required category merely to get0.
The PackTrace maintainer is the designated native acceptance authorizer. Acceptance must name the exact executable and tested runtime/root profile; a changed executable or profile, or revoked acceptance, leaves qualification incomplete. This design decision accepts no artifact and authorizes no key operations or campaigns.

- [ ] Define trusted qualification admission and invalid/stale/wrong-source,
  wrong-binary, wrong-platform/FS and forged evidence refusal before report sealing.
  Preserve rejection of child-granted authority and public JSON deserialization.
- [ ] Keep the public comparison snapshot honest: it exists BEFORE output/Finish.
  Specify actual final process adjudication and late2/130 overrides; do not claim
  the snapshot predicted successful future teardown or recursively render a final
  report to evade that ordering. Current sampling stops before later binding closes;
  any stronger lifetime guarantee needs a deliberate ordering design and tests.
- [ ] Review source-witness, policy, privacy, schema/reason-string and existing
  Intel/batch lifecycle compatibility before code changes.

**DoD:** every would-be completed row has a testable positive predicate and a
fail-closed counterexample; exact authority/data flow and compatibility are approved.
This is not a two-boolean patch or an operator qualification registry.

### B2 — Eligible Bun matching within a bounded source/layout contract

**Type:** identified implementation gap; design and regression checks precede edits.
**Depends:** B0+B1 source/coverage contract. **Writer:** one matching/policy owner.

**Files/interfaces:** `internal/integrityscan/{matching.go,matching_candidates.go,policy.go,policy_evidence_build.go,policy_material.go,policy_evaluate.go}`;
existing `MatchInventoryWithPolicyEvidence`, `indexedMatchingOrigins`,
`ValidateAdvisoryDecision`, `ValidateAdvisorySummary`, `BuildProjectEvidence`,
`EvaluatePolicy`; `internal/projectinventory/{wire_matching.go,wire_validate.go}`
only if the approved evidence closure needs it. Verify exact ownership/call impact
before changing shared symbols. Reuse the npm evaluator, source profiles and
reference engine; do not fork a second detection engine.

- [ ] Inventory the actual Bun tuple/source/native evidence available for the
  approved text versions/layouts and document its failure cases.
- [ ] Design an explicit reviewed origin/installed-association permission. Existing
  saved pins and npm-only grants must NOT silently gain Bun authority; any new
  material permission requires a consciously reviewed policy, not migration.
- [ ] Add RED cases for matching bytes/version but wrong origin, alias/peer/context
  ambiguity, conflicting selected lock/native manifest, missing witnesses, private
  source, stale/withdrawn/changed advisory and forged parent policy material.
- [ ] Implement only evidence-justified eligible Bun decisions and symmetric parent/
  material validation. Unknowns remain candidates or gaps, not enforced findings.
- [ ] Demonstrate one supported Bun malicious and one vulnerability positive/negative,
  plus valid-reference equality/drift; no promise for arbitrary Bun tuple/layouts.

**DoD:** admitted Bun cases have eligible results with original, category, scope,
source and native evidence; negative/ambiguous cases remain indeterminate. Old
policies retain their limits. Every new wire/material field is bounded and parent-
validated; no generic hardlink/store, workspace, reference or pnpm grant is added.

### B3 — Implement category completion and final operational0/1

**Type:** implementation. **Depends:** approved B1 and B2 evidence/material contract;
B4 assets can be prepared earlier. **Writer:** core owner; matching owner reviews.

**Files:** the B1 production files plus
`internal/integrityscan/{result_test.go,policy_report_test.go}`,
`internal/execution/{scan_protocol_test.go,scan_lifecycle_linux_test.go,scan_lifecycle_windows_test.go}`,
`cmd/packtrace/{scan_test.go,scan_receipt_test.go,policy_acceptance_scan_test.go,policy_output_scan_test.go}`.

- [ ] Add actual process acceptance for table7, including a complete default/core
  supported workflow, not only a pure selector or a manufactured report.
- [ ] Implement parent-owned positive predicates for inventory, BOTH advisory
  categories, integrity/reference, native/resource and selected state obligations;
  preserve3 for every genuine required gap and2/130 for final operational failures.
- [ ] Retain accepted findings, category distinctions, privacy and frozen-report
  anti-forgery; policy exceptions never manufacture qualification.
- [ ] Preserve final first-fault/resource/Wait/join/source-close/reap checks. If
  ordering changes, retest Intel maintenance and shared batch/writer behavior.
- [ ] Reuse existing full-root/vet/race, tamper, null/downgrade, output cancellation,
  wrong-witness and caller receipt cases; extend only missing behavior.

**DoD:** table7 is demonstrated end-to-end for admitted npm AND Bun profiles. No
operator/test switch can grant completion. Unsupported hosts/layouts still fail
closed; a good finding row cannot hide an unrelated required gap. New schema/API
meaning is documented and reviewed independently before integration.

## 6. B4–B5 — Acceptance and native evidence

### B4 — Reuse causal fixtures and add the missing acceptance links

**Files:** `cmd/packtrace/{full_matching_scan_test.go,matching_scan_test.go,policy_acceptance_scan_test.go,policy_integrity_acceptance_test.go,setup_scan_test.go}`;
`internal/intelstore/full_matching_fixture_test.go` and
`internal/execution/testdata/intel/README.md`. A focused new causal CLI test is
appropriate only if the existing tests cannot express the selected sequence.

- [ ] Freeze independently reviewed expected identities/locations/counts, source/
  snapshot/reference hashes, decisions, acceptance status, gaps and final exits.
  Scanner output must not serve as its own oracle.
- [ ] Use existing `full.bundle`/`corrected.bundle` and reference fixtures for initial
  match, corrected/withdrawn result, changed-original exception invalidation,
  unchanged-original retention, and an independently retained old generation.
- [ ] Cover exact freshness boundaries, stale/future/imported state, invalid archive/
  SRI/baseline, equality and modified/missing/added/type changes, benign optional
  absence, aliases/multiple physical copies, local/portable and SARIF behavior.
- [ ] Seed only owned inert copies; never alter consenting projects or execute
  malicious packages. A missing causal test is not a missing matching engine.

**DoD:** candidate/harness case ledger distinguishes each actual pass, failure,
blocked and not-run case, with expected ground truth, first fault and cleanup.
Candidate-only rows never become SARIF alerts. An external JSON/SARIF consumer
check is added only for the documented supported contract, without a new renderer.

### B5 — Prepare existing runners, freeze F, then execute approved native rows

**Files:** `.github/workflows/root-verification.yml`,
`probes/offline-integrity/ci/{linux_validation.py,windows_setup.py,windows_shards.py}`,
`probes/offline-integrity/ci/windowsrunner/{main_windows.go,shards.go}`,
existing nativefs/lifecycle tests and `cmd/packtrace/scan_receipt_test.go`.
No new generic harness is required. Audit the old opt-in
`probes/offline-integrity/qualification_test.go` separately; its deliberate partial
failure/Windows refusal is not proof the production backend is absent.

- [ ] Map existing source-test/fault-injection cases separately from externally
  observable packaged-executable cases. A different Go test binary is not the PE/ELF
  being distributed; a private test observer is not a new public receipt API.
- [ ] Resolve actual runner/desktop/hardware/native API and filesystem availability
  before campaign approval. Never enable privileges, recreate a deleted VM, mount
  disks, fetch SDKs or change security merely because a case is blocked.
- [ ] At F record source/tree, compiler/archive/flags, package/executable hashes and
  exact OS/build/host/process architecture/emulation and each root's FS/capabilities.
  Build a candidate for qualification without publishing it first.
- [ ] Approve exact fixtures, requests/downloads if any, launches, concurrency,
  time/storage/output limits, attempts/shards, watchdog and cleanup reserve. Existing
  32-MiB safety and 1-GiB benchmark corpora have DIFFERENT envelopes; never blend them.
- [ ] Run only the approved rows/cases: positive access, canary refusal, original-root
  fences, escapes/special/reparse/mount refusal where safely available, old/varying
  store identities, no target writes/execution/network, query loss, backpressure,
  deadline/interrupt and actual owned-process termination/reap/Job cleanup.
- [ ] Persist one exclusive dispatch intent before each approved attempt. Setup
  failure consumes its attempt. Preserve skips/failures; no auto-retry/profile or
  shard expansion. Ordinary CI and off-network build flags are not native/network-
  denial qualification.

**DoD:** section8's selected rows and table7 pass on exact candidate artifacts, with
separately labelled source/harness evidence for unobservable internal faults. Any
required absent capability is BLOCKED, not a passed skip. No current authority
exists to run these campaigns. A failing row blocks its advertised support claim.

## 7. Required actual process matrix

| Case | Expected final process outcome / independent assertion |
| --- | --- |
| Complete supported scope; report-first, no enforced unaccepted finding | 0; may contain findings, never means safe. Required evidence genuinely complete. |
| Complete scope; explicitly enforced eligible unaccepted finding | 1; actual finding and policy evidence retained. |
| Complete scope; properly accepted finding or report-only policy | 0; accepted finding remains visible; expiry/evidence change revokes acceptance. |
| Required missing/unsupported/ambiguous/stale/read/limit case, with or without findings | 3; retain findings and exact coverage impact, no false verification. |
| Invalid policy/input admission, writer/query/close/teardown/reap failure | 2 unless interrupted; preserve first fault and cleanup facts. |
| User interruption, including simultaneous incomplete/finding/output failure | 130, with bounded owned termination/reap. |
| Positive comparison followed by late output/source-close/reap/query failure | Final2 or130; previously emitted comparison bytes remain frozen and honest about their scope. |
| pnpm experimental, old unsupported hosts/providers/inputs | Retain documented partial/refusal behavior; never borrow core beta qualification. |

Use all16 existing selector combinations plus actual representative overlapping
process faults. Outer `go test` exit0 does not mean its child scan returned0.
The table does NOT demand that a pre-output JSON exit always equals a later final
process status: that would falsify the snapshot contract. Test each named scope.

## 8. Proposed initial platform rows — exact approvals still needed

Preserve the existing Windows11 desktop product target in design section2.
Server2022 is auxiliary CI, NOT a silent replacement. The audits' Server-only and
permanent-exit3 alternatives are rejected for this final proposal. Native x64
Windows11 is the preferred beta proof; a limited emulated alternative requires a
new explicit beta-scope amendment and honest architecture labels.

| Row | Proposed claim and roots | Evidence / approval gate |
| --- | --- | --- |
| L1 | Ubuntu24.04, native amd64; local ext4 target, separate persistent ext4 state/config/reference/output roots; ordinary user | Confirm exact kernel/image/mount and UUID/export-handle support. Image name alone is insufficient. Exact-artifact core flow + native safety/resource checks. |
| W1 | Windows11 desktop, native x64 host/process; local NTFS target and separate NTFS state/config/references; stdout terminal/JSON/SARIF | Confirm actual build, hardware/API availability and ordinary-user fixture capabilities. Current Windows archive is compile-only. Privilege-dependent unavailable cases remain blocked. |
| W-CI | Existing WindowsServer2022 native x64/local-NTFS runner | Supporting source/race CI only, not desktop/artifact proof. No new runner provisioning implied. |

Initial artifact architecture proposal preserves the existing two amd64 assets;
arm64 is not silently added or called qualified. macOS remains deferred. Btrfs/XFS
have implementation or historical evidence, but extra FS/root combinations need
separate claims and native evidence. Read-only tmpfs/overlay target admission is
not durable state-store support; remote/ReFS/FUSE/removable storage is not implied.
Windows guarded `--output FILE` is not currently qualified; stdout-only is an
explicit permitted beta limitation unless separately added to scope. Shell
redirection is caller behavior, not guarded file publication. Windows producer
compatibility must distinguish Linux-generated inert replay from native producer
execution; approve the claim/evidence method without implying new producer grants.

## 9. B6 — Mandatory fixed performance and recovery qualification

**Owner-selected gate, from design section18; NOT a spending authorization.**

- Fixed corpus: **1,000 installed instances, 50,000 files, 1 GiB content** with
  prepared local intelligence/references and independently expected complete work.
- Reference environment: **4 vCPU, 8 GiB RAM, SSD**; record actual configuration.
- **Median of five complete executions ≤90 seconds.**
- **Conservative sum of individual supervisor/worker lifetime peak resident values
  ≤1 GiB.** It is not a portable hard runtime RSS ceiling. Include each actual role
  and writer in an approved measurement/lifecycle accounting contract.

**Files:** existing Linux/Windows runners and resource/lifecycle tests above;
`internal/nativeresource/` only for a demonstrated measurement gap. Reuse bounded
external receipt/capture mechanisms; no general benchmark framework.

- [ ] Before a run freeze exact corpus/expected work/hashes, state/reference IDs,
  cache-state protocol, repetitions, start/end boundaries through final reap/source
  close, native peak methods, artifact identity and all campaign budgets.
- [ ] Explain sampled live sum, simultaneous sampled maximum, sum of individual
  lifetime peaks, Go soft target and Windows Job commit separately. Do not use
  one as another; unknown peaks are not zero or a measured pass.
- [ ] Budget setup/cache/warmup and all repeats; record cold/warm conditions and
  interference. Do not disable security, change the host or inflate caps for speed.
- [ ] A skipped/limited/failed/incomplete run cannot become a fast passing benchmark.
  Capture wall-time, actual per-role memory, sample/query gaps, first fault, final
  exit and cleanup. Benchmark permissions are separate from small safety fixtures.
- [ ] Verify recovery/last-known-good behavior under owned interrupted/corrupt state
  scenarios; failure may not activate partial data or corrupt retained snapshots.

**DoD:** the agreed measurement method yields the required complete results on the
selected platform rows; all five runs and native limits are accounted for. If
measurement/runner capacity is unavailable or target fails, beta is blocked until
repair and fresh authority, or an explicit owner change to this requirement.
Current runtime limits remain: five-minute scan, existing shared I/O/IPC ceilings,
512/128-MiB worker/supervisor Go soft targets and sampled1-GiB resident stop. Do not
claim existing samples already establish independent lifetime peaks.

## 10. B7–B9 — Public readiness, pilot and release

### B7 — Rights, security/support, authentic delivery and EN/ES onboarding

**Can draft in parallel with B1–B5; final claims wait for actual acceptance.**

**Files:** root `LICENSE` and `SECURITY.md` only AFTER owner-approved wording/rights;
README/manual EN/ES, `docs/releases/README.md`, compatibility/current-roadmap docs.
Reuse existing packaging/verification/manual-update/rollback logic, not a new updater.

- [ ] Owner/legal choose project distribution/use/modification/contributor terms;
  retain Go/YAML/software and advisory-data licenses distinctly. No license is
  inferred from a public repository or selected by an agent.
- [ ] Owner supplies a real monitored confidential report route, triage owner,
  supported-version/maintenance and withdrawal policy and achievable response
  expectations. No fake email/SLA; users must not upload local reports/secrets.
- [ ] Choose artifact authenticity: approved detached-signature or CI-attestation
  identity and verifier are recommended for the public security tool. Keys/OIDC/
  permissions are separate security operations. An explicitly accepted unsigned
  alternative must disclose residual trust and cannot be labelled signed proof.
- [ ] Verify intended archive AND manifest names/counts/digests before execution,
  plus authenticity under the chosen route; reject altered/missing/unexpected assets.
  Supply runnable Nushell/Linux and PowerShell walkthroughs for cold install,
  explicit state/policy preparation, setup, useful scan, manual update and guarded
  rollback, without changing pins or deleting state to make an example work.
- [ ] Validate terminal/JSON/SARIF privacy/decision equivalence and documented schema
  consumption. Keep project checks separate from tool assurance and explain final
  process status, partial pnpm and unsupported output/storage cases.

**DoD:** a new user can follow each native-row walkthrough without an agent, target
execution, implicit downloads or secret sharing; rights/contact/authenticity and
known-limitations/support policy have real owners. Prior release notices already
exist; authenticity and project rights remain distinct pending decisions.

### B8 — Consented pre-public pilot (not a replacement for seeded ground truth)

**Proposed cohort, not authorized:** 5–10 known-benign consenting projects, 2–3
independent testers, npm and Bun represented. Proposed ceiling20 project scans
(one initial + one separately agreed clarification per project); exact allocation,
time/byte/output/data retention and preparation permissions need approval first.

After initial B4/B5 success, testers use the frozen candidate and independently
reviewed inventory expectations. Record useful outputs, completeness/gaps,
misleading interpretations, setup friction, false positives and unexplained missing
instances. Benign projects do NOT measure detection recall; positives are inert
fixtures. No install/repair of targets, broad uploads, auto-lookup or unconsented
local-report sharing. Default portable reports; local detail and sharing require
separate consent. Stop on writes, leaks, lost leases/reap, unbounded work or false
verification, preserve evidence and return to repair/review under fresh authority.

**DoD:** no unresolved Critical/High trust-boundary or data-loss/privacy/false-
verification defect in the declared scope, pilot findings triaged with independent
evidence and understood limitations. Lesser beta issues have owners and public
notes; a failed required safeguard cannot be relabelled low priority to pass.

### B9 — Candidate/release go-no-go

- [ ] All selected B0–B8 DoD and process/native/performance cells reviewed; exact
  artifact identity still matches. Rebuild/fixes require affected requalification.
- [ ] Independent source/security review plus artifact/operational acceptance, not
  just coding-agent synthesis, test totals, a green job or historical waivers.
- [ ] Validate per-GOOS notice inventory, exact archive bytes, source/tree/compiler/
  dependency flags, fresh executed counts, schema policy, verification instructions,
  actual Windows runtime evidence and immutable release refs/assets.
- [ ] Owner separately approves accumulated release version, publication/platforms,
  signing route and any local replacement. No beta tag is reserved by this plan.
- [ ] Preserve protected review gates. PR/CI approval does not authorize merge or
  bypass; previous waivers are consumed. No automatic alpha→beta rename.

## 11. Execution method, checks and permission boundaries

Use the existing skill patterns rather than a new process framework:

| Skill | Use |
| --- | --- |
| Ponytail | Reuse engines/runners/fixtures; smallest defect-driven changes; no speculative platform/PNPM expansion. |
| Writing plans / parallel agents | Independently reviewable packages, explicit dependencies and disjoint ownership; adapt to repo `docs/increments/` and `jj`. |
| Verification before completion | Fresh commands/actual outputs before claiming a task passed; a report or selector is not native acceptance. |
| Owned JS producer qualification | Preserve raw links/multiplicity and old failures; any new producer work needs fresh bounded approval. |
| GitHub/jj coordination + ordinary CI verification | Exact source/tree, scoped publication, reconstructed receipt evidence and separate merge authority. |
| Experimental release discipline | Exact artifacts/notices, truthful runtime scope, explicit authenticity/install and rollback decisions. |

Proposed parallel ownership: core owner B1/B3; matching owner B2; acceptance owner
B4; native/capture owner B5/B6; coordinator/public-doc owner B0/B7/B8/B9. At most
four active work streams; shared `matching.go`, `policy_report.go`, protocol and
workflow changes serialize through their owner. Reviewers may inspect independently;
OS/system work has only the principal as writer. No agents inherit execution grants
merely by being dispatched. Small scoped `jj` changes and fresh independent review
end each work package; Superpowers is optional guidance, not a mandatory harness.

**First recommended increment:** B0 + the documentary B1 contract/test inventory.
It closes ambiguity about every positive predicate, Bun authority and final report/
process semantics before any runtime gate changes. B5 environment availability and
B7 owner decisions can be investigated in parallel without campaigns.

Future commands below are examples ONLY, not executed by this planning task.
Use an already approved compatible pinned Go toolchain; set offline environment
before tests, freeze the source and approve test/campaign budgets. Tests compile
and execute code/write caches, so they are NOT read-only inspection.

```nu
with-env { GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off', GOWORK: 'off', GOENV: 'off', GOTELEMETRY: 'off' } {
  go test ./internal/cli -run '^TestSelectScanExit$' -count=1 -v
  go test ./internal/integrityscan -run 'TestPolicyReportOperationalIntegrityAndProvenance|TestRequiredCoverageAndComparisonConditions|TestBunCandidatesKeepOriginalTuplesAndOptIn' -count=1 -v
  go test ./cmd/packtrace -run 'TestScanFiveHundredPackagesDistinguishesInstalledAndLocalPrivacy|TestScanReceiptSurvivesFailedPublicOutput' -count=1 -v
}
```

Those existing cases are regression references, not proof of future beta0/1 or Bun
eligibility. Existing operational child scans expect3. Future B2/B3 acceptance
must add and run the actual new positive and negative process cases. Reuse full
`go test ./...`, `go vet ./...` and supported race suites after approved changes;
confirm named tests ran, not an empty filter or skipped capability.

### Permission ledger

Approved NOW: static multi-agent audit, scope decisions and local plan documents.
NOT approved: runtime implementation, tests/builds/benchmarks, new producer or
intelligence acquisition, SDK/tool downloads, real-project access, runner/VM setup,
privilege/security/credential/signing/workflow changes, native/CI dispatch, issue/
Project mutation, publication, merge/bypass or executable replacement. Subsequent
package approval must explicitly name which of those operations it authorizes.
No historic or unused allowance, setup failure or repaired helper resets a budget.

## 12. Planning validation and limits

Four focused static audits, one critical review and one synthesis supplied the
planning evidence. The principal checked key cited source and reconciled their
disagreements. Later owner decisions make
0/1, full bounded Bun and numeric performance REQUIRED, superseding the audits'
conditional suggestions. Windows Server-only was not adopted: preserve Windows11.
See the companion matrix for evidence scope and corrections.

This plan changes no product, historical evidence, policy, native environment,
release or skills. No new test/campaign result, safety verdict or beta qualification
is claimed. Exact rows, trusted completion design, Bun source permission, legal/
security/authenticity terms, corpus/measurement methods, campaign budgets, pilot
consent and final release remain explicit gates rather than invented facts.
