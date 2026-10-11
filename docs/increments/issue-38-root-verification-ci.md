# Issue 38: bounded root-verification CI installation contract

## Current preparation: native Git amendment approved; revised plan preparation

I selected **Simplificar con Git nativo** to prioritize completion of #38, then approved the complete written amendment through **Aprobar y adaptar plan**, at specification SHA-256 `022ae86be3bafc670452aef429ec525640221ca4d4c71f28f94735260eac9d75`. This approves that amendment and preparation/review of the revised complete plan, not installation, acquisition, hosted execution, publication, integration or closure. The Action-based specification and plan approvals retained below are historical approvals of that route; they do not approve the new native Git implementation. Current `development` was rechecked at `177e8e209b9ba53368323643a3e7c35fc1277606`; #23/PR #37 and the original #38 documentary PR #39 are integrated. The old base and pending-predecessor statements below describe their preparation checkpoints, not the live dependency state.

I subsequently approved the revised complete native plan and selected **Ciclo completo** with explicit scoped local validation, owned-process fixtures, limited official metadata, pinned SDK use inside hosted jobs, one independent technical reviewer and jsustt request, workflow-bearing PR publication, reviewed development integration/normal CI activation and accepted issue-38 closure/Done. Initial acceptance is bounded to five jobs of at most 15 minutes. The original protections/PR-only waiver, PR40, S64, parent/native gates and unrelated deletions remain unchanged. This is authority, not execution or qualification evidence.

## Historical approved Action-based contract

Status: **written specification and complete written plan approved; no execution/publication authority**. The
user approved this complete artifact, including its proposed evidence ceilings,
and separately authorized local complete-plan drafting for
[#38](https://github.com/landroval/PackTrace/issues/38). I keep it OPEN / Preparation, owned by `landroval`, under #11 and
blocked by #23 for implementation. I have not installed YAML, executed Go/hosted
jobs, acquired distributions, published this bookmark/PR or requested peer review.
The user subsequently approved only the complete written plan. Neither artifact's
approval grants adoption/acquisition, executable implementation or activation authority.

Base: integrated development `76ef90daf36c4b4fae2b234369859108440fc24e`.
I use the independent `issue-38-root-verification-ci-spec` bookmark/workspace.
Authority: [toolchain baseline](../design-decisions.md#24-toolchain-and-dependency-baseline),
[testing guidelines](../development-guidelines.md#11-testing-and-compatibility-evidence)
and [collaboration gates](../github-collaboration.md).

I refine the root-only subset of #23's owner-approved
[contract](https://github.com/landroval/PackTrace/blob/9c339943f69cde0a25b105bad34e30d5f327f751/docs/increments/issue-23-root-ci-parser-fuzzing.md)
and [blueprint](https://github.com/landroval/PackTrace/blob/9c339943f69cde0a25b105bad34e30d5f327f751/docs/increments/issue-23-root-ci-parser-fuzzing-plan.md).
Those artifacts are pending independent review in PR #37, not executed or adopted
CI. Reviewed #23 integration is required before this increment's implementation;
local preparation does not require pretending that review has occurred.

## Purpose, ownership and exclusions

I want repeatable evidence from root tests/vet on the exact owned source/toolchain/
runner, without bundling fuzzing or native qualification into the first workflow.
I keep the smallest executable delivery: **only**
`.github/workflows/root-verification.yml`, if later separately approved.

Current documentary ownership is this specification and its separately authorized
issue-keyed local implementation plan. Plan drafting followed approval of this
actual specification; executable delivery still has separate gates.
I do not create a workflow, helper script, Go test, receipt library, public schema,
fixture file or new dependency through this draft. Future inline workflow scripts
must be complete in the approved plan rather than invented at installation time.

I do not change existing readers/tests, go.mod/go.sum, shared states/CLI exits,
shipping milestones, branch rules/security settings or other issue workspaces.
I exclude fuzz targets/controls, snapshots/SemVer qualification, projections,
scanner/matcher runs, nested probes, investigated projects/package managers/feeds,
release builds, native/race/cross-platform jobs, matrix/self-hosted runners,
schedules, privileged PR events, workflow chaining, write tokens/secrets/OIDC,
cache or artifact Actions, auto-upgrades and implicit acquisition.

Fuzz is a later separately approved delivery. I expose no ineffective `run_fuzz`
control or empty fuzz job in this root-only increment. A root pass is not fuzz,
parser completeness, producer/platform support, native safety, coverage or safety.
#22's qualified macOS/safe-opening gap and all native rows remain unchanged.

## Selection and source identity

| Future event | Root checks | Result outside selected phases |
| --- | --- | --- |
| `pull_request` targeting `development` | Selected | Not a fuzz pass |
| `push` to `development` | Selected | Not a fuzz pass |
| `workflow_dispatch` | Selected, root only | No fuzz control/selection |
| Non-development push/PR, other event, schedule or privileged PR event | Not selected | Not-run, never a pass |

I select `ubuntu-24.04`, Linux amd64, exactly one job and no matrix. The label is
not an immutable runner image. A receipt records actual runner image/version,
architecture, kernel and available CPU/RAM, without environment values or secrets.
A detected profile mismatch blocks setup/qualification; I do not select a fallback
platform. The user explicitly approved external environment closure: checks may
run after qualified Action adoption, observed Node 24, profile and credential gates.
I close actual runner-package version/image evidence against platform `Set up job`
metadata at acceptance, not by relaunching Runner.Listener or granting API access.
Absent/contradictory platform evidence leaves qualification pending/failed even if
the bounded checks and nominal job conclusion succeed.

I bind evidence to the actual checked-out commit and tree being tested. For a PR,
automatic merge-checkout evidence is not silently attributed to its head alone:
I distinguish actual checkout, PR head and base identities. I record the applicable
event/ref without substituting another source commit after failure. Untrusted PR
text is not interpolated into shell commands; inspected source is the designated
repository checkout, not a target acquired by the scanner.

Running repository test code is explicit CI execution, potentially including new
PR test code. I do not portray it as data-only parsing or as a sandbox resistant to
malicious repository code. Fork/event approval and runner credential/resource
boundaries must be addressed in the executable plan and actual acceptance.

## Proposed pins, not acquired/adopted distributions

I retain #23's observed proposals; I perform no new metadata/download operation
through this local draft:

| Item | Proposed exact identity | Evidence limitation |
| --- | --- | --- |
| Official Go | `go1.27.1.linux-amd64.tar.gz`, 70,553,950 bytes | Catalog metadata only; no archive acquired here |
| Go SHA-256 | `63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445` | Expected catalog digest, not a measured acquired digest |
| Source URL | `https://go.dev/dl/go1.27.1.linux-amd64.tar.gz` | Future acquisition only, with reviewed exact HTTPS redirect allowlist |
| Checkout | `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` | Observed v7.0.1 identity, not complete adoption qualification |
| Action runtime/license | Node 24; runner >=2.327.1; MIT | Previously inspected named texts, not full bundled/transitive audit |

Before executable implementation/activation I require a bounded reviewed assessment
of the actual pinned Action source/bundle, dependency/security/notice obligations,
main/post behavior, runtime and credential cleanup. No candidate is substituted or
adopted merely because its pin resolves. The currently incomplete assessment is a
real gate, not an implicit exemption or a claim that the Action is insecure.

The approved complete plan must freeze the exact setup commands, source/redirect
policy, acquisition timeouts/budgets, verified archive extraction destination and
presence-only credential checks. Missing values or unavailable qualification block
implementation; the plan may not defer executable details to installation time.
I require explicit permissions for any further consultation/acquisition needed to
prepare that assessment; this contract does not authorize it.

## Setup and credential boundaries

1. I require explicit authorization before the workflow-bearing push/PR and again
   before an integration that can activate development jobs. These actions can
   acquire/execute the Action, download/use Go and consume hosted runner time.
   Documentary publication, root-job selection or manual-only future fuzzing is
   not permission for those effects.
2. Checkout uses only `contents: read`, no persistent credentials, submodules/LFS,
   privileged checkout fallback, automatic tags or host-global safe.directory
   changes. I retain #23's explicit settings: `persist-credentials:false`,
   `submodules:false`, `lfs:false`, `fetch-depth:1`, `fetch-tags:false`,
   `allow-unsafe-pr-checkout:false`, `set-safe-directory:false`.
3. I test only after credential cleanup is actually qualified. Presence checks may
   inspect configuration key names and remaining credential-file existence, never
   values, token/key contents or passphrases. Residual or unknown checkout-credential
   state blocks Go execution. Go command environments receive no checkout token or
   credentials; their exact environment construction is part of the approved plan.
   This does not claim that the entire runner/host has no service credentials or
   that environment sanitization isolates filesystem/process access.
4. Future setup obtains exactly the proposed official archive under approved HTTPS
   destinations and finite redirect/time/byte limits, with no automatic retries,
   alternate mirrors, proxies/credentials or version upgrade. I bound the artifact
   stream at the approved 70,553,950 bytes and reject excess rather than retain or
   extract it. Completion requires that exact size and approved SHA-256 before
   unpacking outside the checkout, without elevation or host-global installation.
5. I record acquisition provenance and actual binary `go version` and
   `go env GOVERSION GOOS GOARCH`. A nonofficial/version/architecture mismatch is a
   blocked setup, not a switch to the existing local X:nodwarf5 compiler. Matching
   size/digest is transport consistency, not reproducible-build/native evidence.
6. No restore/save cache Action or implicit module/toolchain download is allowed.
   Compilation cache/scratch, if needed, is job-local and not reused across runs.
   The root module remains standard-library-only at this slice's approved baseline;
   a changed dependency/toolchain policy requires review, not permission from cache.

An unqualified Action/observed-Node-runtime/credential gate or failed setup prevents
root checks. Runner-package version provenance is the separately approved external
closure; it is not inferred from a PATH Node binary or nominal job success.
I retain the limitation and blocked/not-run phases; I do not turn fail-closed setup
into successful verification. No privilege, sandbox/security-setting change or
additional dependency is silently introduced to make a gate pass.

## Root execution and budgets

After separately approved qualified setup, I use exactly these root operations:

```text
go test -count=1 -json -timeout=10m ./...
go vet ./...
```

I require `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOWORK=off`, `CGO_ENABLED=0`,
`GOMAXPROCS=2` and soft `GOMEMLIMIT=512MiB`. Commands start in the owned root module;
`./...` does not execute or qualify the nested probe module. Root tests are not
invocation of the product scanner or an investigated package manager.

The outer job deadline is **15 minutes including checkout, setup and checks**;
root tests have **10 minutes** inside it. Vet has a distinct phase/exit status and
stays inside the same outer deadline. I run vet after an ordinary test failure when
safe with sufficient remaining time; setup failure, cancellation/deadline or unknown
safety does not force another process. A phase not reached is not-run, not successful
because another phase or the overall runner concluded normally.

`GOMEMLIMIT` is a soft Go-managed per-process goal, not hard aggregate RSS. Available
runner RAM/CPU and observed footprint have explicit measured/unknown states; I do
not promise native containment or performance. GOMAXPROCS is not a runner CPU quota.
`GOPROXY=off` prevents module retrieval; it does **not** block arbitrary network calls
from repository code. No firewall/container/privilege change is authorized here.

I keep bounded phase diagnostics and a compact receipt in ordinary job logs/summary,
without adding an upload/artifact Action or claiming immutable archival. My proposed
ceilings are **16 MiB aggregate captured owned-command stdout/stderr** and **64 KiB
for the compact receipt** per run, independent of Go memory and artifact-byte limits.
These bound supervisor capture, not checkout/service logs. Diagnostic encoding has
bounded representation overhead; no platform-log hard byte ceiling is claimed. The
complete plan defines enforcement/draining, retention and closure before executable
approval. Reaching a ceiling does not invent a complete JSON stream: I retain the
limit/evidence failure and do not certify a pass, even if the test process exits 0.
Missing/truncated evidence is an evidence limitation. I do not persist credentials,
raw investigated inputs, private paths or unbounded environment dumps as evidence.

## Result and receipt contract

I require independent statuses for checkout/setup, tests, vet and receipt closure:
passed, failed, blocked, not-run, cancelled, timed-out or unknown. These documentary
terms are not a new shared Go/wire/report schema or a scan exit-code computation.

- Completed qualified verification requires qualified setup, successful tests/vet,
  complete captured receipt and external platform environment closure. A successful
  bounded-check job alone has qualification pending; it does not certify an unknown
  runner-package version/image or silently satisfy external acceptance.
- An ordinary failed selected phase fails verification even if its siblings pass.
  Interruption/deadline/unknown/missing evidence cannot be relabeled completed.
- Go JSON stdout `build-output` may contain compilation diagnostics; build failure
  is not behavioral RED or an absence of tests that deserves a pass.
- I count tests/subtests from one complete root JSON stream only when
  `Action == "pass"` and `Test` is nonempty. Package passes, cached results,
  parallel sums and zero selected tests are not planned-case execution proof.
- I record exact source identities, event/phase selection, artifact/Action identities,
  measured or unavailable environment observations, commands/settings, phase exit
  codes/times, counts and evidence limitations. No checkout/runner credential value belongs
  in the receipt; a partial receipt states what is unavailable rather than invent it.

Installing the workflow or changing a YAML job name does not configure required
status checks. Branch-rule modification is a separate security operation with its
own permission. No workflow/receipt result closes product or native acceptance.

## Independent documentary expectations

These are authored contract rows, **not executed CI tests**. The later complete
plan must map them to controlled validation/authorized actual hosted evidence;
there are no executable fixtures or runtime Markdown consumers in this draft.

| ID | Condition | Required observation |
| --- | --- | --- |
| R01 | PR targets development | Root selected; actual checkout/head/base identities distinguished |
| R02 | Push to development | Root selected for actual pushed/checked-out source |
| R03 | Manual dispatch | Root only; no fuzz input/job or fuzz-pass claim |
| R04 | Non-development push/PR or other/privileged event | Outside profile; not selected, never fabricated root pass |
| R05 | Node/profile differs, or platform runner/image proof differs/is absent | Setup blocked when detected before Go; external qualification failed/pending otherwise; no fallback |
| R06 | Only catalog digest/pin/texts available | Not acquired/adopted/runner-qualified evidence |
| R07 | Action audit/notice/cleanup incomplete | Activation gate remains blocked; no assumed safe adoption |
| R08 | Credential residue or presence-check uncertainty | Go not run; no token/key/config values disclosed |
| R09 | Archive excess, wrong size/hash or unapproved destination | Setup blocked/failed; never extract/use or retry/fallback implicitly |
| R10 | Explicit setup/publication/runner authority absent | No executable installation or activating publication |
| R11 | Valid setup, successful tests/vet, complete receipt | Completed root verification only for actual environment/source |
| R12 | Ordinary test failure with safe time remaining | Tests failed; vet observed separately; overall not successful |
| R13 | Setup failure | Tests/vet not-run with setup limitation retained |
| R14 | Timeout/cancellation before vet | Interrupted phase retained; unreached vet not-run, not pass |
| R15 | Compilation diagnostics in JSON stdout | Build failure retained; not behavioral RED or zero-tests success |
| R16 | Package passes, cache, separate streams or zero tests | No inflated/planned test count or completed-case claim |
| R17 | Receipt/diagnostic capture truncated or missing | Evidence limitation/unknown retained; no certified completed pass |
| R18 | Proxy off / soft Go memory / nominal runner label | No network-isolation, hard RSS or immutable-image claim |
| R19 | Fuzz/native/producer checks absent | Remain unexecuted/unqualified, not root-derived success |
| R20 | Workflow installed but branch checks unchanged | No claimed required-check enforcement or parent completion |

## Approval, review and later delivery gates

I obtained approval of this complete written specification and may now prepare
the complete issue-38 implementation plan, including actual workflow code,
validation details, finite capture/setup limits and explicit blocked adoption gates.
Before executable code I require reviewed #23 integration, plan approval and exact
permission for applicable security/notice consultation, acquisition/installation,
Action/official-Go use and hosted runner execution. No acquisition is implied by
approving proposed pins in a document.

Workflow-bearing publication and integration each require approval of their possible
automatic root setup/execution effects before they occur. I require independent
final-head review and observed authorized hosted acceptance before completing this
installation issue. A YAML parse, static source reading, local X:nodwarf5 test pass,
nominal successful job or merged PR alone is insufficient evidence for these gates.

I keep #38/#11 open until their distinct acceptances; I do not close #23/#35, change
#22/native rows, or grant fuzz/native/scanner/producer/pilot/release permissions.
The original checkout, #23/#35 workspaces/bookmarks and unrelated local-only deletion
checkpoint remain outside this change. Public reservation is complete; local
plan drafting is authorized, but publication/review, executable implementation,
acquisitions and runner execution remain unauthorized. The user separately approved
up to 10 public texts/headers, 256 KiB each and 2 MiB total, for plan preparation;
9 documents/headers totaling 137,837 bytes were consulted without bundles or Go
archive bodies. This is not distribution, notice/security or runner qualification.

## Approved native Git amendment — complete review scope

### Purpose and smallest delivery

I want to finish the assigned root tests/vet CI issue without adopting an unnecessary checkout Action. The repository was confirmed public through GitHub metadata. I use preinstalled Git to obtain only the designated owned repository source and retain the original bounded official-Go setup and root-check evidence requirements. This is source acquisition and repository-code execution, not data-only inspection or a security sandbox.

The only future executable repository path remains `.github/workflows/root-verification.yml`. I revise only this existing specification and its existing issue-38 plan during preparation. I leave #40, its draft status, harness, acquired material, reviews and history unchanged; none is merged, executed or declared qualified. S64 remains paused. No new helper repository, Go source, module dependency, probe, Action or agent is introduced.

### Native source acquisition and identity

- The only source remote is anonymous HTTPS `https://github.com/landroval/PackTrace.git`. A private-repository response, authentication requirement, missing ref or source mismatch blocks setup; there is no token, SSH, mirror or authenticated fallback.
- Git runs through an explicit isolated environment with a fresh job-owned HOME and scratch directory, disabled system/global configuration and prompts, no inherited credential/proxy/Git configuration environment and no credential helper, extraheader, askpass, SSH command or persisted service credential.
- A new repository is initialized without host templates. Hooks are disabled through a job-owned empty hooks directory; no submodule recursion, LFS acquisition, tags, external filter configuration, auto-upgrades or host-global safe.directory change is permitted. Repository attributes are not configured as executable drivers.
- A shallow, no-tags fetch selects the PR merge ref for `pull_request`, or the exact validated event SHA for push/manual dispatch. PR numbers are bounded decimal data used in argument arrays, never interpolated into shell programs. All expected object identities must have the supported hexadecimal shape before Git is invoked.
- Checkout is detached. Its actual commit must equal the event's expected SHA, and its actual tree is recorded. PR head/base identities remain separate. A moved PR merge ref fails identity qualification rather than causing a second fetch, fallback, retry or substitution.
- Native checkout has a 60-second aggregate deadline within the unchanged 180-second setup and 15-minute job deadlines. Its command capture shares the existing 16 MiB aggregate budget and uses the 64 KiB individual metadata ceiling. Exhaustion or incomplete process closure blocks setup; no valid-looking prefix qualifies source.
- Record the actual preinstalled Git version/path and hosted profile. Preinstalled software is not claimed immutable or source-audited by a version string. Controlled validation must cover the actual planned flags and isolation; authorized hosted acceptance must demonstrate the supported profile. No Git distribution is downloaded or installed by this workflow.

### Exact replacement of Action-specific gates

After owner acceptance of this amendment, this route has no `uses:` checkout entry, no Node invocation/runtime lookup, no checkout Action bundle/dependency/notice adoption, no checkout-produced temporary auth file and no main/post Action cleanup experiment. Those Action-specific predicates are **not applicable to the native route**, not passed or waived and not findings about Action safety.

I replace them with demonstrated anonymous native checkout, isolated configuration/environment, disabled hooks/recursive acquisition, exact source identity and actual Git/hosted-profile evidence. Go receives the same explicit noncredential environment and job-owned storage. I do not inspect real host credential/config values or execute the #40 harness to establish these properties. Absence of passed service credentials does not mean the hosted worker has no internal service credentials or that repository tests cannot access filesystem/process/network resources.

The workflow uses no token/secrets/OIDC input and requires no repository write permission. Its permission declaration is empty. Fork and manual-event execution still require GitHub's applicable event approval and explicit owner authorization; anonymous fetch does not authorize arbitrary repository-code execution.

### Unchanged setup, checks, limits and acceptance

The approved official-Go candidate identity, HTTPS allowlist, 70,553,950-byte archive ceiling and expected SHA-256, no retries/fallback/proxies, 120-second acquisition budget, verified extraction limits, job-local caches and exact official compiler/profile validation remain unchanged. Previously observed metadata is historical; availability/identity must be revalidated within separately approved consultation/acquisition authority before actual use. If the candidate cannot be qualified, stop instead of selecting a version or custom compiler automatically.

Root commands remain `go test -count=1 -json -timeout=10m ./...` and separately observed `go vet ./...`, with the existing offline acquisition settings, `GOMAXPROCS=2`, soft `GOMEMLIMIT=512MiB`, 10-minute test/60-second vet bounds, 16 MiB aggregate capture and 64 KiB compact receipt. Preserve the existing independent phase statuses, complete JSON-stream counting, compilation-versus-behavioral evidence, missing/truncated-evidence failure and external actual runner image/package evidence. Dropping Node removes its runner-version floor as a Node compatibility predicate; the actual hosted runner version/image must still be observed, with no claim of immutable image or successful unknown profile.

R01–R04 and R09–R20 remain binding with source acquisition attributed to native Git rather than an Action. For R05 require actual Git/Linux amd64/Ubuntu 24.04/Python profile and external runner/image evidence, not Node. For R06 do not infer acquisition or runtime qualification from candidate metadata or a named binary. R07 requires qualification of the native source/environment prerequisites, not an Action assessment. R08 requires no passed/persisted service credentials and qualified isolated native configuration; uncertainty blocks Go without reading real credential values.

Before closure I require independent final-head review, authorized actual PR/manual/development-push root runs, exact source/tree/toolchain/runner receipts and complete diagnostic reconstruction. No YAML-only installation, merged PR, historical local test count, nominal job success, missing event evidence or parent completion stands in for acceptance. Root success does not install required branch checks, certify scanner safety or qualify fuzz/native/producer/release behavior.

### Approval and execution boundary

I approved this complete amendment and authorized preparation/review of the revised complete executable plan only. The subsequent **Ciclo completo** records those explicit bounded permissions for this native route; it does not grant unspecified acquisitions, environment provisioning, privilege/protection changes or unconditional closure. No proposal here changes branch protections, credentials, runner provisioning or security settings. I preserve all original workspaces/bookmarks and unrelated deletion checkpoints. #38 remains OPEN until its complete accepted delivery; #11 and all other parent states remain unchanged.
