# Issue 23 Root Qualification Preparation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for coordinator-owned documentary preparation. A later executable increment preserves the owner's multi-agent choice and requires its own reviewed implementation handoff. Steps use checkbox tracking; no new agent call, hosted execution or acquisition is authorized here.

**Goal:** Deliver a reviewed, pinned qualification blueprint for later root CI and bounded reader fuzzing, without installing or executing it.

**Architecture:** I retain one documentary contract/plan lane independent of #35. I select an official distribution and one immutable checkout Action, then map existing in-memory reader boundaries, deterministic seed families and finite fuzz jobs to explicit evidence/activation gates. I keep native qualification separate.

**Tech Stack:** Future official Go 1.27.1 with CGO disabled; GitHub-hosted Ubuntu 24.04 amd64; root standard-library module; one pinned GitHub checkout Action.

**Spec:** [approved #23 contract](issue-23-root-ci-parser-fuzzing.md), approved local commit `2f68d4ab302626b4c34078338979d46961138465`.

Status: **draft plan; review/publication pending**. The user approved the written contract and local plan drafting with bounded public metadata/text consultation. I have not acquired executable distributions, enabled workflows, run Go/fuzz/CI, requested review or published a branch. I keep #23 OPEN / Preparation. Documentary completion requires peer review/integration; it is not executable-delivery permission.

## Global constraints

- Root tests/vet on `pull_request` targeting development and pushes to development; fuzz only on `workflow_dispatch` with explicit `run_fuzz=true` (default false). No schedules, workflow chaining or privileged PR events.
- Exactly the four existing readers: npm lock, manifest, OSV raw record and Bun reader through owned JSONC normalization. No snapshots, SemVer, projections, paths, archives, probes or targets.
- Root module only; `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOWORK=off`, `CGO_ENABLED=0`; no module/toolchain auto-download or cache Action.
- Root job 15 minutes, root test 10 minutes; manual fuzz job 10 minutes, each selected target 60 seconds with a 2-minute test timeout; one worker, sequential targets, GOMAXPROCS=2.
- Active mutation input at most 256 KiB; reader limits/depth handled by independent deterministic root regressions, not truncation. GOMEMLIMIT=512MiB is soft per process, not hard aggregate RSS.
- Crash evidence at most 1 MiB/case and 16 MiB total. Limit/timeout/cancellation/unknown or missing receipts cannot become a pass.
- Only contents:read token permission, no secrets/OIDC/write rights, submodules/LFS, credential persistence, privileged service/container, protection changes or auto-upgrades.
- A future workflow-containing push/PR can automatically download/setup/run root checks. I require explicit acquisition/runner-execution approval **before that publication**, even though fuzz is manual.
- No native/producer/platform/pilot/release or full-coverage claim; #22's macOS gap and all native rows remain unchanged.

## Review focus

1. A new workflow PR must not silently activate downloads/runner execution before the owner approves those effects.
2. A pinned Node Action is a separate supply-chain dependency despite the Go root being standard-library-only; pin identity is not a complete security/license audit.
3. Fuzz campaign success is restricted to eligible bytes/time/targets, never skipped inputs, exhaustive parsing or negative coverage.
4. Original-byte digests, whole-zero errors and raw ownership must survive JSONC normalization and post-return mutations without leaking input.
5. Failure, compilation error, interrupted phases, retention caps and absent evidence must remain distinct from behavioral RED or success.

## Pins observed by public consultation only

I consulted public metadata/texts after the user's explicit permission. I did not
clone/build/install the Action, fetch dist/index.js, download a Go archive, run its
code, inspect credentials or alter machine security/configuration.

| Item | Exact proposed pin | Observed metadata / provenance |
| --- | --- | --- |
| Go distribution | `go1.27.1.linux-amd64.tar.gz` | Official [release catalog](https://go.dev/dl/?mode=json); stable go1.27.1, Linux amd64, archive size 70,553,950 bytes |
| Go SHA-256 | `63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445` | Selected catalog entry, not a digest measured from acquired bytes |
| Future Go source URL | `https://go.dev/dl/go1.27.1.linux-amd64.tar.gz` | Official distribution service; redirects restricted to approved official HTTPS distribution endpoints during future setup |
| Checkout Action | `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` | Public [v7.0.1 release](https://github.com/actions/checkout/releases/tag/v7.0.1) and tag ref point directly to this commit; no moving tag in future workflow |
| Runtime | Node 24; Actions Runner >=2.327.1 | Pinned action.yml runs `dist/index.js` as main/post; package engines >=24; README records runner floor |
| Action license | MIT, GitHub/contributors | Pinned LICENSE requires retained copyright/permission notice; no claim of complete bundled/transitive notice review |

Pinned texts inspected: [action.yml](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/action.yml),
[LICENSE](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/LICENSE),
[package.json](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/package.json),
[README](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/README.md),
[input helper](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/src/input-helper.ts)
and [auth helper](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/src/git-auth-helper.ts).

Static findings: checkout defaults to credential persistence and safe.directory
configuration, so I require explicit `persist-credentials:false`, `submodules:false`,
`lfs:false`, `fetch-depth:1`, `fetch-tags:false`, `allow-unsafe-pr-checkout:false`
and `set-safe-directory:false` in the future workflow. Normal checkout temporarily
configures authentication; false persistence alone is not measured cleanup evidence.
Before Go code runs, the future acceptance checks credential **presence only** (git
configuration key names and remaining temporary credential-file existence), without
reading/printing tokens, SSH keys or config values. Residual credentials block execution.
No host-global/security change or SSH credential is introduced by this preparation.

The Action has bundled Node dependencies; I have not audited its full dependency
graph/dist bundle or demonstrated cleanup/runtime behavior. Source review is limited
to the named texts, not complete adoption qualification. Before executable adoption,
I require a reviewed bounded security/notice assessment and exact distribution/
runner permissions; inability to complete it blocks adoption, not a permissive
fallback. I do not weaken the approved publisher/pin policy.

## One documentary task: reviewable qualification blueprint

**Files:** this plan and the separately approved contract only.

**Consumes:** approved contract, current root go.mod, the four unchanged reader
signatures and their shared JSON/error conventions, official Go catalog entry,
pinned checkout texts and native-plan evidence limits.

**Produces:** this complete written pin/seed/phase/approval blueprint, not runtime
interfaces, YAML, fuzz functions, acquired artifacts or qualified runner evidence.

- [x] **Step 1 — Confirm approved scope and independent base.** I read the integrated
  reader code and the approved contract. I use the issue-specific workspace/bookmark
  directly above development `76ef90daf36c4b4fae2b234369859108440fc24e`; shared sources,
  #35's workspace, original checkout and local checkpoint remain outside this change.
- [x] **Step 2 — Consult and record exact public pins.** I resolve the Action release/tag
  to its immutable full commit, inspect the named bounded texts and record the selected
  official Go catalog entry. The table above records actual observations, not an
  acquired archive hash, legal/security qualification or executed version.
- [x] **Step 3 — Fix phase selection and minimum privilege.** I use the approved event
  table and checkout settings above. I exclude privileged PR events, secret-bearing
  test environments and automatic fuzz dispatch. Future setup verifies the exact
  archive size/digest before extraction outside the checkout and actual Go version/
  GOOS/GOARCH before any root check. No mismatch is corrected by upgrade/fallback.
- [x] **Step 4 — Map the seed families to each unchanged reader.** I preserve F01–F18
  from the contract and the concrete mapping below. I reuse existing deterministic
  root tests; I require a separately approved code increment for missing regressions.
- [x] **Step 5 — Define selected-target commands and evidence closure.** I use the
  exact commands/environment and receipt rules below, including not-run/unknown
  phases. I do not pretend they have executed under this documentary task.
- [ ] **Step 6 — Review this plan against the spec.** I check source pins, event/security
  decisions, all 18 family IDs, time/resource semantics, reader-role distinctions and
  absence of executable changes. The owner reviews this written artifact before its
  separately authorized publication. Inline/agent critique is not peer approval.
- [ ] **Step 7 — Publish/review/integrate only if separately authorized.** The coordinator
  commits/pushes only these issue documents, opens a documentary draft PR, requests
  agreed final-head second-person review separately, and obtains integration/closure
  authority. #23 acceptance then means reviewed documents, not executed CI/fuzzing.

### Seed mapping and independent expectations

| Families | npm lock | Manifest | OSV raw | Bun JSONC |
| --- | --- | --- | --- | --- |
| F01–F04 | F01 minimum v2/v3 | F02 any-object minimum | F03 id/modified strings, deliberately non-timestamp modified | F04 versions 0–3, workspace object/package array members |
| F05–F09 | Invalid JSON/root shape, decoded duplicates, encodings, root-inclusive depth | Same envelope checks; no invented required keys | Same envelope checks before required id/modified | Same through JSONC normalization, no cleanup rescue |
| F10 | Required packages object and object records | Arbitrary values in an object remain raw success | Nonempty string id/modified | Required workspaces/packages and exact member shapes |
| F11 | Integer v2/v3 only; other integer unsupported; fraction/exponent invalid-shape | No version qualification | No raw-reader schema-version qualification | Integer 0–3 only; other integer unsupported; fraction/exponent invalid-shape |
| F12 | Unknown fields/exact numbers retained | Same | Same | Same, original rather than normalized digest |
| F13/F14 | Not JSONC; comments remain invalid-json | Not JSONC | Not JSONC | Valid comments/trailing commas/string escapes versus `{,}`, `[,]`, stray slash/unterminated comment |
| F15/F16 | 64 MiB byte-first limit | 2 MiB byte-first limit | 4 MiB byte-first limit | 64 MiB byte-first limit |
| F17/F18 | Whole-zero private errors and independent Fields/Packages bytes | Whole-zero private errors and independent Fields | Whole-zero private errors and independent Fields | Whole-zero private errors and independent Fields/Workspaces/Packages |

All concrete minimum literals and expected codes are fixed in the approved spec.
For Bun's successful JSONC seed I use authored
`{/*note*/"lockfileVersion":1,"workspaces":{},"packages":{},}` and its exact
original-byte digest, not reserialized JSON. For decoded duplicates, the minimum
valid envelope gains both `"x":1` and `"\u0078":2`; duplicate-key wins before later
shape/version checks. F09 adds 127 nested arrays under one unknown root property
for total container depth 128, then 128 for depth 129. F15 uses whitespace padding
on complete valid envelopes to the stated exact lengths; I do not populate the
active mutation corpus with these large boundary inputs.

Later code must carry literal independent expected outcomes and source IDs, not
runtime Markdown or another parser as oracle. Arbitrary fuzz mutations instead
check deterministic invariants, whole-zero controlled errors, original SHA and
ownership. I snapshot a successful value before mutating its input/second result;
that snapshot is an ownership reference, not independent semantic conformance.
Each crash needs a minimized named regression before its fix is closed.

### Future command/receipt contract — not executed

All commands run from the owned root under the approved local/offline Go settings,
GOMAXPROCS=2 and soft GOMEMLIMIT=512MiB after separately approved verified setup:

```text
go test -count=1 -json -timeout=10m ./...
go vet ./...
go test -run=^$ -fuzz=^FuzzParseNPMLock$ -fuzztime=60s -timeout=2m -parallel=1 ./internal/inventory
go test -run=^$ -fuzz=^FuzzParseManifest$ -fuzztime=60s -timeout=2m -parallel=1 ./internal/inventory
go test -run=^$ -fuzz=^FuzzParseOSVRecord$ -fuzztime=60s -timeout=2m -parallel=1 ./internal/intel
go test -run=^$ -fuzz=^FuzzParseBunLock$ -fuzztime=60s -timeout=2m -parallel=1 ./internal/inventory
```

Only explicit manual fuzz selection permits the last four commands. I require
at least one eligible seed and observed selection of each required target; inputs
over 256 KiB remain explicitly outside that finite campaign, not truncated into
passing cases. Four selected targets run sequentially; an unreachable later target
is not-run. A job deadline/timeout/interruption or a missing/truncated receipt
cannot supply completed evidence. Vet retains its own exit status when safely run
inside the root deadline after test failure.

A future receipt records source commit, official artifact/digest and actual version,
runner image/architecture/resources, settings/commands, each phase status/exit/time,
test/subtest count from one root JSON stream, selected target/eligible-seed evidence,
crashes/regression references, retention limitations and remaining native/producer
limitations. Compiler build-output is not behavioral RED; package passes and zero
selected tests are excluded from test counts. Soft Go memory settings and runner
capacity are not aggregate RSS enforcement. No recorded result is implied here.

## Separate executable increments and authority

Future executable paths are exactly the five in the specification. They are not
created by this documentary plan. Before their implementation I require an approved
concrete executable plan with complete workflow/fuzz code, behavior checks and
acquisition/execution permissions; that plan must not invent credential cleanup,
source/security/notice or official-runner evidence from this static consultation.

The owner must explicitly authorize all activation effects before a workflow-bearing
PR/push: checkout Action acquisition/execution, official Go download/unpacking/use,
hosted runner charges/time, root tests/vet and any selected manual fuzz campaign.
Publication permission for documents or the independent #35 branch is not that
authority. No automatic status-check ruleset modification is permitted.

Documentation-only #23 closure stays separate from those later increments and from
#11 shipping acceptance. I keep #22/native rows, platform support, producer/matcher,
scanner/pilot and release qualification open/unclaimed. I request review of this
written plan; I do not dispatch agents, install code, acquire executables or run jobs.
