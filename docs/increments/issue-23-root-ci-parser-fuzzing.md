# Issue 23: root CI and parser-fuzzing qualification contract

Status: **written specification approved**. The user approved this complete
written artifact and authorized local plan preparation plus bounded public
Go/Actions metadata/text consultation, not distribution acquisition or execution. I keep
[#23](https://github.com/landroval/PackTrace/issues/23) OPEN / Preparation, owned by
`landroval`. Its plan remains unapproved. I have not enabled workflows, run hosted
jobs/fuzzing, acquired executable toolchain/Action distributions, changed protections
or requested review.

Base: integrated development `76ef90daf36c4b4fae2b234369859108440fc24e`.
Authority: [official toolchain baseline](../design-decisions.md#24-toolchain-and-dependency-baseline),
[testing guidelines](../development-guidelines.md#11-testing-and-compatibility-evidence),
[collaboration gates](../github-collaboration.md) and
[native feasibility plan](../native-safety-probe.md).

## Purpose, ownership and evidence boundary

I want a reviewed, bounded root-verification/fuzzing contract before installing CI.
The root module is standard-library-only; owned synthetic tests are not investigated
project/dependency execution. I exclude the isolated probe module and all target,
feed, package-manager and native-probe inputs.

This draft owns this document alone. The later documentary plan will be
`docs/increments/issue-23-root-ci-parser-fuzzing-plan.md`, only after written-spec
approval. The independent SemVer lane [#35](https://github.com/landroval/PackTrace/issues/35)
changes neither this contract nor existing reader interfaces; neither task blocks
the other's documentary review.

Future executable ownership, if separately approved, is limited to:

- `.github/workflows/root-verification.yml`
- `internal/inventory/npmlock_fuzz_test.go`
- `internal/inventory/manifest_fuzz_test.go`
- `internal/inventory/bunlock_fuzz_test.go`
- `internal/intel/osv_fuzz_test.go`

I do not change existing readers/tests, the module, shared states, CLI exits,
shipping milestones or protection rules as part of that proposed slice. New shared
helpers, large regression-file additions or broader CI jobs need an agreed scope
change. A future plan may split executable delivery into separately approved PRs;
this document does not activate any of them.

## Agreed activation and runner profile

I select **root tests/vet on pull requests and pushes to `development`; fuzzing only
on explicit manual dispatch**. The future single workflow has these event rules:

| Event | Root tests/vet | Fuzzing |
| --- | --- | --- |
| `pull_request` targeting `development` | Required job in this workflow | Not selected; not a fuzz pass |
| `push` to `development` | Required job in this workflow | Not selected; not a fuzz pass |
| `workflow_dispatch`, `run_fuzz=false` (default) | Selected | Not selected |
| `workflow_dispatch`, `run_fuzz=true` | Selected | Four selected targets, sequentially |
| Other branch/event, schedule, privileged PR event | Outside this profile | Not selected |

The runner profile is GitHub-hosted **`ubuntu-24.04`, Linux amd64**, with its actual
image/version, architecture, kernel, available CPU/RAM and toolchain recorded for
each run. The label is a selection request, not an immutable image or native-safety
claim. An architecture/version mismatch blocks qualification rather than selecting
a fallback toolchain/runner. macOS, Windows, ARM, self-hosted runners, race detection,
cross-compilation, release builds and native filesystem tests are excluded.

I do not use `pull_request_target`, schedules or workflow chaining to execute PR
code with elevated trust. A manual fuzz dispatch does not authorize other jobs,
downloads or targets. Hosted execution itself remains separately gated. A future
push, PR or development update containing the workflow can trigger hosted root
checks and setup downloads: before that publication I require explicit approval
of those acquisitions and runner executions. Workflow publication is not a passive
documentation operation, and manual-only fuzzing does not make root checks manual.

## Acquisition and immutable-pinning policy

I select the official **Go 1.27.1 Linux amd64 distribution**, `CGO_ENABLED=0`, as
already approved in the design. The local `go1.27.1-X:nodwarf5` compiler is not an
official build and cannot supply hosted/toolchain qualification evidence.

For a later explicitly approved acquisition plan I require:

1. I name the exact `go1.27.1.linux-amd64.tar.gz` artifact from the official
   [Go distribution service](https://go.dev/dl/), record its official release
   metadata source and expected SHA-256 in the written plan, and obtain approval
   of that exact artifact/pin before download. If it is unavailable, I stop; I
   do not upgrade, switch mirrors, substitute the local compiler or auto-download.
2. I verify the approved digest before unpacking outside the source tree, record
   acquisition provenance and actual `go version`/`go env GOVERSION GOOS GOARCH`,
   and use only the verified toolchain. A matching transport digest is not proof
   of reproducible builds, a complete supply-chain audit or native qualification.
3. I select **`actions/checkout` from the GitHub `actions` publisher** as the only
   proposed Action. Before approving an executable plan, I identify and review
   its exact immutable full commit SHA and runtime requirements in that plan.
   No moving tag, automatic pin update, marketplace substitute or third-party
   wrapper is permitted. I review source/security, license/notice obligations and
   runtime requirements before adoption; pin identity alone is not a security audit.
   I do not require `actions/setup-go` or cache Actions: the explicit
   official-distribution step owns Go sourcing.
4. I keep credentials out of commands, logs, cache and retained artifacts. Checkout
   uses `persist-credentials: false`, no submodules and no LFS. Workflow token
   permissions are only `contents: read`; no write permissions, secrets, OIDC,
   repository-setting changes or privileged service/container are introduced.
   Test/fuzz command environments must not receive checkout tokens or credentials.
5. I require separate approval for the actual toolchain/Action acquisition and
   workflow installation/execution. This specification selects sourcing policy,
   not an unconsulted revision or checksum. The later plan must contain the exact
   verified pins before implementation approval; their absence blocks activation.

Initial specification preparation fetched no external toolchain/Action metadata
or archive. The subsequently authorized plan consultation records public metadata
and texts separately in the plan; no executable distribution was acquired. I do
not fabricate checksums, commit pins, audits or acquisition evidence. The selected
sources are explicit; exact-pin approval remains a defined later gate, not a claim
that #23's acquisition acceptance is already complete.

## Root checks and receipts

After separately approved setup, I require these owned root commands under
`GOTOOLCHAIN=local`, `GOPROXY=off`, `GOWORK=off`, `CGO_ENABLED=0`:

```text
go test -count=1 -json -timeout=10m ./...
go vet ./...
```

I run vet as a distinct phase, recording its own exit code even if tests fail when
safe within the outer deadline. I disable cache restore/save and implicit module,
workspace or toolchain acquisition. `./...` is evaluated from the root module and
does not qualify or execute the nested probe module.

A receipt records exact source commit, actual toolchain/settings, runner profile,
commands, phase exit codes, timing, selected/omitted phases and interruptions. I
retain bounded diagnostics sufficient to distinguish compilation from behavior;
Go JSON `build-output` can carry compiler errors on stdout. A failed build is not
behavioral RED. Tests/subtests are counted from one JSON stream only when
`Action == "pass"` and `Test` is nonempty; package events and parallel sums are
excluded. Missing/truncated receipts or zero selected tests do not establish a
pass or execution of planned cases.

Passing root tests/vet qualifies only those checks on that exact environment and
commit. I do not call it a scanner run, official reproducible release, platform
support, native safety, producer compatibility, coverage completion or safety.
Installing a workflow does not itself enforce status checks in the branch ruleset;
changing required checks remains separately authorized security configuration.

## Four parser-fuzz contracts

I propose exactly these future targets; every invocation supplies synthetic bytes
to the existing in-memory reader, without executing target code/configuration:

| Target | Reader | Existing reader byte ceiling | Family-specific concerns |
| --- | --- | --- | --- |
| `FuzzParseNPMLock` | `inventory.ParseNPMLock` | 64 MiB | Canonical v2/v3; required object records; retained unknown fields |
| `FuzzParseManifest` | `inventory.ParseManifest` | 2 MiB | Any root object; raw ownership, not declaration resolution |
| `FuzzParseOSVRecord` | `intel.ParseOSVRecord` | 4 MiB | Nonempty string id/modified; no timestamp/header/affected qualification |
| `FuzzParseBunLock` | `inventory.ParseBunLock` through owned JSONC normalization | 64 MiB | Canonical versions 0–3; required workspace objects/package arrays; original-byte SHA |

I exclude direct standalone normalizer fuzzing, snapshot manifests, SemVer,
projections, archives, paths and the optional #15 probe. Expanding targets requires
scope approval rather than silently enlarging this wave.

For every eligible input I require:

- No panic, hang or recovered internal fault reported as successful parsing.
- Repeated calls on identical bytes yield the same structural result/error category
  and original SHA; map iteration/rendering order is not a comparison oracle.
- Every rejection returns the entire zero document and the correct existing
  controlled error type, with only allowed fixed codes. Inventory readers may emit
  invalid-json, duplicate-key, limit-exceeded, invalid-shape, unsupported-version;
  the OSV raw reader emits the first four, not unsupported-version.
- Successful raw maps/slices own their bytes. A second successful result and the
  caller's input can be mutated after return without changing the snapshotted first
  result. I do not mutate inputs concurrently with a parser call.
- SHA-256 is checked against the original input bytes, not a normalized JSONC or
  reserialized document. Digest equality is not publisher authentication.
- Error strings equal fixed `inventory: CODE` or `intel: CODE` texts, never raw
  input, unknown keys, authored sensitive markers or decoder detail. Successful
  evidence is not automatically public-output-safe.

### Authored minimum seeds and deterministic regressions

The following seed families are documentary recipes with independent expected
outcomes. A later plan must map each ID to literal per-reader seeds and separately
specify the implementation tests. It cannot use the reader under test to generate
expected values, import real feeds/targets or read this Markdown at test runtime.

| ID | Authored seed/condition | Independent expectation |
| --- | --- | --- |
| F01 | npm `{"lockfileVersion":3,"packages":{}}`, plus v2 variant | Raw success, exact original digest |
| F02 | Manifest `{}` | Raw success with non-nil empty fields |
| F03 | OSV `{"id":"PACKTRACE-SYNTHETIC-I23","modified":"not-a-timestamp"}` | Raw success only; not temporal qualification |
| F04 | Bun `{"lockfileVersion":1,"workspaces":{},"packages":{}}`, plus 0/2/3 variants | Raw success only; not Bun producer qualification |
| F05 | Empty/truncated JSON and two top-level values, for each reader | Whole-zero invalid-json |
| F06 | Root `[]`, `null`, `true`, `1`, and `"x"`, separately | Whole-zero invalid-shape |
| F07 | Duplicate decoded root/nested keys, including `"x"` versus `"\u0078"` | Whole-zero duplicate-key |
| F08 | Invalid UTF-8 and unmatched JSON surrogate escapes, separately | Whole-zero invalid-json |
| F09 | Valid envelope with total container depth 128 / 129, separately | Success / whole-zero limit-exceeded |
| F10 | npm/OSV/Bun missing/null/wrong-type required fields or members; manifest with arbitrary property values | Whole-zero invalid-shape for those required-shape failures; manifest property values remain uninterpreted success |
| F11 | npm/Bun unsupported canonical integer version versus fractional/exponent spelling | Unsupported-version versus invalid-shape, separately |
| F12 | Valid unknown nested/raw fields and large exact JSON number | Raw preservation without normalization or precision loss |
| F13 | Bun comments and trailing commas outside strings; strings containing comment markers/escapes | Success and exact original-byte digest |
| F14 | Bun `{,}`, `[,]`, stray slash and unterminated block comment, separately | Whole-zero invalid-json; no cleanup rescue |
| F15 | Existing reader byte limit - 1, exact limit, limit + 1 with a padded valid envelope | First two successful; oversized whole-zero limit-exceeded |
| F16 | Oversized malformed input at reader byte limit + 1 | Whole-zero limit-exceeded before syntax |
| F17 | Rejection containing authored private marker in a field/value | Exact fixed diagnostic without disclosure |
| F18 | Caller input/raw output/second output mutation after success | First result, original digest and sibling result remain independent |

F09 uses the existing total-depth counting rule, including the root container. F15
padding is outside strings and preserves required envelope fields. F15/F16 are
large deterministic boundary regressions, not active mutation-corpus seeds. I
reuse existing root regressions where they already establish these expectations;
this document does not require duplicate suites or large fixture files.

### Explicit time and resource ceilings

The future plan must preserve these proposed, reviewable ceilings:

| Resource/phase | Ceiling and treatment |
| --- | --- |
| Root job outer duration | 15 minutes including setup and checks; timeout is not pass |
| Root test process | `-timeout=10m`; vet remains inside the outer deadline |
| Manual fuzz job outer duration | 10 minutes including setup and all four targets |
| Per selected target | `-fuzztime=60s`, `-timeout=2m`, one fuzz worker (`-parallel=1`) |
| Go concurrency | `GOMAXPROCS=2`; targets run sequentially, no unbounded matrix |
| Active mutation input | At most 256 KiB per byte-slice case; larger cases excluded explicitly, not truncated/coerced |
| Go managed memory | `GOMEMLIMIT=512MiB`, explicitly a soft per-process goal, not a hard aggregate RSS cap |
| Persisted crash/regression evidence | At most 1 MiB per case, 16 MiB total; exceeding retention budget is an evidence limitation, not suppressed success |

The future command shape selects one exact `FuzzParse…` target at a time with
`-run=^$`; it cannot interpret zero selected targets or skipped seeds as proof.
At least one eligible seed and an observed selected target are required. Inputs
above the active 256 KiB envelope are recorded as outside that bounded campaign;
reader maximum/depth boundaries remain independent deterministic root checks.
The limits do not establish exhaustive grammar coverage, hard RSS containment or
performance. The runner's available memory/storage and observed process footprint
must be recorded; absent measurements stay unknown. No privilege/cgroup/security
change is authorized to enforce a stronger cap implicitly.

I distinguish passed, failed, not-run, cancelled, timed-out, blocked and unknown
phases in documentary receipts. These are not a new public schema/shared model.
PR root success with fuzz deliberately unselected is not a fuzz pass. Cancellation,
crash, timeout, incomplete/truncated evidence or a failed selected target cannot
be relabeled successful; selected targets not reached remain not-run. Findings,
scan exit selection and product coverage are not computed by these jobs.

Every discovered crash receives a bounded retained reproduction and a minimized,
named deterministic regression under a separately reviewed fix before its closure.
An oversized/unretained case keeps the failure/evidence limitation visible. Fuzz
success is finite adversarial evidence, not parser completeness or negative findings.

## Native separation and later approval sequence

[#22](https://github.com/landroval/PackTrace/issues/22) remains blocked on its qualified
macOS runner/safe-opening mechanism. It does not block documentary #23 preparation,
but no nominal hosted macOS job or cross-compilation can fill that native row.
All five native rows retain their actual evidence state; this task changes none.

I require, in order: approval of this written contract; an approved written plan
with exact acquisition pins/permissions, seed mappings and checks; separately
explicit installation/acquisition/execution authorization; observed checks and
bounded receipts; independent final-head review; authorized integration/closure.
A documentation-only delivery records reviewed artifacts, not fabricated Go,
runner or fuzz execution. Native/producer/pilot/release capability parents remain
open until their own acceptance; #23 is not blanket qualification of #11.

## Documentary acceptance

- [x] I obtain approval of this written specification before preparing its plan.
- [x] I verify local links, 18 unique seed-family IDs, reader names/budgets, event
  rules, pin/acquisition gates, privacy/timeout/retention semantics and exact file scope.
- [ ] I record a local one-document commit and distinguish documentary checks from
  implementation, official toolchain acquisition and hosted/fuzz execution.
- [ ] I separately obtain publication/review authorization; no branch push, PR,
  ready transition, independent approval or issue/parent closure is implied here.
