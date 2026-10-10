# Multiplatform offline scan: contract and gated delivery plan

**Status: program direction and first portable delivery approved; native and later implementation gates remain unapproved.** I selected simultaneous agents and then selected
**multiplatform from the start**. That initial selection authorized preparing this single brief,
not production implementation, prototype creation/execution, target access,
downloads, runner provisioning, privileged fixtures, CI, publication or release.
I explicitly selected **Ciclo completo (recomendado)** for section 7 and bounded source-only section 8 on 2026-10-10T20:52:59.581000+00:00. This authorizes the Go pair, owned local checks/agent review, scoped issue #54/PR publication, development-only verified integration and scoped closure/Done. It does not authorize the other native/program stages. This authorization is recorded before Go.

The current integrated baseline is `45b3424cc5120a479dbacefa34de6a8d737d9514`.

**Goal:** deliver a useful read-only, offline npm/Bun investigation through the
existing `packtrace scan [options] PATH` contract, while retaining every native
qualification row and making missing evidence visible.

**Architecture:** retain the modular Go monolith and same-trusted-binary
supervisor/worker. Reuse existing inventory/intelligence/CLI readers and pure
selectors; add only the actual missing consumers and authorities. Native
acquisition, source qualification and report publication are separate trust
boundaries, not side effects of argument parsing or metadata matching.

**Tech stack:** stdlib first. Official Go 1.27.1 and `CGO_ENABLED=0` remain the
qualification baseline. At most the already-selected `golang.org/x/sys v0.44.0`
may be considered for native controls, after its separate adoption/preparation
requirements. Existing owned JSONC and SemVer implementations are reused. No
SCALIBR re-adoption, database, RPC/CLI framework or automatic dependency download.

**Spec and authority:** this file is the program contract and phased plan, read
with [design decisions](../design-decisions.md), [Probe B](../native-safety-probe.md),
[compatibility](../inventory-compatibility.md), [pre-1.0 acceptance](../pre-1.0-features.md)
and [collaboration](../github-collaboration.md). It does not invent a complete
backend implementation plan where the mandatory mechanism is still unknown.
Section 7 below specifies one independently implementable portable delivery;
section 8 states the separate gates for the rest.

**Execution method:** simultaneous agents on independent, file-owned work; one
coordinator owns interfaces, shared integration, final verification and GitHub
mutations. Agents report blockers to the coordinator, never seek owner approval
independently. A fresh agent review is not GitHub peer approval. Approval is
recorded before any code in the corresponding accepted delivery.

## 1. Outcome, not counters

The eventual first runnable task is an explicit advisory-only
`packtrace scan --checks malicious,vulnerability [other approved options] PATH`
investigation with prepared local intelligence, correct input selection,
evidence-bound matching, independent coverage, portable terminal/JSON/SARIF and
coherent exits. Default `scan PATH` retains all three required categories: until
integrity is implemented its integrity coverage is required/not-run, not excluded,
and it cannot report completed three-category acceptance or exit 0 merely because
advisory matching finished. It never
runs npm/Bun, dependency code or project scripts and never synchronizes implicitly.

The current `demo`, `inspect`, `inspect-batch`, and `inspect-bun` are usable
supplied-metadata commands. Their candidates are not confirmed findings;
`scan` is still unavailable. More tests, a checksum match, a merged PR or fewer
open issues do not establish this program's completion.

At most one scoped delivery issue is opened for each accepted meaningful
milestone, not for every agent. Its complete approved acceptance, integration and
verification include closure/completed and Done of its existing Project item,
under my standing authorization. Epics are not closed by inference. #22, #38 and
PR #40 are not executed, closed or changed by this preparation.

## 2. Preserved matrix and prerequisites

| Native environment | Architecture | Current state | Execution prerequisite |
| --- | --- | --- | --- |
| macOS 15 | arm64 | NOT RUN / BLOCKED | Credible pre-content-open argument and designated authorized runner |
| macOS 15 | amd64 | NOT RUN / BLOCKED | Same, demonstrated natively on this architecture |
| Ubuntu 24.04 | amd64 | NOT RUN | Designated authorized runner and qualified complete access chain |
| Ubuntu 24.04 | arm64 | NOT RUN | Same, demonstrated natively on this architecture |
| Windows Server 2022 | amd64 | NOT RUN | Designated authorized runner and qualified native namespace/reparse chain |

Only a local Linux device is currently listed by Zeron. It is not a designated
Ubuntu runner. No macOS/Windows runner is designated. Missing runners are blockers,
not permission to provision or substitute platforms. Cross-compilation, emulation,
portable unit tests and one architecture cannot qualify another native row.

The original inventory targets remain npm 8.19.4/v2, npm 10.9.4/v3,
npm 11.6.2/v3, Bun 1.3.2 and Bun 1.4.2 text formats actually demonstrated by
producer fixtures, including the approved single-project/workspace layouts.
npm 12, pnpm, Yarn, binary bun.lockb and outside-root stores remain unsupported
unless separately approved. An explicit profile chooses interpretation, not
producer compatibility or registry-origin proof. Generated-producer fixtures and
package-manager execution require their own authorization.

## 3. Non-negotiable safety and evidence contract

- Open the explicit project root once; use handle-relative, traversal-resistant
  acquisition. No ancestor or independent nested-project discovery.
- Follow only qualified in-root links with cycle detection. Refuse escapes;
  explicitly qualify mount/reparse/namespace boundaries. String prefixes and
  `os.Root` alone do not meet the complete contract.
- Exclude special objects before unsafe content opening. `Lstat -> Open -> Fstat`
  and event-only/nonblocking flags are not accepted macOS device-open proofs.
- Bind observations to opened handles and before/after identity/metadata. Detect
  changes and invalidate affected comparisons; do not claim immutable snapshots.
- Reads, decoder work, worker output, entries, depth, concurrency, duration and
  memory observation use the existing numerical contracts. The 256 MiB target
  metadata budget counts also toward 16 GiB target reads; intelligence actual
  reads, including rereads, have a separate 8 GiB budget. Preserve all other
  production limits in design sections 17–18 and 21–26; no silent increase.
- Keep controlled harness writes separate from the read-only observer. Reports,
  caches and temporary files stay outside the target and cannot alias into it.
- Fail closed before acquisition when required safeguards are unavailable. An
  always-deny implementation is not positive native acceptance.
- Worker protocol remains versioned JSONL/private pipes: 1 MiB/message, 64 MiB
  cumulative both directions including separators, 64 KiB captured stderr.
  No raw-input fragmentation, unchecked allocation or worker-controlled policy,
  redaction, public exits, downloads, mutation or deletion.
- A valid completion message, EOF and normal exit plus coherent check closures
  are required; no single marker proves successful coverage. Preserve valid
  independent results after failures without presenting the whole run as complete.
- A subprocess is not a sandbox; Go memory targets, resident sampling and
  OS-specific enforced metrics are distinct. No unsupported hard-cap claim.

### Finding versus coverage

A confirmed advisory match needs supported identity, concrete version conditions,
origin correspondence and usable qualified advisory source/activity/category
context. Mere name/version, locator-derived npm names, Bun tuple claims, local
hashes and operator flags cannot supply missing authority. Preserve same-slot and
same-source bindings; ambiguous origin remains a non-enforcement candidate.

Stale, unknown, future-dated or overdue-reconciliation freshness leaves required
coverage incomplete but **retains otherwise-qualified positive findings**. It
normally yields exit 3. Missing/corrupt/unbound bytes instead make the affected
matching unavailable. Record authenticity, object digest equality, source
currentness, producer compatibility and policy are distinct facts.

Locked observations are never called observed-installed. Aliases, workspaces,
physical duplicates, unsupported sources and uncertainty must remain distinct.
Negative results require complete applicable evaluation; positives can retain
unrelated sibling gaps. Withdrawn records cannot create active findings and
unknown/contradictory corrections cannot be ignored.

## 4. Reuse and missing implementations

| Area | Reuse | Missing consumer or qualification |
| --- | --- | --- |
| npm | `ParseNPMLock`, `ProjectNPMLock`, `ProjectNPMLockNames`, `SelectNPMInput` | Qualified root-slot acquisition, producer/layout evidence, observations/reconciliation |
| Bun/manifests | Bun typed/workspace projections, manifest/declaration projections, `CompareRootRequirements` | Qualified discovery, ownership and installed observations; no invented graph resolution |
| Advisories | OSV header/times/identity/affected projections, strict SemVer and `EvaluateOSVVersionConditions` | Source/category/activity/correction and supported origin correspondence consumers |
| Intelligence | `ParseSnapshotManifest` | Actual object-byte checks/loading, record/projection binding, pinned reads, provenance/freshness interpretation |
| CLI | `ParseArgs`, `SelectScanExit` | Trusted effective policy, supervisor, common result/renderers and safe publication |
| Native | Existing Probe B contract and historical evidence only | Qualified production acquisition/monitoring/termination/publication on each row |

The manifest's 256 slots, declared lengths/counts and source timestamps are
already specified. They are not verified objects, complete retrieval, freshness
or authentication. Do not reimplement its reader or treat missing consumers as
an excuse to reopen approved numeric budgets.

## 5. CLI, reports and policy

Keep current `ParseArgs` grammar/defaults/provided-option provenance, including
manager profiles, explicit checks, fail-on, format, privacy, policy, state-dir,
output and `--` handling. Read `ScanArgumentRequest`; do not invent new flags.
Default checks remain malicious/vulnerability/integrity. An explicit advisory-only
scope reports integrity excluded, not complete three-category coverage.

Terminal default and `--format json|sarif --output -` can use stdout; a requested
file destination is a separate safe-publication boundary, not a serializer
side effect. Reject unsafe/existing/target-alias destinations and races; publish
without overwrite under an approved durability/permission contract. A failure
returns 2 without falling back to another output. Unsupported SARIF is a private
operational failure, not silent format substitution.

One common structured result retains effective trusted-policy provenance,
observations, evidence, candidates/findings, per-scope coverage and diagnostics.
Portable is default; local disclosure requires trusted effective-policy permission.
Target settings and worker messages cannot weaken policy. Preserve interruption
130, report failure 2, required gaps 3, enforcement 1, completion 0 precedence.

Existing supplied-metadata commands and schemas remain byte/exit-identical;
root help may change only when an actual accepted command implementation changes.

## 6. Parallel ownership and integration gates

| Track | Initial owner boundary | Work that can proceed | Work that stays gated |
| --- | --- | --- | --- |
| Native feasibility | Source/contract analysis; later isolated `probes/native-safety/` only after its approval | Bounded macOS pre-content-open argument from the named sources below | Other OS implementation, prototype, tools/runners/privileges, native executions and production backend adoption |
| Portable intelligence | First exact pair in section 7; later bounded intel consumers | Declared-reference/byte equality with owned inputs after approval | Filesystem loader, activation, source trust/currentness, complete records/findings |
| Inventory/result/CLI | Existing APIs and written common result/coverage/IPC contracts | Read-only design and tests/contracts accepted in later scoped deliveries | Filesystem acquisition, policy authority, render/publication integration and `scan` activation |
| Coordinator/reviewer | This brief, interface decisions, commits/publication and final checks | Merge non-overlapping accepted changes, adversarial review, record blockers | No implicit scope widening, peer approval or parent completion |

During execution use isolated jj workspaces and explicit cwd; preserve all other
heads/bookmarks/workspaces and the original 21 `.pi/todos/` deletions. One agent
owns a production file. Freeze reviewed interfaces before dependent writes.
Code review runs on the combined final tree, not only per-agent branches.

The ongoing administrator waiver remains PR-only, development-only operationally,
for approved own increments with exact-head/combined/merged-tree verification.
It is not peer approval or feature execution authorization. No direct/force push,
branch deletion, new security setting, #40 execution or release is included.

## 7. First exact portable delivery: reference-to-bytes comparison

This small implementation plan is approved for the first portable delivery only;
other program implementation stages remain gated. It adds a necessary missing content check without any filesystem or new
CLI wrapper. It is portable across the target matrix, but its tests do not
qualify native safety or producer compatibility.

**Files:** create only `internal/intel/snapshot_object_check.go` and
`internal/intel/snapshot_object_check_test.go`; update this brief's execution ledger
only after approval. Do not change the manifest reader, modules, existing
intelligence APIs, CLI or workflows.

**Exact proposed surface:**

```go
type SnapshotObjectCheckState uint8
const (
    SnapshotObjectCheckUnknown SnapshotObjectCheckState = iota
    SnapshotObjectCheckBytesEqual
    SnapshotObjectCheckLengthMismatch
    SnapshotObjectCheckDigestMismatch
)
type SnapshotObjectCheck struct {
    State SnapshotObjectCheckState
    ExpectedSHA256, ObservedSHA256 [32]byte
    ExpectedBytes, ObservedBytes uint64
}
func CheckSnapshotObject(ref SnapshotObjectReference, data []byte) (SnapshotObjectCheck, error)
```

**Contract:** compare only supplied bytes to declared SHA-256/length. Ignore raw
`Fields` and `Records` for this computation; neither is authenticated or validated
content by this function. Do not interpret locators as paths. No filesystem,
reader, clock, environment, policy, source mapping, object activation or storage.
No input/output byte sharing: result has only copied scalars/fixed arrays and
retains neither the input slice nor reference raw fields. Caller must not mutate
inputs concurrently. These internal digest fields are private, not portable
report/IPC output.

This bounded in-memory first consumer accepts at most **4 MiB** of declared or
supplied bytes per call, including exact limit. Oversize is whole-zero result plus
fixed `ParseError{Code: "limit-exceeded"}` before hashing. This scope limit is not
a reduction of the manifest's declared 32 GiB storage scope or a production read
budget change; larger objects remain unsupported by this first helper. It is not
a streaming store implementation, and it may not be used to truncate an object.

For admissible inputs always calculate observed digest/length; select length
mismatch before digest mismatch, otherwise bytes-equal. Correct empty-byte digest
and zero length match. Incorrect empty digest is digest-mismatch. A caller-forged
reference with inconsistent `Records`/raw fields still produces only this literal
byte comparison, never a valid-manifest assertion. No diagnostic echoes content,
URLs, hashes, source IDs, paths or caller strings. A bytes-equal state is not
publisher authenticity, a valid JSONL/index schema, verified record count,
projection/original binding, complete snapshot or source qualification.

### TDD and ownership

- [ ] Coordinator records exact approval before either Go file and freezes the
  proposed API/limits/interpretation. Missing-API RED then compiling behavioral
  RED must be distinguished.
- [ ] Implementation agent owns the Go pair; tests independently specify exact
  empty/ordinary/max bytes, wrong length, equal-length wrong digest, simultaneous
  mismatches, duplicate calls, input mutation after return, raw-field/path
  indifference, and over-limit reference/data with whole-zero/private error.
- [ ] Observe GREEN using existing owned inputs/toolchain only, no download.
- [ ] Fresh reviewer discriminates omitted-hash, omitted-length, reversed mismatch
  priority and limit-bypass mutations; classify compiler failures separately,
  restore exact source bytes and repeat checks. Review specifically rejects any
  result type/comment calling digest equality authenticated or snapshot-complete.
- [ ] Coordinator verifies pair scope and unchanged legacy CLI outputs, fresh root
  tests/vet/build/gofmt on final head and combined/actual merged tree, then approved
  publication/integration/closure. A native row remains NOT RUN despite unit passes.

The first behavioral RED cases are independent expected outcomes, not captured
implementation output. Start the approved test file with this executable core,
then add the exact-limit, ownership/duplicate-call and raw-field-indifference
cases named above:

```go
package intel

import (
    "crypto/sha256"
    "errors"
    "testing"
)

func TestCheckSnapshotObjectLiteralCases(t *testing.T) {
    data := []byte("owned-snapshot-fixture")
    ref := SnapshotObjectReference{SHA256: sha256.Sum256(data), Bytes: uint64(len(data))}
    wrongHash := ref
    wrongHash.SHA256[0] ^= 1
    wrongLength := ref
    wrongLength.Bytes++
    bothWrong := wrongHash
    bothWrong.Bytes++
    empty := SnapshotObjectReference{SHA256: sha256.Sum256(nil)}
    cases := []struct {
        name string
        ref SnapshotObjectReference
        data []byte
        want SnapshotObjectCheckState
    }{
        {"same", ref, data, SnapshotObjectCheckBytesEqual},
        {"empty", empty, nil, SnapshotObjectCheckBytesEqual},
        {"wrong-length", wrongLength, data, SnapshotObjectCheckLengthMismatch},
        {"wrong-hash", wrongHash, data, SnapshotObjectCheckDigestMismatch},
        {"length-before-hash", bothWrong, data, SnapshotObjectCheckLengthMismatch},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got, err := CheckSnapshotObject(tc.ref, tc.data)
            if err != nil || got.State != tc.want {
                t.Fatal("unexpected comparison outcome")
            }
            if got.ExpectedBytes != tc.ref.Bytes || got.ObservedBytes != uint64(len(tc.data)) ||
                got.ExpectedSHA256 != tc.ref.SHA256 || got.ObservedSHA256 != sha256.Sum256(tc.data) {
                t.Fatal("comparison evidence lost")
            }
        })
    }
}

func TestCheckSnapshotObjectLimitsAreWholeZero(t *testing.T) {
    oversized := make([]byte, (4<<20)+1)
    for _, tc := range []struct { ref SnapshotObjectReference; data []byte }{
        {SnapshotObjectReference{Bytes: (4<<20)+1}, nil},
        {SnapshotObjectReference{}, oversized},
    } {
        got, err := CheckSnapshotObject(tc.ref, tc.data)
        var parseErr *ParseError
        if got != (SnapshotObjectCheck{}) || !errors.As(err, &parseErr) || parseErr.Code != "limit-exceeded" {
            t.Fatal("oversize did not fail privately with a whole-zero result")
        }
    }
}
```

This is proposed test code, not executed RED/GREEN evidence. The implementation
uses only `crypto/sha256`, `len`, scalar copies and fixed error codes: preflight
both limits, compute observed values, then length/hash/equality priority. No
parallel hashing or cache is needed.

Planned local check syntax uses Nushell and no automatic toolchain/module setup:

```nu
with-env {GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: '0'} {
    go test -count=1 ./internal/intel
    go test -count=1 ./...
    go vet ./...
    go build -o $env.PACKTRACE_VERIFY_BINARY ./cmd/packtrace
}
```

These commands are **not executed by this brief**. A modified local toolchain may
provide development evidence only; official/native verification remains separate.
Before these checks, the coordinator sets `PACKTRACE_VERIFY_BINARY` to an exclusive
owned receipt-directory destination outside any target. An unset variable or an
existing destination blocks that build; do not use an arbitrary shared `/tmp` file. Preserve exact receipts and do not claim network denial
from `GOPROXY=off` alone.

## 8. Native and later-delivery authorization gates

A single owner approval may authorize **only** the section 7 Go pair and listed
owned-input development checks plus bounded source-only macOS feasibility work.
The form must separately state whether it includes the one scoped issue/PR,
development-only verified integration and scoped closure/Done; otherwise stop
before GitHub mutations. This approval never includes a native prototype,
runner/toolchain acquisition or provisioning, privileges/security changes,
qualification, production acquisition, `scan` activation, real projects, CI or
release. The rest of this program is not implicitly executable.

The source-only parallel task is limited to the macOS pre-content-open question:
the two pinned XNU `spec_open`/`VNOP_OPEN` sources linked in Probe B, the existing
cached Darwin declarations for the selected x/sys pin, and the corresponding
Go `os.Root` contract. Inspect at most those four source groups; introduce no new
module/artifact, helper, sandbox or unreviewed mechanism. Produce a bounded written
credible-argument/BLOCKED conclusion explaining the complete opening chain,
residual side effects and required native instrumentation. This is source reasoning,
never a native PASS. Other OS implementation or expanded investigation is not
inherited. Source inspection can establish a blocker; it cannot close #22 or
qualify a row by itself.

Reuse Probe B exactly, including its macOS-first order. Source/API analysis may
report BLOCKED and never authorizes an unsafe fallback, cgo, special mount/helper,
additional binding or altered build. Prototype stays isolated; no automatic
promotion into production. Fix the affected production mechanisms only after
review of actual feasibility evidence and the corresponding approved plan.

| Probe resource | Existing bound, not consumption permission |
| --- | --- |
| Each authorized native row, including cleanup | 15 minutes |
| Individual test child | 10 seconds |
| Child launches / race repetitions | 100 / 50 |
| Concurrent workers / trusted fixture mutators | 1 / 1 plus supervisor |
| Synthetic bytes / entries | 32 MiB / 1,000 |
| Deliberately touched allocation per process | 64 MiB |
| Harness-observed aggregate stop threshold | 512 MiB; not hard prevention |
| Evidence per row / stderr per child | 32 MiB / 64 KiB |
| New build cache per runner | 2 GiB |

Before any native execution separately approve its exact runner/image/kernel/
filesystem/architecture, official toolchain artifact/checksum, available cached
modules, case groups, independent timeout/recovery and cleanup ownership. Device,
mount, symlink privilege, security, acquisition and provisioning permissions are
not inherited. Use no real projects, credentials, host passthroughs or target code.

Positive regular files/in-root links must succeed; outside canaries, special-file
opening, replacement races, live changes, sampling/termination and preflight
refusal must have sufficient observations. Stop immediately on escape, observer
write, unsafe device open, uncontrolled process or absent required safeguard.
Record PASS/FAIL/BLOCKED/NOT RUN and retain failed/partial evidence, not retries
until a desired success. No runner currently meets these prerequisites.

Subsequent production tasks must freeze their input/output contracts first:
object/index/projection binding and corruption; advisory activity/correction and
source/category qualification; identity/origin equivalence; trusted policy;
common result/coverage/wire lifecycle; inventory reconciliation; each native
backend; report formats and safe publication. This list is explicit remaining
work, **not ready-to-run placeholder tasks or fabricated Go APIs**. Each accepted
milestone uses this brief and a precise scoped contract before code; no additional
ceremonial document chain or generic framework is required.

## 9. Program acceptance and abort criteria

The program is complete only with executed approved fixtures for npm/Bun,
workspaces and all five native rows; valid positive/negative/indeterminate cases;
withdrawals/corrections and stale positive retention; private-origin collisions;
unusable shrinkwrap blocking fallback; duplicate physical instances and locked
versus installed separation; data/budget/protocol failures; no target mutation or
network activity; consistent terminal/JSON/SARIF and 130/2/3/1/0 outcomes; report
collision/alias/race refusal; preserved existing metadata CLI behavior.

Use OS-enforced network denial for the actual offline qualification after its
explicit approval; no host firewall/security change is inferred. Producer fixture
creation, full integrity detection, consenting real-project pilot and release
remain separately authorized work under the original pre-1.0 requirements.
This advisory-scanner program does not claim all three detection categories or
complete integrity merely by emitting an excluded/not-run status.

Abort the affected path on unsafe access, unsupported mandatory controls, target
mutation, outbound traffic, private leakage, mismatched supporting evidence or
candidate promotion without required authority. A usable partial report retains
valid independent findings/gaps; inability to produce the requested report is an
operational failure. Do not reinterpret refusal or unexecuted acceptance as success.

## 10. Preparation ledger

- [x] Verified current development and eight open issues without new public issues.
- [x] Three parallel read-only investigations and a synthesis completed; code and
  authoritative docs checked by the coordinator. One synthesis over-gated freshness;
  corrected here against design sections 9/10 rather than adopting it silently.
- [x] Owner selected multiplatform-from-start preparation. Preserve five rows and
  original npm/Bun targets; do not narrow the scope to available local Linux.
- [x] Only local Linux is listed; runner availability and native evidence remain gaps.
- [x] Owner approved the program direction and exact first portable delivery, including scoped publication/integration/closure; other stages remain gated.
- [ ] Record separate prototype/runner/toolchain/execution gates before those actions.
- [ ] Production code, tests, publication and integration: not performed by preparation.
