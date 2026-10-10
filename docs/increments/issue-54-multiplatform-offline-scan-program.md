# Multiplatform offline scan: contract and gated delivery plan

**Status: program direction, first portable delivery and section-15 supplied-stream increment approved; native and other later gates remain unapproved.** I selected simultaneous agents and then selected
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

### 8.1 Executed bounded source-only analysis

**Baseline:** `45b3424cc5120a479dbacefa34de6a8d737d9514`  
**Scope:** the four authorized source groups only. No prototype, build, type-check command, native query, or execution occurred.

#### Conclusion: BLOCKED

The bounded sources do not establish an end-to-end macOS mechanism that obtains a stable metadata-only reference, verifies that the referenced object is regular, and then opens **that same object** for content without first risking a device-driver open. This is not a finding that macOS support is impossible; it is a finding that the approved API/source surface supplies no proved chain.

#### Attempted chain and break

1. Go 1.27.1 `os.Root` provides beneath-root path containment and follows only links that remain beneath the root. Its contract expressly says Root methods do **not** prohibit filesystem-boundary traversal or access to Unix device files ([`Root`](https://pkg.go.dev/os@go1.27.1#Root)). `Root.Lstat` returns metadata, while `Root.Open` opens for reading ([`Root.Lstat`](https://pkg.go.dev/os@go1.27.1#Root.Lstat), [`Root.Open`](https://pkg.go.dev/os@go1.27.1#Root.Open)). Therefore `Lstat → Open` has a replacement window and provides no same-object guarantee.
2. The repository pin is `golang.org/x/sys v0.44.0` (`probes/scalibr-inventory/go.mod:47`, `go.sum:152-153`). Its Darwin arm64 and amd64 generated files are selected by `darwin && arm64` / `darwin && amd64`, with no `cgo` build predicate ([arm64](https://github.com/golang/sys/blob/v0.44.0/unix/zsyscall_darwin_arm64.go#L1-L10), [amd64](https://github.com/golang/sys/blob/v0.44.0/unix/zsyscall_darwin_amd64.go#L1-L10)). The selected declarations expose `Openat`, `Fstat`, and `Fstatat` ([arm64 open](https://github.com/golang/sys/blob/v0.44.0/unix/zsyscall_darwin_arm64.go#L1806-L1841), [arm64 stat](https://github.com/golang/sys/blob/v0.44.0/unix/zsyscall_darwin_arm64.go#L2602-L2629)); `Stat_t.Mode` and `S_IFMT`/`S_IFREG` make a source-level regular-file test expressible ([type](https://github.com/golang/sys/blob/v0.44.0/unix/ztypes_darwin_arm64.go#L65-L84), [mode constants](https://github.com/golang/sys/blob/v0.44.0/unix/zerrors_darwin_arm64.go#L1420-L1427)). These declarations are compatible with the stated Darwin architectures and CGO-disabled constraint at the source/build-tag level, but no compile or type-check result is claimed.
3. `Fstatat` returns metadata, not a stable object reference. A later `Openat` resolves the name again. `Fstat` binds metadata to the returned descriptor only **after** open. Thus `Fstatat → mode check → Openat → Fstat` cannot exclude a regular-to-device substitution before the open.
4. Flag declarations alone do not establish the missing same-object/pre-driver chain. `O_NOFOLLOW`/`O_NOFOLLOW_ANY` address symlink following, not a leaf changing from regular to special; rejecting all links also cannot satisfy the required positive in-root-link behavior. `O_SYMLINK` references a symlink rather than yielding a regular-content descriptor. `O_EVTONLY` and `O_NONBLOCK` remain open flags, not regular-only predicates ([Darwin constants](https://github.com/golang/sys/blob/v0.44.0/unix/zerrors_darwin_arm64.go#L1121-L1143)).

#### Kernel-side consequence

Within a call to pinned XNU `VNOP_OPEN`, the reviewed wrapper dispatches through the vnode open operation ([`kpi_vfs.c:2534-2553`](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/bsd/vfs/kpi_vfs.c#L2534-L2553)). If that dispatch reaches `spec_open` for a special vnode, `spec_open` calls the character driver's `d_open` at line 397 or the block driver's `d_open` at line 447 ([`spec_vnops.c:353-481`](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/bsd/miscfs/specfs/spec_vnops.c#L353-L481)); successful special opens can also proceed to device-specific ioctls. The reviewed callee bodies contain no `O_EVTONLY` bypass, but the upstream user-open path was outside the authorized source groups, so this review does not prove that every candidate flag combination reaches `VNOP_OPEN`. It proves only that, **if** special-open dispatch reaches these callees, driver `d_open` occurs. Neither the reviewed flag declarations nor these callee bodies establish that `O_EVTONLY` or `O_NONBLOCK` avoids that dispatch; therefore they do not establish pre-driver exclusion.

#### Missing evidence and required next decision

Unblocking requires either (a) an established public API/flag that atomically returns a metadata-only stable reference without invoking special-device open and permits content-open of the same verified regular object, or (b) separately approved design change for a new binding, helper, sandbox, special mount, or altered build. Later native approval must also provide instrumentation proving no driver-open callback occurs before rejection, descriptor/object identity across the content-open transition, deterministic replacement-race coverage, and the actual macOS kernel/API match. Source inspection alone cannot provide those proofs.

#### Native matrix

| Environment | Architecture | Status |
| --- | --- | --- |
| macOS 15 | arm64 | NOT RUN |
| macOS 15 | amd64 | NOT RUN |
| Ubuntu 24.04 | amd64 | NOT RUN |
| Ubuntu 24.04 | arm64 | NOT RUN |
| Windows Server 2022 | amd64 | NOT RUN |

**Uncertainty:** XNU `11215.1.10` is a pinned reasoning reference, not evidence for any future runner’s installed kernel. Absence of a proved mechanism in these four groups is not proof that no mechanism exists elsewhere.

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
- [x] Preparation did not execute production code/tests/publication/integration.
  The separately approved first-delivery execution follows below; native gates remain open.


## 11. First portable delivery execution ledger — issue #54

I approved section 7 and the bounded section 8 source-only analysis before Go,
recorded in `cd8319f8210d22e3ae1089ea413b843262e4a998`. I selected one scoped
issue under #9, PR publication and development-only verified integration under
my ongoing PR-only administrator waiver, followed by scoped closure/Done.
This is not permission to execute the remaining program or close a parent.

- [x] Frozen interfaces: existing `SnapshotObjectReference`/`ParseError` unchanged;
  exact section 7 scalar comparison API and 4 MiB declared/supplied bounds.
  Implementer owns only the new Go pair; analyst owns no product source.
  One coordinator owns brief/GitHub/jj/final evidence. No shared-write conflict.
- [x] Missing-API RED: one compiler build-fail, zero behavioral fail actions.
- [x] Compiling-stub RED: 11 expected test/subtest failures, no build-fail or
  stderr. GREEN: 11 focused passes, root 3,079 passes (baseline 3,068).
- [x] Fresh independent task agent: spec and quality approved, no Critical,
  Important or Minor findings. Agent review is not GitHub peer approval.
- [x] Four actually compiling mutations detected and byte-exactly restored:
  omitted digest branch (3 test failures), omitted length branch (3), reversed
  mismatch priority (2), omitted 4 MiB preflight (1). None is compile-only.
- [x] Coordinator fresh restored-source focused/root tests, vet/build/gofmt.
  162 owned legacy CLI case/format comparisons were stdout/stderr/exit-identical:
  72 npm inspect, 40 batch, 12 demo, 38 Bun (19 cases in both formats).
- [x] Parallel source-only macOS analysis completed; result BLOCKED in section
  8.1, five native rows NOT RUN. Callee evidence does not prove the upstream
  flag path; I narrowed the report instead of claiming event-only always unsafe.
- [x] Reviewer declines ruled: suite/mutation repetition was reserved for the
  coordinator and performed there; no named unchanged-source risk required
  extra crawling; macOS/native execution lies outside the Go task. Accepted.
- [ ] Final documentation delta/whole-branch review and exact public head checks.
- [ ] PR publication, combined-tree and actual merged-tree verification.
- [ ] Accepted bounded issue closure/completed and existing Project item Done.

All executed Go evidence is modified local `go1.27.1-X:nodwarf5 linux/amd64`,
`GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0`. These command settings
do not prove OS-enforced network denial, official/native/producer/hosted-CI/release
qualification or authenticated/active intelligence. `scan` remains unavailable;
equality is literal supplied-byte evidence, not manifest/schema/record validation.
The manifest's separate 32 GiB declared-object ceiling is unchanged.

Issue #9 remains incomplete; #22/#38/PR #40, other epics, native gates and
unrelated work are unchanged. The 21 unrelated task-ledger deletions also visible
in the new workspace were excluded from every explicit file-scoped commit,
left unpublished and un-restored. Source bookmarks/workspaces remain preserved.

## 12. Approved portable format contract — implementation approved for #56

I selected **Contrato + macOS (recomendado)** to prepare this continuation and
execute only the explicitly bounded public-source study in section 13. That
selection is not approval of this new format or Go implementation. The work
forks from `f7689f2e3c46a30f098a748a364d4690d8140b5e`; #54/PR #55's bounded
first delivery is completed, independently checked and integrated. Its section
11 describes its authored pre-publication state; final acceptance/closure is
recorded in [PR #55](https://github.com/landroval/PackTrace/pull/55#issuecomment-6102281863).

### Approved portable snapshot-block consumer contract

**Status:** I approved this format contract by selecting **Aprobar 1.1 y preparar plan (recomendado)**. This approves catalog + separate record objects and explicit manifest 1.1, and authorizes preparing its implementation plan only. It is not Go, publication or native execution authority. Base: `f7689f2e3c46a30f098a748a364d4690d8140b5e`. I preserve the approved 256 JSONL matching blocks. The approved continuation resolves row/hash/original binding; it does not respecify the existence of those blocks.

#### Two format alternatives

1. **Offsets into one exact-originals blob.** Each block row names an original byte range and its record digest. This minimizes object count, but a scan cannot establish the enclosing blob’s manifest digest without reading the whole blob. A valid blob may approach the 32 GiB declared-store ceiling while one scan has only 8 GiB of actual intelligence reads. Range hashing proves a record, not the declared blob. I do not recommend this dead end.

2. **Catalog plus separate exact original-record objects (recommended).** The manifest’s `originals` reference names a JSONL occurrence catalog; each catalog row names one content-addressed exact OSV record object. A matching row binds identity and affected slot to that catalog occurrence and object digest. A query reads one matching block, the catalog, and only selected original objects. Standard-library JSON, SHA-256, UTF-8 validation, buffered line reading with an explicit cap, and checked counters suffice; no database, binary index, or dependency is justified.

**Approved compatibility decision:** I selected alternative 2 and the new manifest format `1.1`, whose `originals` object is the occurrence catalog. This byte layout is not smuggled into `schemaVersion: "1.0"`. `ParseSnapshotManifest` and existing 1.0 behavior remain unchanged until separately approved implementation; a 1.0 manifest is not interpreted as this new layout.

#### Recommended exact format

All digests are lowercase 64-character SHA-256 hex. All integers are canonical unsigned decimal JSON numbers (`0` or a nonzero digit followed by digits; no sign, fraction or exponent), checked for uint64 overflow before allocation. `sourceOrdinal` ranges from 0 through 1,999,999; each original `bytes` is 1 through 4,194,304; `affectedIndex` must fit and name an actual projected slot. Catalog physical rows are capped at 2,000,000; the sum of physical rows across the 256 blocks is independently capped at 2,000,000, preserving the existing declaration limits. Catalog and block objects are UTF-8 JSONL with no BOM and no blank lines. A zero-byte object has zero rows and no separator; a nonempty object uses LF separators and a required final LF. CR and therefore CRLF are invalid. Each physical line is exactly one JSON object; invalid UTF-8, unpaired surrogates, trailing bytes within a line, unknown/missing fields, or duplicate decoded keys are fatal for that object. Whitespace inside a line is permitted and remains digest-significant.

The **catalog row** has exactly:

```json
{"v":1,"sourceOrdinal":0,"sha256":"<64hex>","bytes":123}
```

`sourceOrdinal` is contiguous from zero and fixes source occurrence order. The physical catalog row count must equal `manifest.originals.records`; its exact byte count and SHA-256 must equal the `originals` reference. Repeated `sha256` values are allowed because duplicate source occurrences remain distinct; equal digests must declare equal lengths. Before preparation deduplicates an object, it must additionally compare both admitted exact byte sequences byte-for-byte, not infer byte identity from hash and length alone. Distinct bytes under the same digest/length make preparation unavailable; do not silently discard either occurrence or overwrite an addressed object. Reading one already-stored object cannot prove that upstream deduplication was correct. Only verified byte-identical originals are stored once. A repeated or skipped ordinal is invalid. Each original record is stored at the existing content-addressed object location selected by its digest, never by an upstream path.

The **matching-block row** has exactly:

```json
{"v":1,"identityHash":"<64hex>","ecosystem":"npm","name":"exact decoded name","sourceOrdinal":0,"originalSHA256":"<64hex>","originalBytes":123,"affectedIndex":0}
```

This first row format supports npm only. Identity hashing is SHA-256 of ASCII `npm`, one NUL byte, then the exact npm-name UTF-8 bytes accepted by the existing OSV npm identity validator. That name grammar excludes NUL, so no custom length framing is needed. No trimming, case-folding, Unicode normalization, PURL substitution, or alias expansion occurs. Block index is the unsigned value of digest byte zero. Every row’s hash must recompute and select its containing block.

Block rows are strictly increasing by `(identityHash, ecosystem UTF-8 bytes, name UTF-8 bytes, sourceOrdinal, affectedIndex)`; an equal tuple is an invalid duplicate. The same original may legitimately have several affected slots, and duplicate source occurrences remain separate ordinals. The physical block row count must equal that slot’s manifest `records`; exact block bytes and SHA-256 must equal that block reference.

A hash hit is only routing. The consumer must compare exact ecosystem and name and must reject neither legitimate collisions nor silently combine them. It loads the named catalog occurrence and requires catalog digest/length to equal the row. It then verifies the exact original object’s digest/length, parses those same bytes with `ParseOSVRecord`, projects header, affected, npm identity and times, and requires all projection source hashes to equal `originalSHA256`. It retains original version/range evidence without evaluating it: `EvaluateOSVVersionConditions` needs a concrete version query and belongs to the subsequent matching consumer, not this identity-only reader. `affectedIndex` must exist; that exact slot must reproduce the row’s npm ecosystem/name and identity hash. Different slots never lend identity, version support, activity, or uncertainty to one another.

Byte and row cross-binding does not establish index completeness. A hash-valid block may omit a relevant original/slot or retain an older correction; reading only selected originals cannot detect that. Every admitted source occurrence remains as an exact original object in the occurrence catalog, including non-npm records, unroutable/unknown-identity records and withdrawn records without ecosystem. Only qualified npm slots produce this format's matching rows; others are retained, not silently discarded. Complete retrieval, current correction selection and definitive no-match require a separately qualified preparation/index contract; until then retrieval/correction coverage is explicitly unqualified. This consumer cannot turn an empty selected block into a definitive negative. The row is deliberately not an activity or correction verdict. Exact original bytes retain all affected/version fields, withdrawal claims, unknown fields, and correction evidence. The consumer reports withdrawal as reported/not-declared/unknown, never “active”; not-declared is absence of a withdrawal claim, not proof of activity. Until a separately approved corrections consumer exists, correction status remains explicitly unqualified and blocks a correction-free or complete applicability claim. Unusable slots and unsupported version conditions remain visible uncertainty. Nothing here yields authenticated source, active snapshot, trusted origin, complete coverage, a confirmed finding, or enforcement eligibility.

#### Data flow and budgets

For one npm identity, compute its hash and select exactly one of the already-specified 256 blocks. Stream that block once while simultaneously counting physical bytes/rows, validating rows, and hashing all exact bytes; retain only full-identity matches, but release no result until the whole block reference verifies. Then stream and verify the catalog once, retaining bindings only for selected ordinals. Finally, read each selected unique original object once, bounded by the existing 4 MiB OSV-record limit, and apply the existing in-memory object check and OSV projections.

The 4 MiB helper is valid for each original record only. It must not be applied to or used to truncate a larger block or catalog. Those objects require bounded streaming verification by the actual reader. Hashing and parsing should share each read; any retry or deliberate second pass counts again.

Before each read, compare the declared length with the remaining **8 GiB actual local-intelligence read budget** as a preflight only; do not charge that declaration and then charge the same bytes again. Charge each actually returned byte exactly once. Limit each request to remaining global bytes and the expected object length plus one detection byte. If the global budget is exhausted before complete length/EOF evidence is established, leave that object unavailable rather than make a further positive-byte read or infer EOF. EOF-only observations charge zero bytes; detection bytes and every reread count. Catalog, block, originals, verification, and rereads all count, without phase resets. A manifest may validly declare up to 32 GiB of store objects yet be unscannable for a query whose required reads exceed 8 GiB; that produces explicit unavailable/incomplete matching, not manifest invalidity and not a limit increase. This layout avoids requiring the full original feed merely to verify one query.

The proposed 1.1 snapshot-reference validation boundary must verify the catalog and apply the 32 GiB per-snapshot unique-declared-byte limit to catalog, all 256 block references and every catalog-referenced original together, deduplicating consistent declared digests/lengths with checked arithmetic. It refuses per-snapshot declared-size validity if the catalog is unavailable; it does not infer actual storage or byte-identity validation from that arithmetic. The unchanged 1.0 manifest parser accounts only for its direct references and cannot establish this 1.1 check. The consumer may expose partial verified evidence without the per-snapshot validity verdict, but must label that gap. The separate 32 GiB global managed-store quota also covers other manifests, retained snapshots and staging; only the separately approved store/quota authority can enforce or attest that global occupancy. Selected-block corruption makes that hash slot unavailable but does not invalidate verified sibling blocks. One corrupt original makes every selected row bound to that digest unavailable; independently verified sibling originals survive. Catalog corruption prevents catalog cross-binding for selected rows, so they remain unavailable, while independently valid nonmatching evidence is retained. No corruption becomes an empty/no-match result.

#### Next smallest meaningful consumer slice

The next consumer should accept an already parsed manifest plus supplied catalog, selected-block, and selected original-object byte streams under one read counter, and return owned, source-ordinal/affected-slot-bound OSV evidence for one npm identity. It should perform routing, complete object/row cross-binding, original parsing, existing projections, and conservative uncertainty retention. The exact streaming API, memory/retained-projection/line bounds, cancellation and parser-version change belong in the implementation plan after owner approval of this format. Those are explicit execution blockers, not implementation authority or implicit unlimited buffering. It should not be another scalar helper or CLI wrapper, and it should not open files, publish/activate snapshots, qualify sources, interpret native paths, or produce findings. Actual filesystem reading, safe publication, native controls, snapshot selection, source qualification, activity/correction policy, and public reporting remain separate gates.

#### Acceptance cases

- Exact catalog/block/final-LF bytes; empty objects where permitted; invalid BOM, CRLF, missing final LF, blank line, malformed UTF-8/surrogate, duplicate key, noncanonical integer, unknown field, and row/count mismatch.
- Exact and repeated source occurrences; declared digest/equal length retained across ordinals, but preparation deduplication requires byte-for-byte equality. Test conflicting supplied bytes under equal claimed digest/length failing preparation without replacement (not a claimed executed true SHA-256 collision). Conflicting lengths, skipped/repeated ordinals and duplicate matching tuples are rejected.
- Correct slot; forged hash; wrong block; two real distinct identities sharing a block-byte prefix retained then separated by exact ecosystem/name (no fabricated full SHA-256 collision execution claim); no cross-slot support.
- Manifest-to-block, block-to-row, row-to-catalog, catalog-to-object, and object-to-projection digest/length/index mismatches, each failing closed without private content in errors.
- Exact 4 MiB original accepted and +1 rejected; a block larger than 4 MiB streamed successfully; declared preflight versus actual/reread accounting at 8 GiB, including refusal when no complete EOF evidence is available at exhaustion, and over-budget declarations while a 32 GiB-declared manifest remains structurally valid.
- Withdrawn, no-withdrawal-claim, malformed withdrawal, unsupported version sibling, unknown correction, duplicate originals, corrupt selected block, corrupt one original, and valid sibling retention—all without authenticated/active/trusted-origin/coverage/finding claims.

Preparation failure must not silently omit or truncate an original that exceeds
the existing 4 MiB OSV-record limit, or exceed the format/store bounds merely to
fit source data. Such a preparation remains unavailable; the previous accepted
snapshot and source-check timestamps are not refreshed by an incomplete update.
This states intended future behavior, not implemented snapshot activation.

## 13. Executed bounded upstream macOS source study

### macOS upstream source report — `O_EVTONLY`

#### Outcome

**Credible partial SOURCE argument; full safety claim BLOCKED.** The authorized XNU sources do **not** support a guarantee that `open/openat(..., O_EVTONLY, ...)` obtains a metadata/event reference to every vnode without special-device driver activity before an `fstat` regular-file check. On the ordinary `VNOP_OPEN` path, special vnodes reach driver `d_open` callbacks, and disk devices may receive ioctls. A complete permission-positive chain and universal result are blocked by out-of-scope callees, especially compound-open, authorization, process-policy, and generic read-entry code.

#### Source argument

1. **Flags and syscall entry.** In `fcntl.h`, `O_EVTONLY` is `0x00008000` (“event notifications only”). `FFLAGS` converts `O_RDONLY` (zero) into kernel `FREAD`. In `vfs_syscalls.c`, `open`/`openat` enter `openat_internal` → `open1at` → `open1`. `open1` strips `FREAD|FWRITE` only when both `O_EVTONLY` and `proc_disallow_rw_for_o_evtonly(p)` are true, then calls `vn_open_auth`. The policy callee is outside the allowed files, so when/for whom stripping applies is **BLOCKED**.

2. **Authorization/open dispatch.** `vn_open_auth` may use `VNOP_COMPOUND_OPEN`; success suppresses the later `VNOP_OPEN`. The compound implementation and mount-specific availability are outside scope, so that branch is **BLOCKED**. On the traditional branch, it calls `vn_authorize_open_existing` and then `VNOP_OPEN`. The authorization implementation is outside scope, so absence of a denial here is not a complete positive permission chain.

3. **Special-device consequence on the demonstrated branch.** `kpi_vfs.c:VNOP_OPEN` dynamically invokes the vnode's open operation. `spec_vnops.c` maps `vnop_open_desc` to `spec_open`. `spec_open` has no `O_EVTONLY` bypass:
   - `VCHR`: calls `cdevsw[maj].d_open`; disk-character devices can then issue `VNOP_IOCTL` initialization queries.
   - `VBLK`: calls `bdevsw[maj].d_open`; success can then issue block-size/count ioctls.
   - `open1` can additionally issue `TIOCSCTTY` for a tty unless `O_NOCTTY`/process state prevents it.

   This is a conditional driver-opening path if its earlier authorization/dispatch conditions allow it. The bounded sources do not establish that the path is reachable for every process/flag combination, or that it is excluded for every such combination; a universal callback-free event-open guarantee remains unproved. This does **not** imply devices must be rejected at flag-validation time; a genuinely callback-free metadata reference could safely represent and later reject them, but these sources do not establish that behavior.

4. **`fstat` comes too late for that guarantee.** `kern_descrip.c:fstat` obtains the existing vnode and calls `vn_stat_noauth`; `vfs_vnops.c:vn_stat_noauth` calls `vnode_getattr` and maps `VREG`, `VCHR`, and `VBLK` to the corresponding `st_mode` type. The mapped `spec_getattr` implementation is outside the six XNU files, so whether the stat operation itself is callback-free is **BLOCKED**. Regardless, the demonstrated `spec_open` callbacks precede this check.

5. **Same-vnode content transition.** `open1` stores the vnode in the fileglob; `vn_read` later reads that same stored vnode and propagates `IO_EVTONLY` to `VNOP_READ`. Thus, if `FREAD` was retained and generic read admission permits it, the same fd/vnode can reach content I/O without path re-resolution. Those conditions are **BLOCKED** because the process-policy and generic syscall read gate are outside scope. If `FREAD` was stripped, inspected public transitions do not restore it: `F_SETFL` changes only `FCNTLFLAGS` (not `FREAD/FWRITE`), while dup paths share the fileglob and `dupfdopen` forbids requesting broader access. `F_GETPATH` followed by `open` would re-resolve a path. Absence of another transition from these files alone is not proof that none exists.

#### Go/public surface

The two preselected cached `x/sys` v0.44.0 files show, for Darwin/arm64, public `unix.O_EVTONLY = 0x8000`, and declarations for exported `Open`, `Openat`, `Dup`, plus the unexported `read` syscall stub. That lowercase stub is not itself a public Go read API. They do not establish the complete `Fstat` surface, generated-stub chain, non-arm64 parity, or a CGO-free build property; those remain **BLOCKED**, with no inherited proof.

#### Preserved native qualification matrix

Regular-file event-open/read, device callbacks/ioctls, `fstat` behavior and same-vnode transitions are all unexecuted source hypotheses.

| Native environment | Architecture | Status |
|---|---|---|
| macOS 15 | arm64 | **NOT RUN / BLOCKED** |
| macOS 15 | amd64 | **NOT RUN / BLOCKED** |
| Ubuntu 24.04 | amd64 | **NOT RUN** |
| Ubuntu 24.04 | arm64 | **NOT RUN** |
| Windows Server 2022 | amd64 | **NOT RUN** |

#### Exact sources and anchors

- `https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/vfs/vfs_syscalls.c` — `openat_internal`, `open1at`, `open1`
- `https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/vfs/vfs_vnops.c` — `vn_open_auth`, `vn_open_auth_finish`, `vn_read`, `vn_stat_noauth`
- `https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/sys/fcntl.h` — `O_EVTONLY`, `FFLAGS`, `FMASK`, `FCNTLFLAGS`
- `https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/kern/kern_descrip.c` — `fstat`, `sys_fcntl_nocancel`, `dupfdopen`, `fo_read`
- `https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/vfs/kpi_vfs.c` — `VNOP_OPEN`
- `https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/miscfs/specfs/spec_vnops.c` — `spec_vnodeop_entries`, `spec_open`, `spec_ioctl`
- Existing cache only: `golang.org/x/sys@v0.44.0/unix/zerrors_darwin_arm64.go`, `unix/syscall_darwin.go`.

All six authorized HTTP fetches succeeded; no source-fetch uncertainty. Scope used: **8 files**. Fetcher reported **848,226 characters** for XNU; both selected cached files measured **115,369 bytes**. Character count is not byte count: a conservative four-byte-per-character UTF-8 upper bound plus the measured cache bytes is **3,508,273 bytes**, below 8 MiB. This is an upper bound, not an observed exact UTF-8 byte total. The analyst supplied no reliable elapsed-time measurement; it must not be represented as a measured 15-minute qualification result.

Coordinator budget read-back: the analyst chat was created at
`2026-10-10T21:37:48.744Z` and recorded its last activity at
`2026-10-10T21:40:36.439Z`. That observed harness wall-clock interval is about
168 seconds, below the approved 15 minutes; it is not a monotonic native-runtime
measurement or platform qualification. No additional source groups were followed.

## 14. Historical continuation preparation ledger

This records the preparation stage. Its no-execution/no-publication statements apply to that stage; the later bounded approval and execution are recorded in section 16.

- [x] Current development verified; exactly eight existing issues and draft PR
  #40 remain outside this design's tracking scope. No new issue, PR or push.
- [x] Two read-only scouts identified the next consumer and source-study scopes.
  The initial scout wrongly treated JSONL block format as unspecified; corrected
  against design section 25. Only row/hash/original binding is newly proposed.
- [x] Owner explicitly selected combined contract/source preparation, not Go.
- [x] Independent drafting and bounded source-reading agents ran concurrently;
  neither owns product source. One coordinator edits this single brief only.
- [x] Coordinator narrowed unsupported native universal/path claims, retained
  missing-callee/read-policy/binding proof, restored the five platform rows,
  corrected private versus public Go declarations and character/byte accounting.
- [x] Coordinator corrected the draft's query-free version evaluator claim,
  identity-hash over-framing, byte-budget double charging, missing catalog object
  accounting, full-hash collision test claim and missing index-completeness gap.
- [x] Fresh independent contract review: READY FOR OWNER REVIEW, no unresolved
  Important findings. First-pass findings required byte-equality before
  preparation deduplication, explicit non-npm retention and assignment of the
  1.1 aggregate declaration check; corrected above. The reviewer accepted the
  first-person attribution ruling: text intentionally represents the owner,
  who explicitly selected preparation; it is not an assistant permission claim.
  The non-semantic Markdown escape issue was corrected before this checkpoint.
- [x] Owner approved catalog + separate records and explicit format 1.1;
  selecting **Aprobar 1.1 y preparar plan** authorizes planning, not execution.
- [x] Exact implementation plan prepared in section 15 with proposed
  streaming/memory/line/cancellation bounds, frozen interfaces, file ownership
  and required TDD/mutation checks; none of those checks has been executed.
- [x] Fresh independent static plan review: READY FOR OWNER REVIEW after
  coordinator corrections. Five first-pass and four follow-up Important issues
  resolved: BOM/framing discrimination, cancellation precedence/actual charging,
  fatal block/catalog read errors, the production row-counter boundary, and a
  reproducible SHA-pinned 162-case legacy matrix with distinct fresh executables.
  Minor duplicate/nil semantics, temporary-retention accounting, digest assertions
  and source-guard wording were corrected. No Go/test/mutation/native execution
  or GitHub peer approval is represented by this documentary review.
- [x] I approved section 15, its frozen API/resource profile and the full-cycle
  supplied-stream increment by selecting **Ciclo completo (recomendado)**.
  Section 16 records that scope before the first new Go change; other gates remain closed.

At the preparation stage, no new Go or product execution was authorized or performed. Section 16 subsequently authorized only the bounded supplied-stream delivery. Native prototypes/queries/runs, dependencies/toolchains, privilege or security changes, real-target access, provisioning, CI and release remain unauthorized and unperformed in this continuation. `scan` remains unavailable. Preserve all five qualification rows, #22/#38/PR #40 and all capability parents; do not narrow to local Linux or close #22 from a source argument. Unrelated task-ledger deletions remain unpublished and un-restored. This approved format and consumer are not complete scanner authorization.

## 15. Supplied-stream npm snapshot-block consumer implementation plan — approved for #56

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` only after the owner approves this complete plan and separately authorizes implementation. Use a fresh implementer for each task, a fresh reviewer after task 1 before task 2, a fresh reviewer after task 2, and a fresh whole-branch reviewer before publication/integration. Steps use checkbox (`- [ ]`) syntax. Execution authority is the bounded section-16 owner approval, not an inference from drafting. No native work, target acquisition or other out-of-scope action is authorized.

**Goal:** Add the smallest complete supplied-stream consumer for one exact npm identity—also used unchanged for Bun packages that consume npm advisories—using explicit manifest 1.1, one selected matching block, the occurrence catalog, and selected exact original OSV streams.

**Architecture:** Preserve `ParseSnapshotManifest` as the format-1.0-only entry point and add a separate `ParseSnapshotManifestV11` entry point over one shared private manifest core. A pure `internal/intel` consumer accepts an already parsed 1.1 manifest and caller-supplied `io.Reader`s, verifies the selected block and catalog as bounded JSONL under one actual-read counter, reads each selected unique original once, and returns one owned original/projection object with a binding list for every source-ordinal/affected-slot occurrence. It does not open paths, select/activate snapshots, evaluate versions, decide findings, or claim source/index/correction/activity completeness.

**Tech Stack:** Go 1.27.1, standard library only, existing `internal/jsoninput.Object`, `SnapshotManifest`, `CheckSnapshotObject`, `ParseOSVRecord`, `ProjectOSVHeader`, `ProjectOSVAffected`, `QualifyOSVNPMIdentities`, and `ProjectOSVTimes`. No dependency or module changes.

**Spec:** `docs/increments/issue-54-multiplatform-offline-scan-program.md` sections 12 and 14 at the implementation base selected by the coordinator. The approved catalog + separate record-object format and manifest 1.1 control. The coordinator alone edits that brief.

### Status and authority

I first approved the section-12 **format** and selected **Aprobar 1.1 y preparar plan**, which authorized preparation only. After the independent static plan review and coordinator corrections, I selected **Ciclo completo (recomendado)** for the complete section-15 plan at `c722c8acc565a64cf6f3f7796025907d80f3e221`. This separately approves the frozen internal API/resource profile, subagent-driven Go/TDD/restored mutations, synthetic checks/162 legacy comparisons, issue #56 under #9, PR/development integration and this child's scoped closure/Done. Section 16 records the approval before code. No filesystem/native/store-path acquisition, probes, targets, dependencies/toolchains, CI/release, security changes or `scan` activation is authorized. Historical #54/PR #55 authorization was not reused as permission.

### File map

- Modify `internal/intel/snapshot_manifest.go`: keep public 1.0 behavior exact; route it and the new explicit 1.1 entry point through one private core.
- Modify `internal/intel/snapshot_manifest_test.go`: pin 1.0 non-acceptance of 1.1 and the explicit 1.1 path without weakening any existing 1.0 tests.
- Create `internal/intel/snapshot_npm_stream.go`: frozen stream API, strict JSONL readers, one actual-byte counter, catalog/block/original binding, complete declared-size check, projection reuse, and conservative gap output.
- Create `internal/intel/snapshot_npm_stream_test.go`: synthetic supplied readers and exact TDD, framing, binding, budget, sibling-retention, ownership/privacy, and authority-gap cases.
- Do not modify `go.mod`, add `go.sum`, create fixtures under real projects, add a CLI wrapper, or add filesystem/native/store/source/report code.

### Decisions resolving specification/implementation tensions

1. **Known corruption fails only this scoped call.** A known malformed/hash-corrupt/length-corrupt selected block or catalog prevents trustworthy binding for this one query call, so the call returns a fixed whole-zero error. This is consistent with section 12's unavailable matching semantics: other independently invoked hash-slot/snapshot calls remain unchanged. It is not snapshot-wide invalidation, preparation/activation authority, or an override of the contract's broader future partial-record design.
2. **Resource unavailability is not corruption.** A declared object that cannot be completely read under the fixed 8 GiB counter, a line beyond this consumer's 1 MiB profile, or a retained-result bound produces an explicit resource gap. It never becomes format invalid, empty/no-match, or a declaration-valid verdict. Already verified independent original siblings within the same call may remain.
3. **Complete declared-size validity is catalog-dependent.** Manifest parsing validates the 257 direct references exactly as 1.0 does. Only a fully structured catalog permits the 32 GiB unique-declared-byte check across catalog + all 256 blocks + every catalog-referenced original. Valid declarations over 32 GiB are fatal `limit-exceeded`; an unavailable catalog leaves `SnapshotDeclarationGap`.
4. **Stored-byte identity and quota remain outside the consumer.** The returned gaps always include preparation byte-identity and global managed-store quota. Reading one addressed object cannot prove preparation compared duplicate admitted byte sequences, and this call cannot attest occupancy across retained snapshots/staging.
5. **Cancellation is cooperative around `Read`, not interrupting.** `context.Context` is checked before and after every `Read`. An arbitrary `io.Reader` may block indefinitely inside `Read`; this API starts no goroutine, closes no reader, exposes no caller-supplied callback, and claims no deadline enforcement. Private synchronous sink/visitor functions are implementation details, not cancellation mechanisms. A future native worker owns deadlines/termination.

### Global Constraints

- `ParseSnapshotManifest([]byte)` remains 1.0-only with the same result/error precedence and accepts no 1.1 input. `ParseSnapshotManifestV11([]byte)` accepts exactly nonempty string `"1.1"`; it does not default, upgrade, reinterpret, or accept 1.0.
- Manifest 1.0 and 1.1 share one private parser body and the existing 1 MiB envelope, 256 positional blocks, 2,000,000 logical block-row declaration ceiling, direct-reference coherence, and 32 GiB direct unique-declared-byte check. No second manifest implementation. The consumer accepts an unchanged parsed 1.1 value and cheaply rechecks consumed typed direct-reference indices/ranges/coherence/aggregate counters before any read; it neither reparses manifest JSON nor authenticates fabricated values.
- One query is ecosystem `npm` plus an exact existing-profile npm name. Bun passes its npm package identity through this same API; no Bun format branch or alias is added.
- Identity hash is SHA-256 over bytes `npm`, NUL, exact name. Block index is digest byte zero. No trim, fold, normalization, PURL substitution, alias expansion, or full-hash collision fabrication.
- Catalog and block objects are caller-supplied streams only. No `os.Open`, paths, native handles, store locator, source locator, registry, HTTP, package-manager, CLI, or exported/caller-supplied acquisition callback.
- JSONL objects: zero bytes means zero rows; nonempty means LF-separated rows with a required final LF. BOM, CR/CRLF, blank line, missing final LF, invalid UTF-8/surrogate, trailing line bytes, duplicate decoded key, unknown/missing field, noncanonical integer, row/count mismatch, sort violation, and duplicate block tuple are fatal for that object.
- Consumer line profile: at most 1,048,576 content bytes before LF. Whitespace remains digest-significant. A longer otherwise-uninspected line is `SnapshotGapResource`, not proof of malformed format; the entire referenced object must still verify before returning that gap.
- Catalog rows: at most 2,000,000, ordinal exactly physical row index, bytes 1..4,194,304, duplicate digest allowed only with equal declared length.
- Across all 256 blocks, declared records remain capped at 2,000,000 by manifest parsing. Selected matching rows retained by this call are capped at 4,096.
- The raw supplied `Originals` slice is capped at 1,024 slots before any result/map/allocation/read; nil and duplicate slots count toward that ceiling, not semantic acceptance. Nil-reader entries are ignored and can leave selected originals missing. Duplicate non-nil streams for the same digest are whole-zero `invalid-shape` even below the ceiling. Selected unique original digests are independently capped at 1,024.
- Retained raw-original bytes are capped at 16,777,216 (16 MiB). Retained metadata entries are capped at 2,100,000. Retained logical payload bytes are capped at 268,435,456 (256 MiB). These deterministic payload bounds are not an exact Go heap/RSS guarantee and introduce no worker-budget authority.
- A metadata entry is charged once for each direct unique digest, catalog unique digest, retained binding, and returned unique original. A binding receives one logical metadata charge, not another charge for its returned representation. Pending, grouping and output representations may coexist temporarily; their allocation overhead belongs to the expressly unqualified heap/RSS measurement, not this logical counter. Logical bytes charge 40 bytes per retained digest/length declaration, the exact query string once, each retained raw original byte once, and every exported retained projection string occurrence. These are deterministic payload bounds, not exact Go heap/RSS claims.
- The actual local-intelligence read budget is exactly 8,589,934,592 bytes (8 GiB), private and fixed. Catalog, selected block, originals, detection bytes, and deliberate rereads share one counter with no phase reset. Declarations are preflight comparisons only and are never charged.
- Each `Read` request is bounded by the smaller of 32 KiB, remaining global bytes, and remaining expected object bytes plus one detection byte. Every returned byte is charged once. EOF-only reads charge zero.
- `(n > 0, io.EOF)` establishes EOF after the returned bytes. Reaching declared length with `err == nil` requires a one-byte detection read. If no budget remains for that read, the object is unavailable; exact length or EOF is not inferred. A positive detection byte is charged and proves length mismatch.
- Original bytes are retained once per unique digest and checked with existing `CheckSnapshotObject`; each is independently limited to 4 MiB. The same bytes feed existing OSV parser/projectors. No row gets its own copied raw/projection graph.
- Each returned unique original owns one `Bindings` list. Every binding preserves `SourceOrdinal` and `AffectedIndex`; it points into that original's one `Affected`/`Identity` projection. Different slots never lend identity, versions, ranges, activity, or uncertainty.
- Structural state and query eligibility are separate. Byte/JSON/projection success does not itself make a binding eligible. Eligibility requires the exact indexed slot to be an existing qualified npm candidate with exact ecosystem/name/hash.
- `EvaluateOSVVersionConditions` is not called. A concrete `SemVer` query is absent; original `Versions`/`Ranges` remain in `OSVAffectedProjection` for a later consumer.
- Block/catalog malformed, reader failure, cancellation, digest/length/count/order/cross-binding failure, or complete declaration overflow returns whole-zero `SnapshotNPMEvidence` plus a fixed `*ParseError`. No underlying error, raw content, name, path, or source locator appears in the error.
- Missing/unreadable/over-budget/hash-bad/length-bad/malformed/projector-bad originals are record-local states. Valid unique original siblings and their bindings survive. A bad original never becomes a negative result.
- Baseline gaps always remain: index completeness, correction, activity, source qualification, registry correspondence, finding authority, global store quota, and preparation byte identity. Empty records are therefore never definitive absence.
- Maximum declared records (2,000,000), actual 8 GiB reads, 32 GiB per-snapshot unique declarations, retained bindings, unique originals, raw bytes, metadata entries, and logical bytes are independent counters; none substitutes for another.
- Inputs/results are owned as documented; caller concurrent mutation is excluded. Output mutation cannot change caller data or a fresh call.
- Standard-library only. No new framework, dependency, global mutable singleton, goroutine, exported/caller-supplied callback, panic, print, logger, filesystem, clock, environment, network, or process operation.

### Frozen public API

These declarations are exact. Implementers may add private helpers only inside `snapshot_npm_stream.go`; they may not rename fields, collapse structural/query state, expose a configurable budget, or add acquisition authority.

```go
// ParseSnapshotManifestV11 is added beside the unchanged 1.0-only entry point.
func ParseSnapshotManifestV11(data []byte) (SnapshotManifest, error)

type SnapshotOriginalStream struct {
    SHA256 [32]byte
    Reader io.Reader
}

type SnapshotNPMStreams struct {
    Block     io.Reader
    Catalog   io.Reader
    Originals []SnapshotOriginalStream
}

type SnapshotStreamState uint8

const (
    SnapshotStreamUnknown SnapshotStreamState = iota
    SnapshotStreamUnavailable
    SnapshotStreamBytesVerified
    SnapshotStreamStructured
)

type SnapshotDeclarationState uint8

const (
    SnapshotDeclarationUnknown SnapshotDeclarationState = iota
    SnapshotDeclarationGap
    SnapshotDeclarationVerified
)

type SnapshotOriginalState uint8

const (
    SnapshotOriginalUnknown SnapshotOriginalState = iota
    SnapshotOriginalUnavailable
    SnapshotOriginalVerified
)

type SnapshotOriginalProblem uint8

const (
    SnapshotOriginalProblemNone SnapshotOriginalProblem = iota
    SnapshotOriginalProblemMissing
    SnapshotOriginalProblemRead
    SnapshotOriginalProblemResource
    SnapshotOriginalProblemLength
    SnapshotOriginalProblemDigest
    SnapshotOriginalProblemParse
    SnapshotOriginalProblemProjection
)

type SnapshotBindingState uint8

const (
    SnapshotBindingUnknown SnapshotBindingState = iota
    SnapshotBindingGap
    SnapshotBindingEligible
)

type SnapshotBindingProblem uint8

const (
    SnapshotBindingProblemNone SnapshotBindingProblem = iota
    SnapshotBindingProblemOriginal
    SnapshotBindingProblemAffectedIndex
    SnapshotBindingProblemIdentity
)

type SnapshotGapKind uint8

const (
    SnapshotGapIndexCompleteness SnapshotGapKind = iota + 1
    SnapshotGapCorrection
    SnapshotGapActivity
    SnapshotGapSourceQualification
    SnapshotGapRegistryCorrespondence
    SnapshotGapFindingAuthority
    SnapshotGapGlobalStoreQuota
    SnapshotGapPreparationByteIdentity
    SnapshotGapResource
)

type SnapshotAffectedBinding struct {
    SourceOrdinal uint64
    AffectedIndex uint64
    State         SnapshotBindingState
    Problem       SnapshotBindingProblem
}

type SnapshotOriginalEvidence struct {
    SHA256  [32]byte
    Bytes   uint64
    State   SnapshotOriginalState
    Problem SnapshotOriginalProblem
    Raw     []byte
    Header  OSVHeader
    Affected OSVAffectedProjection
    Identity OSVNPMIdentityProjection
    Times    OSVTimes
    Bindings []SnapshotAffectedBinding
}

type SnapshotNPMEvidence struct {
    ManifestSHA256 [32]byte
    IdentityHash   [32]byte
    Ecosystem      string
    Name           string
    BlockIndex     uint8
    BytesRead      uint64
    BlockState     SnapshotStreamState
    CatalogState   SnapshotStreamState
    Declaration    SnapshotDeclarationState
    Records         []SnapshotOriginalEvidence
    Gaps            []SnapshotGapKind
}

func ReadSnapshotNPMIdentity(
    ctx context.Context,
    manifest SnapshotManifest,
    name string,
    streams SnapshotNPMStreams,
) (SnapshotNPMEvidence, error)
```

### Review Focus

1. **EOF/read-budget ambiguity** — `TestSnapshotReadBudgetAndEOF`: declared bytes are not charged, every returned/detection/reread byte is charged once, `(n, EOF)` works, and exact-length-without-EOF at 8 GiB exhaustion is a resource gap.
2. **JSONL framing and strict rows** — `TestReadSnapshotNPMIdentityJSONLFailures`: BOM/CRLF/blank/missing LF/duplicate key/unknown field/noncanonical number/order/count/hash corruption are fatal whole-zero; an over-profile line is a verified-object resource gap.
3. **Routing and five-way cross-binding** — `TestReadSnapshotNPMIdentityBindingFailures`: manifest→block, block→row, row→catalog, catalog→object, and object→projection/slot mismatches fail closed at the assigned boundary without collision conflation or cross-slot support.
4. **Record-local failure with siblings** — `TestReadSnapshotNPMIdentityOriginalSiblingRetention`: missing/read-bad/length-bad/digest-bad/malformed/unsupported sibling records stay unavailable while usable siblings, raw evidence, versions/ranges, withdrawal state, and occurrence bindings survive.
5. **Authority/privacy/ownership** — `TestReadSnapshotNPMIdentityGapsPrivacyOwnership`: all eight baseline gaps remain, empty results are not definitive absence, no version/finding/activity claim appears, errors contain no marker/path/raw reader text, and mutations do not alias inputs/fresh outputs.

---

### Task 1: Explicit manifest 1.1 path without changing 1.0

**Files:**
- Modify `internal/intel/snapshot_manifest.go`.
- Modify `internal/intel/snapshot_manifest_test.go`.

**Consumes:** Existing `SnapshotManifest`, `SnapshotObjectReference`, `SnapshotBlockReference`, `SnapshotSource`, `snapshotManifestObject`, `snapshotManifestUint`, and `snapshotManifestReference` unchanged.

**Produces:** `ParseSnapshotManifestV11([]byte) (SnapshotManifest, error)`. `ParseSnapshotManifest` remains source-compatible and behavior-compatible for every existing test.

- [ ] **Step 1: Write the missing-API and compatibility tests.** Add this exact test; do not modify existing 1.0 expectations.

```go
func TestParseSnapshotManifestExplicitV11(t *testing.T) {
    oneOne := snapshotTestBase()
    oneOne["schemaVersion"] = "1.1"
    data := snapshotTestBytes(t, oneOne)

    got10, err10 := ParseSnapshotManifest(data)
    pe10, ok10 := err10.(*ParseError)
    if !ok10 || pe10.Code != "unsupported-version" ||
        !reflect.DeepEqual(got10, SnapshotManifest{}) {
        t.Fatal("1.0 entry point silently accepted 1.1")
    }

    got11, err11 := ParseSnapshotManifestV11(data)
    if err11 != nil || got11.SchemaVersion != "1.1" ||
        got11.Source.ID != "packtrace-synthetic-i21" || len(got11.Blocks) != 256 {
        t.Fatal("explicit 1.1 manifest result missing")
    }

    oneZero := snapshotTestBase()
    gotWrong, errWrong := ParseSnapshotManifestV11(snapshotTestBytes(t, oneZero))
    peWrong, okWrong := errWrong.(*ParseError)
    if !okWrong || peWrong.Code != "unsupported-version" ||
        !reflect.DeepEqual(gotWrong, SnapshotManifest{}) {
        t.Fatal("1.1 entry point silently accepted 1.0")
    }

    oneOne["unknown"] = json.RawMessage(`{"dup":0,"\u0064up":1}`)
    gotBad, errBad := ParseSnapshotManifestV11(snapshotTestBytes(t, oneOne))
    peBad, okBad := errBad.(*ParseError)
    if !okBad || peBad.Code != "duplicate-key" ||
        !reflect.DeepEqual(gotBad, SnapshotManifest{}) {
        t.Fatal("1.1 bypassed the shared envelope validator")
    }
}
```

- [ ] **Step 2: Run the focused missing-API RED after separate execution approval.**

```nu
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go test -count=1 -run '^TestParseSnapshotManifestExplicitV11$' ./internal/intel
}
```

Expected: compilation fails only because `ParseSnapshotManifestV11` is undefined. Record this separately from behavioral RED.

- [ ] **Step 3: Add a compiling behavioral stub.** Add only the exact declaration below, rerun, and require the test to compile and fail because valid 1.1 returns whole-zero nil error.

```go
func ParseSnapshotManifestV11(data []byte) (SnapshotManifest, error) {
    return SnapshotManifest{}, nil
}
```

- [ ] **Step 4: Replace the stub by extracting one shared private core.** The existing body moves byte-for-byte except for its version comparison. No other validation/order/constant/type changes are allowed.

```go
func ParseSnapshotManifest(data []byte) (SnapshotManifest, error) {
    return parseSnapshotManifestVersion(data, "1.0")
}

func ParseSnapshotManifestV11(data []byte) (SnapshotManifest, error) {
    return parseSnapshotManifestVersion(data, "1.1")
}

func parseSnapshotManifestVersion(data []byte, requiredVersion string) (SnapshotManifest, error) {
    fields, code := jsoninput.Object(data, maxSnapshotManifestBytes)
    if code != "" {
        return SnapshotManifest{}, &ParseError{Code: code}
    }
    version := projectOSVString(fields, "schemaVersion")
    if version.State != OSVFieldValue || version.Value == "" {
        return SnapshotManifest{}, &ParseError{Code: "invalid-shape"}
    }
    if version.Value != requiredVersion {
        return SnapshotManifest{}, &ParseError{Code: "unsupported-version"}
    }
    sourceFields, code := snapshotManifestObject(fields["source"])
    if code != "" {
        return SnapshotManifest{}, &ParseError{Code: code}
    }
    id := projectOSVString(sourceFields, "id")
    if id.State != OSVFieldValue || id.Value == "" || strings.ContainsRune(id.Value, 0) {
        return SnapshotManifest{}, &ParseError{Code: "invalid-shape"}
    }
    if len(id.Value) > 256 {
        return SnapshotManifest{}, &ParseError{Code: "limit-exceeded"}
    }
    originals, code := snapshotManifestReference(fields["originals"], -1)
    if code != "" {
        return SnapshotManifest{}, &ParseError{Code: code}
    }
    var blocks []json.RawMessage
    if json.Unmarshal(fields["blocks"], &blocks) != nil || blocks == nil || len(blocks) < maxSnapshotManifestBlocks {
        return SnapshotManifest{}, &ParseError{Code: "invalid-shape"}
    }
    if len(blocks) > maxSnapshotManifestBlocks {
        return SnapshotManifest{}, &ParseError{Code: "limit-exceeded"}
    }
    result := SnapshotManifest{
        SHA256: sha256.Sum256(data), Fields: fields, SchemaVersion: version.Value,
        Source: SnapshotSource{Fields: sourceFields, ID: id.Value}, Originals: originals,
        Blocks: make([]SnapshotBlockReference, maxSnapshotManifestBlocks),
    }
    lengths := map[[32]byte]uint64{originals.SHA256: originals.Bytes}
    blockCounts := make(map[[32]byte]uint64)
    remainingBytes := maxSnapshotManifestObjectBytes - originals.Bytes
    remainingRecords := maxSnapshotManifestRecords
    for index, raw := range blocks {
        ref, code := snapshotManifestReference(raw, index)
        if code != "" {
            return SnapshotManifest{}, &ParseError{Code: code}
        }
        length, shared := lengths[ref.SHA256]
        if shared && length != ref.Bytes {
            return SnapshotManifest{}, &ParseError{Code: "invalid-shape"}
        }
        if count, exists := blockCounts[ref.SHA256]; exists && count != ref.Records {
            return SnapshotManifest{}, &ParseError{Code: "invalid-shape"}
        }
        if !shared {
            if ref.Bytes > remainingBytes {
                return SnapshotManifest{}, &ParseError{Code: "limit-exceeded"}
            }
            remainingBytes -= ref.Bytes
            lengths[ref.SHA256] = ref.Bytes
        }
        if ref.Records > remainingRecords {
            return SnapshotManifest{}, &ParseError{Code: "limit-exceeded"}
        }
        remainingRecords -= ref.Records
        blockCounts[ref.SHA256] = ref.Records
        result.Blocks[index] = SnapshotBlockReference{Index: index, Reference: ref}
    }
    result.Source.Locator = projectOSVString(sourceFields, "locator")
    result.Source.AcquisitionMethod = projectOSVString(sourceFields, "acquisitionMethod")
    result.Source.Attribution = projectOSVString(sourceFields, "attribution")
    result.Source.AcquiredAt = projectOSVTimestamp(sourceFields, "acquiredAt")
    result.Source.ExportedAt = projectOSVTimestamp(sourceFields, "exportedAt")
    result.Source.LastSuccessfulCheck = projectOSVTimestamp(sourceFields, "lastSuccessfulCheck")
    result.Source.LastFullReconciliation = projectOSVTimestamp(sourceFields, "lastFullReconciliation")
    return result, nil
}
```

- [ ] **Step 5: Run focused GREEN and unchanged 1.0 regression.**

```nu
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go test -count=1 -run '^TestParseSnapshotManifest' ./internal/intel
}
```

Expected: all existing `TestParseSnapshotManifest*` tests and the new explicit-1.1 test pass. Any changed existing case/error/result is a failure; do not update the old expectation.

- [ ] **Step 6: Make the first file-scoped checkpoint only after GREEN.**

```nu
gofmt -w internal/intel/snapshot_manifest.go internal/intel/snapshot_manifest_test.go
jj diff --name-only
jj commit internal/intel/snapshot_manifest.go internal/intel/snapshot_manifest_test.go -m "feat: parse snapshot manifest 1.1 explicitly"
```

Expected `jj diff --name-only` before the commit: exactly the two task-1 files plus any separately acknowledged pre-existing unrelated paths, which remain excluded from the path-scoped commit. `jj 0.46` syntax is used; no `--allow-new`.

- [ ] **Step 7: Fresh task-1 review gate.** Under the approved subagent-driven method, a fresh reviewer checks the exact task-1 commit against the unchanged 1.0 contract and explicit 1.1 tests. Resolve findings and rerun task-1 focused checks before task 2 starts. Author self-review is not this gate.

### Task 2: Complete supplied-stream npm consumer

**Files:**
- Create `internal/intel/snapshot_npm_stream.go`.
- Create `internal/intel/snapshot_npm_stream_test.go`.

**Consumes exactly:**

```go
jsoninput.Object(data []byte, byteLimit int) (map[string]json.RawMessage, string)
CheckSnapshotObject(ref SnapshotObjectReference, data []byte) (SnapshotObjectCheck, error)
ParseOSVRecord(data []byte) (OSVDocument, error)
ProjectOSVHeader(doc OSVDocument) (OSVHeader, error)
ProjectOSVAffected(doc OSVDocument) (OSVAffectedProjection, error)
QualifyOSVNPMIdentities(header OSVHeader, affected OSVAffectedProjection) (OSVNPMIdentityProjection, error)
ProjectOSVTimes(doc OSVDocument) (OSVTimes, error)
```

It also reuses package-private `validOSVNPMName`, `snapshotManifestUint`, existing `maxAffectedEntries`, and existing manifest constants. It does not call `EvaluateOSVVersionConditions`.

**Produces exactly:** the frozen public API above. No loader, exported/caller-supplied callback, iterator, source registry, store interface, CLI, finding type, or configurable limits.

#### Task 2A — TDD fixtures, missing API RED, compiling behavioral RED

- [ ] **Step 1: Add complete synthetic fixture helpers.** The fixture builds supplied bytes only; it never opens a path or uses a real project.

```go
package intel

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "go/ast"
    "go/parser"
    "go/token"
    "io"
    "reflect"
    "strconv"
    "strings"
    "testing"
)

const streamTestOriginal = `{"id":"OSV-SYNTHETIC-1","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["1.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`

func streamTestDigest(data []byte) string {
    sum := sha256.Sum256(data)
    return hex.EncodeToString(sum[:])
}

func streamTestRows(lines ...string) []byte {
    if len(lines) == 0 {
        return nil
    }
    return []byte(strings.Join(lines, "\n") + "\n")
}

func streamTestCatalogLine(ordinal uint64, original []byte) string {
    return fmt.Sprintf(`{"v":1,"sourceOrdinal":%d,"sha256":"%s","bytes":%d}`,
        ordinal, streamTestDigest(original), len(original))
}

func streamTestBlockLine(name string, ordinal uint64, original []byte, affected uint64) string {
    hash := sha256.Sum256(append([]byte("npm\x00"), []byte(name)...))
    return fmt.Sprintf(`{"v":1,"identityHash":"%s","ecosystem":"npm","name":%q,"sourceOrdinal":%d,"originalSHA256":"%s","originalBytes":%d,"affectedIndex":%d}`,
        hex.EncodeToString(hash[:]), name, ordinal, streamTestDigest(original), len(original), affected)
}

func streamTestManifest(t *testing.T, catalog []byte, blockIndex byte, block []byte) SnapshotManifest {
    t.Helper()
    empty := sha256.Sum256(nil)
    refs := make([]any, 256)
    for i := range refs {
        refs[i] = map[string]any{"index": i, "sha256": hex.EncodeToString(empty[:]), "bytes": 0, "records": 0}
    }
    blockSum := sha256.Sum256(block)
    refs[int(blockIndex)] = map[string]any{"index": int(blockIndex), "sha256": hex.EncodeToString(blockSum[:]), "bytes": len(block), "records": bytes.Count(block, []byte{'\n'})}
    catalogSum := sha256.Sum256(catalog)
    raw, err := json.Marshal(map[string]any{
        "schemaVersion": "1.1",
        "source": map[string]any{"id": "packtrace-synthetic-stream"},
        "originals": map[string]any{"sha256": hex.EncodeToString(catalogSum[:]), "bytes": len(catalog), "records": bytes.Count(catalog, []byte{'\n'})},
        "blocks": refs,
    })
    if err != nil {
        t.Fatal("fixture marshal failed")
    }
    manifest, err := ParseSnapshotManifestV11(raw)
    if err != nil {
        t.Fatal("fixture manifest failed", err)
    }
    return manifest
}

func streamTestCall(t *testing.T, original []byte) SnapshotNPMEvidence {
    t.Helper()
    catalog := streamTestRows(streamTestCatalogLine(0, original))
    block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
    manifest := streamTestManifest(t, catalog, 0x2a, block)
    digest := sha256.Sum256(original)
    got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{
        Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog),
        Originals: []SnapshotOriginalStream{{SHA256: digest, Reader: bytes.NewReader(original)}},
    })
    if err != nil {
        t.Fatal("unexpected stream failure", err)
    }
    return got
}
```

- [ ] **Step 2: Add the exact positive contract test.** It is a literal expected result, not a production-derived eligibility oracle.

```go
func TestReadSnapshotNPMIdentityExactEvidence(t *testing.T) {
    original := []byte(streamTestOriginal)
    got := streamTestCall(t, original)
    digest := sha256.Sum256(original)
    expectedGaps := []SnapshotGapKind{
        SnapshotGapIndexCompleteness, SnapshotGapCorrection, SnapshotGapActivity,
        SnapshotGapSourceQualification, SnapshotGapRegistryCorrespondence,
        SnapshotGapFindingAuthority, SnapshotGapGlobalStoreQuota,
        SnapshotGapPreparationByteIdentity,
    }
    expectedManifest := streamTestManifest(t,
        streamTestRows(streamTestCatalogLine(0, original)), 0x2a,
        streamTestRows(streamTestBlockLine("left-pad", 0, original, 0)))
    if got.ManifestSHA256 != expectedManifest.SHA256 ||
        got.IdentityHash != ([32]byte{0x2a, 0x7a, 0xb3, 0xd5, 0x63, 0x56, 0x2f, 0x66, 0x6c, 0xa1, 0xb4, 0xd2, 0x49, 0x4f, 0xf2, 0x0b, 0xc1, 0x14, 0xb8, 0xfc, 0xd8, 0x1d, 0x9d, 0xc1, 0xe4, 0xcb, 0x22, 0x1d, 0x5c, 0x47, 0xc1, 0xbc}) ||
        got.Ecosystem != "npm" || got.Name != "left-pad" || got.BlockIndex != 42 ||
        got.BlockState != SnapshotStreamStructured || got.CatalogState != SnapshotStreamStructured ||
        got.Declaration != SnapshotDeclarationVerified || !reflect.DeepEqual(got.Gaps, expectedGaps) ||
        len(got.Records) != 1 {
        t.Fatal("literal query/object state changed")
    }
    record := got.Records[0]
    if record.SHA256 != digest || record.Header.SourceSHA256 != digest ||
        record.Affected.SourceSHA256 != digest || record.Identity.SourceSHA256 != digest ||
        record.Times.SourceSHA256 != digest || record.Bytes != uint64(len(original)) ||
        record.State != SnapshotOriginalVerified || record.Problem != SnapshotOriginalProblemNone ||
        !bytes.Equal(record.Raw, original) || record.Header.ID.Value != "OSV-SYNTHETIC-1" ||
        record.Affected.State != OSVFieldValue || len(record.Affected.Entries) != 1 ||
        record.Affected.Entries[0].Versions.Entries[0].Value != "1.0.0" ||
        record.Affected.Entries[0].Ranges.Entries[0].Type.Value != "SEMVER" ||
        record.Identity.Entries[0].Qualification != OSVNPMIdentityCandidate ||
        record.Times.Withdrawal != WithdrawalNotDeclared ||
        !reflect.DeepEqual(record.Bindings, []SnapshotAffectedBinding{{
            SourceOrdinal: 0, AffectedIndex: 0,
            State: SnapshotBindingEligible, Problem: SnapshotBindingProblemNone,
        }}) {
        t.Fatal("owned original/projection/binding evidence changed")
    }
    if got.BytesRead != uint64(len(streamTestRows(streamTestBlockLine("left-pad", 0, original, 0)))+
        len(streamTestRows(streamTestCatalogLine(0, original)))+len(original)) {
        t.Fatal("actual read accounting charged declarations or missed bytes")
    }
}
```

- [ ] **Step 3: Add table-driven fatal JSONL/profile tests with exact outcomes.** Each case starts from the positive fixture and changes only the named bytes/reference. Expected fatal rows return `SnapshotNPMEvidence{}` and exact `intel: <code>`; `line-profile` returns nil error, no records, `SnapshotGapResource`, and `SnapshotStreamBytesVerified` for the affected object.

```go
func streamTestFatal(t *testing.T, manifest SnapshotManifest, streams SnapshotNPMStreams, code string) {
    t.Helper()
    got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", streams)
    var pe *ParseError
    if !errors.As(err, &pe) || pe.Code != code || err.Error() != "intel: "+code ||
        !reflect.DeepEqual(got, SnapshotNPMEvidence{}) {
        t.Fatal("missing private whole-zero failure")
    }
}

func TestReadSnapshotNPMIdentityJSONLFailures(t *testing.T) {
    original := []byte(streamTestOriginal)
    validCatalog := streamTestRows(streamTestCatalogLine(0, original))
    validBlock := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
    cases := []struct{name, code string; data []byte}{
        {"bom", "invalid-shape", append([]byte{0xef, 0xbb, 0xbf}, validBlock...)},
        {"bom-over-profile", "invalid-shape", append(append([]byte{0xef, 0xbb, 0xbf}, bytes.Repeat([]byte{' '}, (1<<20)+1)...), '\n') },
        {"crlf", "invalid-shape", bytes.ReplaceAll(validBlock, []byte("\n"), []byte("\r\n"))},
        {"blank", "invalid-shape", append(validBlock, '\n')},
        {"missing-final-lf", "invalid-shape", validBlock[:len(validBlock)-1]},
        // jsoninput.Object checks utf8.Valid before decoding and returns invalid-json.
        {"invalid-utf8", "invalid-json", append([]byte{0xff}, '\n')},
        {"surrogate", "invalid-json", streamTestRows(`{"v":1,"identityHash":"\ud800"}`)},
        {"duplicate-key", "duplicate-key", streamTestRows(strings.Replace(streamTestBlockLine("left-pad", 0, original, 0), `"v":1`, `"v":1,"\u0076":1`, 1))},
        {"unknown-field", "invalid-shape", streamTestRows(strings.Replace(streamTestBlockLine("left-pad", 0, original, 0), `"v":1`, `"v":1,"extra":0`, 1))},
        {"noncanonical-integer", "invalid-json", bytes.Replace(validBlock, []byte(`"sourceOrdinal":0`), []byte(`"sourceOrdinal":01`), 1)},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            manifest := streamTestManifest(t, validCatalog, 0x2a, tc.data)
            digest := sha256.Sum256(original)
            streamTestFatal(t, manifest, SnapshotNPMStreams{
                Block: bytes.NewReader(tc.data), Catalog: bytes.NewReader(validCatalog),
                Originals: []SnapshotOriginalStream{{SHA256: digest, Reader: bytes.NewReader(original)}},
            }, tc.code)
        })
    }
}
```

Additional named subtests in this same function must use literal expected codes:

| Subtest | Input | Expected |
|---|---|---|
| `catalog-zero-byte` | empty catalog, empty selected block, no originals | structured catalog/block, declaration verified, zero records, baseline gaps |
| `catalog-skipped-ordinal` | first catalog row ordinal 1 | whole-zero `invalid-shape` |
| `catalog-repeated-ordinal` | rows 0,0 | whole-zero `invalid-shape` |
| `catalog-conflicting-length` | repeated digest with lengths 1 and 2 | whole-zero `invalid-shape` |
| `block-sort` | two valid rows in descending tuple order | whole-zero `invalid-shape` |
| `block-duplicate-tuple` | same tuple twice | whole-zero `invalid-shape` |
| `block-wrong-slot` | valid row whose digest byte zero differs from selected block | whole-zero `invalid-shape` |
| `block-forged-hash` | replace one hash nibble | whole-zero `invalid-shape` |
| `block-record-count` | manifest records differs from physical LF rows | whole-zero `invalid-shape` |
| `block-digest` | mutate one whitespace byte without changing reference | whole-zero `digest-mismatch` |
| `catalog-digest` | mutate one whitespace byte without changing reference | whole-zero `digest-mismatch` |
| `line-profile` | one valid row padded to 1,048,577 content bytes with reference recomputed | nil error, bytes-verified state, resource gap, no declaration verdict/no records |

- [ ] **Step 4: Add binding, sibling, and authority tests.** These exact semantic cases are required; test helpers may only construct bytes/readers.

```go
func TestReadSnapshotNPMIdentityDistinctSameBlockPrefix(t *testing.T) {
    // These are real distinct hashes sharing byte zero 0x26, not a fabricated full collision.
    one := []byte(`{"id":"ONE","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"pkg-3"}}]}`)
    two := []byte(`{"id":"TWO","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"pkg-6"}}]}`)
    catalog := streamTestRows(streamTestCatalogLine(0, one), streamTestCatalogLine(1, two))
    block := streamTestRows(
        streamTestBlockLine("pkg-6", 1, two, 0),
        streamTestBlockLine("pkg-3", 0, one, 0),
    )
    // Sort by the literal full hashes: pkg-6 265115... precedes pkg-3 267b1f....
    manifest := streamTestManifest(t, catalog, 0x26, block)
    oneDigest, twoDigest := sha256.Sum256(one), sha256.Sum256(two)
    got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "pkg-3", SnapshotNPMStreams{
        Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog),
        Originals: []SnapshotOriginalStream{
            {SHA256: oneDigest, Reader: bytes.NewReader(one)},
            {SHA256: twoDigest, Reader: bytes.NewReader(two)},
        },
    })
    if err != nil || len(got.Records) != 1 || got.Records[0].Header.ID.Value != "ONE" ||
        got.Records[0].Bindings[0].State != SnapshotBindingEligible {
        t.Fatal("same-prefix identity was combined or discarded")
    }
}

func TestReadSnapshotNPMIdentityDuplicateOccurrenceSingleOriginal(t *testing.T) {
    original := []byte(streamTestOriginal)
    catalog := streamTestRows(streamTestCatalogLine(0, original), streamTestCatalogLine(1, original))
    block := streamTestRows(
        streamTestBlockLine("left-pad", 0, original, 0),
        streamTestBlockLine("left-pad", 1, original, 0),
    )
    manifest := streamTestManifest(t, catalog, 0x2a, block)
    digest := sha256.Sum256(original)
    got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{
        Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog),
        Originals: []SnapshotOriginalStream{{SHA256: digest, Reader: bytes.NewReader(original)}},
    })
    want := []SnapshotAffectedBinding{
        {SourceOrdinal: 0, AffectedIndex: 0, State: SnapshotBindingEligible},
        {SourceOrdinal: 1, AffectedIndex: 0, State: SnapshotBindingEligible},
    }
    if err != nil || len(got.Records) != 1 || !reflect.DeepEqual(got.Records[0].Bindings, want) {
        t.Fatal("duplicate occurrence duplicated raw/projections or lost bindings")
    }
}
```

`TestReadSnapshotNPMIdentityBindingFailures` must pin these literal outcomes:

| Subtest | Expected |
|---|---|
| manifest schema/index changed, source ID emptied/source fields nil, direct ref over 32 GiB/2M, unique direct-byte or block-record sum overflow, same-digest length conflict, or repeated-block count conflict | whole-zero `invalid-shape` before any stream read; no raw manifest reparse or detection claim for arbitrary nonempty source-ID/raw-field mutation |
| block row `originalSHA256` or `originalBytes` differs from selected catalog occurrence | whole-zero `invalid-shape` |
| selected ordinal absent from catalog | whole-zero `invalid-shape` |
| affected index outside projected slice | record verified, binding `SnapshotBindingGap/SnapshotBindingProblemAffectedIndex` |
| indexed slot ecosystem/name differs | record verified, binding `SnapshotBindingGap/SnapshotBindingProblemIdentity` |
| another slot matches but indexed slot differs | same identity gap; no cross-slot support |
| PURL conflicts with exact package name | same identity gap |
| all projections source hashes equal exact original digest | binding may become eligible |

`TestReadSnapshotNPMIdentityOriginalSiblingRetention` must use at least two distinct selected originals and pin each bad case independently:

| Bad original case | Bad record | Good sibling |
|---|---|---|
| stream omitted | unavailable/missing; binding original gap | verified/eligible retained |
| reader returns private error text | unavailable/read; no text in result/error | verified/eligible retained |
| short or extra byte | unavailable/length | verified/eligible retained |
| same declared length, wrong digest | unavailable/digest | verified/eligible retained |
| malformed OSV JSON | unavailable/parse | verified/eligible retained |
| valid OSV exceeding projector structural limits | unavailable/projection | verified/eligible retained |
| aggregate retained raw/logical limit reached | unavailable/resource + global resource gap | earlier verified sibling retained |

Use withdrawn/no-withdrawal/malformed-withdrawal originals to expect respectively `WithdrawalReported`, `WithdrawalNotDeclared`, and `WithdrawalUnknown`. Include unsupported version/range content and assert it remains in `Affected`; never expect `OSVVersionOutcome` or call the evaluator.

- [ ] **Step 5: Add private-counter boundary tests without allocating or reading 8 GiB.** The test modifies only the unexported counter in package `intel`; no public limit/configuration is added.

```go
func TestSnapshotReadBudgetAndEOF(t *testing.T) {
    t.Run("counter-math", func(t *testing.T) {
        b := snapshotReadBudget{used: maxSnapshotReadBytes - 1}
        if b.remaining() != 1 || !b.canStart(1) || b.canStart(2) {
            t.Fatal("8 GiB preflight arithmetic changed")
        }
        if !b.charge(1) || b.used != maxSnapshotReadBytes || b.charge(1) {
            t.Fatal("actual-byte counter overflow/double-charge guard changed")
        }
    })
    t.Run("same-read-eof", func(t *testing.T) {
        b := snapshotReadBudget{}
        data, resource, code := readSnapshotOriginalBytes(context.Background(),
            &eofWithDataReader{data: []byte("abc")}, 3, &b)
        if code != "" || resource || string(data) != "abc" || b.used != 3 {
            t.Fatal("(n, EOF) did not establish exact end byte")
        }
    })
    t.Run("detection-byte", func(t *testing.T) {
        b := snapshotReadBudget{}
        _, resource, code := readSnapshotOriginalBytes(context.Background(),
            bytes.NewReader([]byte("abcd")), 3, &b)
        if code != "length-mismatch" || resource || b.used != 4 {
            t.Fatal("positive detection byte was not charged")
        }
    })
    t.Run("no-budget-for-eof", func(t *testing.T) {
        b := snapshotReadBudget{used: maxSnapshotReadBytes - 3}
        _, resource, code := readSnapshotOriginalBytes(context.Background(),
            &exactWithoutEOFReader{data: []byte("abc")}, 3, &b)
        if code != "" || !resource || b.used != maxSnapshotReadBytes {
            t.Fatal("EOF was inferred after budget exhaustion")
        }
    })
    t.Run("reread-counts", func(t *testing.T) {
        b := snapshotReadBudget{}
        for range 2 {
            data, resource, code := readSnapshotOriginalBytes(context.Background(), bytes.NewReader([]byte("abc")), 3, &b)
            if code != "" || resource || string(data) != "abc" { t.Fatal("small reread failed") }
        }
        if b.used != 6 { t.Fatal("reread was not charged") }
    })
}

type eofWithDataReader struct{ data []byte; done bool }
func (r *eofWithDataReader) Read(p []byte) (int, error) {
    if r.done { return 0, io.EOF }
    r.done = true
    return copy(p, r.data), io.EOF
}

type exactWithoutEOFReader struct{ data []byte; done bool }
func (r *exactWithoutEOFReader) Read(p []byte) (int, error) {
    if !r.done { r.done = true; return copy(p, r.data), nil }
    return 0, nil
}
```

Add the exact reader-error, cancellation and production row-counter tests below. Cancellation after `Read` takes precedence over returned malformed/extra bytes and reader errors, after valid returned bytes have been charged. These tests do not block a goroutine or claim context interrupts `Read`.

```go
type snapshotTestErrorReader struct{}
func (snapshotTestErrorReader) Read([]byte) (int, error) {
    return 0, errors.New("private-path:/secret/raw-marker")
}

func TestReadSnapshotNPMIdentityStreamReadErrors(t *testing.T) {
    original := []byte(streamTestOriginal)
    catalog := streamTestRows(streamTestCatalogLine(0, original))
    block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
    manifest := streamTestManifest(t, catalog, 0x2a, block)
    for _, which := range []string{"block-read-error", "catalog-read-error"} {
        t.Run(which, func(t *testing.T) {
            streams := SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog)}
            if which == "block-read-error" { streams.Block = snapshotTestErrorReader{} }
            if which == "catalog-read-error" { streams.Catalog = snapshotTestErrorReader{} }
            streamTestFatal(t, manifest, streams, "read-failed")
        })
    }
}

type snapshotTestCancelReader struct {
    cancel context.CancelFunc
    data []byte
    calls int
}
func (r *snapshotTestCancelReader) Read(p []byte) (int, error) {
    r.calls++
    n := copy(p, r.data)
    r.cancel()
    return n, io.EOF
}

func TestReadSnapshotNPMIdentityCancellationBoundary(t *testing.T) {
    original := []byte(streamTestOriginal)
    catalog := streamTestRows(streamTestCatalogLine(0, original))
    block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
    manifest := streamTestManifest(t, catalog, 0x2a, block)
    for _, tc := range []struct { name string; data []byte; before bool }{
        {"before-read", block, true},
        {"after-valid-read", block, false},
        {"cancel-plus-malformed", []byte("{broken\n"), false},
        {"cancel-plus-extra-byte", append(append([]byte(nil), block...), 'x'), false},
    } {
        t.Run(tc.name, func(t *testing.T) {
            ctx, cancel := context.WithCancel(context.Background())
            defer cancel()
            reader := &snapshotTestCancelReader{cancel: cancel, data: tc.data}
            if tc.before { cancel() }
            got, err := ReadSnapshotNPMIdentity(ctx, manifest, "left-pad", SnapshotNPMStreams{
                Block: reader, Catalog: bytes.NewReader(catalog),
            })
            var pe *ParseError
            wantCalls := 1
            if tc.before { wantCalls = 0 }
            if !errors.As(err, &pe) || pe.Code != "canceled" || err.Error() != "intel: canceled" ||
                !reflect.DeepEqual(got, SnapshotNPMEvidence{}) || reader.calls != wantCalls {
                t.Fatal("cancellation precedence or zero-result boundary changed")
            }
        })
    }
}

func TestSnapshotReadBudgetCancellationCharge(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    reader := &snapshotTestCancelReader{cancel: cancel, data: []byte("x")}
    budget := snapshotReadBudget{used: 3}
    called := false
    _, observed, resource, code := readSnapshotStream(ctx, reader, 0, &budget,
        func([]byte) string { called = true; return "invalid-shape" })
    if code != "canceled" || resource || observed != 1 || budget.used != 4 || called || reader.calls != 1 {
        t.Fatal("returned byte charging or cancellation-before-sink changed")
    }
}

func TestSnapshotReadBudgetPhysicalRows(t *testing.T) {
    rows := uint64(maxSnapshotManifestRecords - 1)
    if code := snapshotPhysicalRowNext(&rows); code != "" || rows != maxSnapshotManifestRecords {
        t.Fatal("last permitted physical row rejected")
    }
    if code := snapshotPhysicalRowNext(&rows); code != "limit-exceeded" || rows != maxSnapshotManifestRecords {
        t.Fatal("production physical-row ceiling changed")
    }
}

func TestReadSnapshotNPMIdentityNilStreams(t *testing.T) {
    original := []byte(streamTestOriginal)
    catalog := streamTestRows(streamTestCatalogLine(0, original))
    block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
    manifest := streamTestManifest(t, catalog, 0x2a, block)
    digest := sha256.Sum256(original)
    for _, usable := range []bool{false, true} {
        originals := []SnapshotOriginalStream{{SHA256: digest}, {SHA256: digest}}
        if usable { originals[1].Reader = bytes.NewReader(original) }
        got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{
            Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog), Originals: originals,
        })
        if err != nil || len(got.Records) != 1 { t.Fatal("nil slots became fatal or discarded the occurrence") }
        record := got.Records[0]
        if usable {
            if record.State != SnapshotOriginalVerified || record.Bindings[0].State != SnapshotBindingEligible {
                t.Fatal("nil followed by usable same-digest stream was not retained")
            }
        } else if record.State != SnapshotOriginalUnavailable || record.Problem != SnapshotOriginalProblemMissing ||
            record.Bindings[0].State != SnapshotBindingGap {
            t.Fatal("nil streams became usable or absent evidence")
        }
    }
}

func TestReadSnapshotNPMIdentitySuppliedDuplicates(t *testing.T) {
    original := []byte(streamTestOriginal)
    catalog := streamTestRows(streamTestCatalogLine(0, original))
    block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
    manifest := streamTestManifest(t, catalog, 0x2a, block)
    digest := sha256.Sum256(original)
    streamTestFatal(t, manifest, SnapshotNPMStreams{
        Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog),
        Originals: []SnapshotOriginalStream{
            {SHA256: digest, Reader: bytes.NewReader(original)},
            {SHA256: digest, Reader: bytes.NewReader(original)},
        },
    }, "invalid-shape")
}
```

- [ ] **Step 6: Observe missing-API RED.** Run only after separate execution approval.

```nu
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go test -count=1 -run '^(TestReadSnapshotNPMIdentity|TestSnapshotReadBudget)' ./internal/intel
}
```

Expected: compilation failure naming the frozen stream types/function/private budget helpers. Record compiler RED separately.

- [ ] **Step 7: Add the frozen public declarations and compiling stubs.** Copy the public API exactly. Add the private declarations below only so every test compiles; rerun and require behavioral failures, not a compiler failure.

```go
const maxSnapshotReadBytes uint64 = 8 << 30

type snapshotReadBudget struct{ used uint64 }
func (b *snapshotReadBudget) remaining() uint64 { return maxSnapshotReadBytes - b.used }
func (b *snapshotReadBudget) canStart(n uint64) bool { return n <= b.remaining() }
func (b *snapshotReadBudget) charge(n uint64) bool {
    if n > b.remaining() { return false }
    b.used += n
    return true
}

func snapshotPhysicalRowNext(*uint64) string { return "" }

type snapshotChunkSink func([]byte) string
func readSnapshotStream(context.Context, io.Reader, uint64, *snapshotReadBudget, snapshotChunkSink) ([32]byte, uint64, bool, string) {
    return [32]byte{}, 0, false, ""
}

func readSnapshotOriginalBytes(context.Context, io.Reader, uint64, *snapshotReadBudget) ([]byte, bool, string) {
    return nil, false, ""
}

func ReadSnapshotNPMIdentity(context.Context, SnapshotManifest, string, SnapshotNPMStreams) (SnapshotNPMEvidence, error) {
    return SnapshotNPMEvidence{}, nil
}
```

Expected behavioral RED: the positive test fails missing literal result, fatal cases fail because errors are nil, and counter/EOF tests fail their exact outcomes. Record actual failing tests; do not count the prior compiler error as behavioral failure.

#### Task 2B — Minimal complete GREEN algorithm

- [ ] **Step 8: Replace stubs with the frozen API and bounded reader primitives.** Start the new production file with the exact package/import block below, then copy the frozen public declarations verbatim before the private constants. The file must use only these imports/constants/counters and fixed private codes. The following code is complete for read/EOF/JSONL behavior; no goroutine or raw-error wrapping may replace it.

```go
package intel

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "io"

    "packtrace/internal/jsoninput"
)

const (
    maxSnapshotReadBytes              uint64 = 8 << 30
    maxSnapshotJSONLLineBytes                = 1 << 20
    maxSnapshotRetainedBindings              = 4_096
    maxSnapshotSuppliedOriginalStreams        = 1_024
    maxSnapshotUniqueOriginals               = 1_024
    maxSnapshotRetainedOriginalBytes  uint64 = 16 << 20
    maxSnapshotMetadataEntries        uint64 = 2_100_000
    maxSnapshotLogicalBytes           uint64 = 256 << 20
)

type snapshotReadBudget struct{ used uint64 }
func (b *snapshotReadBudget) remaining() uint64 { return maxSnapshotReadBytes - b.used }
func (b *snapshotReadBudget) canStart(n uint64) bool { return n <= b.remaining() }
func (b *snapshotReadBudget) charge(n uint64) bool {
    if n > b.remaining() { return false }
    b.used += n
    return true
}

type snapshotRetainedBudget struct {
    raw, metadata, logical uint64
}
func (b *snapshotRetainedBudget) metadataEntry() bool {
    if b.metadata == maxSnapshotMetadataEntries { return false }
    b.metadata++
    return true
}
func (b *snapshotRetainedBudget) logicalBytes(n uint64) bool {
    if n > maxSnapshotLogicalBytes-b.logical { return false }
    b.logical += n
    return true
}
func (b *snapshotRetainedBudget) reserveOriginal(raw, projection uint64) bool {
    if projection > ^uint64(0)-raw { return false }
    combined := raw + projection
    if raw > maxSnapshotRetainedOriginalBytes-b.raw || combined > maxSnapshotLogicalBytes-b.logical {
        return false
    }
    b.raw += raw
    b.logical += combined
    return true
}

type snapshotChunkSink func([]byte) string

func readSnapshotStream(ctx context.Context, r io.Reader, expected uint64, budget *snapshotReadBudget, sink snapshotChunkSink) ([32]byte, uint64, bool, string) {
    if r == nil { return [32]byte{}, 0, false, "invalid-shape" }
    if !budget.canStart(expected) { return [32]byte{}, 0, true, "" }
    h := sha256.New()
    buf := make([]byte, 32<<10)
    var observed uint64
    for {
        if ctx == nil { return [32]byte{}, 0, false, "invalid-shape" }
        select { case <-ctx.Done(): return [32]byte{}, 0, false, "canceled"; default: }
        remainingWithDetection := expected + 1 - observed
        request := uint64(len(buf))
        if request > remainingWithDetection { request = remainingWithDetection }
        if request > budget.remaining() { request = budget.remaining() }
        if request == 0 { return [32]byte{}, observed, true, "" }
        n, err := r.Read(buf[:int(request)])
        validCount := n >= 0 && n <= int(request)
        charged := true
        if validCount && n > 0 {
            charged = budget.charge(uint64(n))
            if charged { observed += uint64(n) }
        }
        // Charge valid returned bytes before cancellation; classify neither
        // returned content nor reader/count errors until this check.
        select { case <-ctx.Done(): return [32]byte{}, observed, false, "canceled"; default: }
        if !validCount { return [32]byte{}, observed, false, "read-failed" }
        if !charged { return [32]byte{}, observed, false, "limit-exceeded" }
        if observed > expected { return [32]byte{}, observed, false, "length-mismatch" }
        if n > 0 {
            _, _ = h.Write(buf[:n])
            if code := sink(buf[:n]); code != "" { return [32]byte{}, observed, false, code }
        }
        if err != nil {
            if err != io.EOF { return [32]byte{}, observed, false, "read-failed" }
            if observed != expected { return [32]byte{}, observed, false, "length-mismatch" }
            var sum [32]byte
            copy(sum[:], h.Sum(nil))
            return sum, observed, false, ""
        }
        if n == 0 { return [32]byte{}, observed, false, "read-failed" }
    }
}

func readSnapshotOriginalBytes(ctx context.Context, r io.Reader, expected uint64, budget *snapshotReadBudget) ([]byte, bool, string) {
    if expected > maxSnapshotObjectCheckBytes { return nil, false, "limit-exceeded" }
    data := make([]byte, 0, int(expected))
    _, _, resource, code := readSnapshotStream(ctx, r, expected, budget, func(chunk []byte) string {
        if uint64(len(data))+uint64(len(chunk)) <= expected {
            data = append(data, chunk...)
        }
        return ""
    })
    if code != "" || resource { return nil, resource, code }
    return data, false, ""
}

type snapshotJSONLState struct {
    line []byte
    overLine bool
    profileGap bool
    rows uint64
    prefix [3]byte
    prefixBytes int
}

func snapshotPhysicalRowNext(rows *uint64) string {
    if *rows >= maxSnapshotManifestRecords { return "limit-exceeded" }
    *rows += 1
    return ""
}

func readSnapshotJSONL(ctx context.Context, r io.Reader, ref SnapshotObjectReference, budget *snapshotReadBudget, visit func([]byte, uint64) string) (SnapshotStreamState, bool, string) {
    s := snapshotJSONLState{line: make([]byte, 0, 512)}
    sum, observed, resource, code := readSnapshotStream(ctx, r, ref.Bytes, budget, func(chunk []byte) string {
        for _, c := range chunk {
            if s.prefixBytes < len(s.prefix) {
                s.prefix[s.prefixBytes] = c
                s.prefixBytes++
                if s.prefixBytes == len(s.prefix) && s.prefix == ([3]byte{0xef, 0xbb, 0xbf}) {
                    return "invalid-shape"
                }
            }
            if c == '\r' { return "invalid-shape" }
            if c != '\n' {
                if !s.overLine {
                    if len(s.line) == maxSnapshotJSONLLineBytes {
                        s.overLine, s.profileGap = true, true
                        s.line = s.line[:0]
                    } else {
                        s.line = append(s.line, c)
                    }
                }
                continue
            }
            if !s.overLine && len(s.line) == 0 { return "invalid-shape" }
            physical := s.rows
            if code := snapshotPhysicalRowNext(&s.rows); code != "" { return code }
            if !s.overLine {
                if code := visit(s.line, physical); code != "" { return code }
            }
            s.line = s.line[:0]
            s.overLine = false
        }
        return ""
    })
    if code != "" { return SnapshotStreamUnknown, false, code }
    if resource { return SnapshotStreamUnavailable, true, "" }
    if observed != ref.Bytes { return SnapshotStreamUnknown, false, "length-mismatch" }
    if len(s.line) != 0 || s.overLine { return SnapshotStreamUnknown, false, "invalid-shape" }
    if sum != ref.SHA256 { return SnapshotStreamUnknown, false, "digest-mismatch" }
    if s.rows != ref.Records { return SnapshotStreamUnknown, false, "invalid-shape" }
    if s.profileGap { return SnapshotStreamBytesVerified, true, "" }
    return SnapshotStreamStructured, false, ""
}
```

- [ ] **Step 9: Add exact row parsers and ordering.** They reuse `jsoninput.Object` and `snapshotManifestUint`; every referenced helper is defined here.

```go
type snapshotCatalogRow struct { ordinal uint64; digest [32]byte; bytes uint64 }
type snapshotBlockRow struct {
    identity [32]byte
    ecosystem, name string
    ordinal uint64
    digest [32]byte
    bytes, affected uint64
}
type snapshotPendingBinding struct {
    ordinal, affected uint64
    digest [32]byte
    bytes uint64
    catalogBound bool
}

func snapshotExactRow(line []byte, keys ...string) (map[string]json.RawMessage, string) {
    fields, code := jsoninput.Object(line, maxSnapshotJSONLLineBytes)
    if code != "" { return nil, code }
    if len(fields) != len(keys) { return nil, "invalid-shape" }
    for _, key := range keys { if _, ok := fields[key]; !ok { return nil, "invalid-shape" } }
    return fields, ""
}

func snapshotRowDigest(fields map[string]json.RawMessage, key string) ([32]byte, string) {
    value := projectOSVString(fields, key)
    if value.State != OSVFieldValue || len(value.Value) != 64 { return [32]byte{}, "invalid-shape" }
    raw, err := hex.DecodeString(value.Value)
    if err != nil || hex.EncodeToString(raw) != value.Value { return [32]byte{}, "invalid-shape" }
    var out [32]byte
    copy(out[:], raw)
    return out, ""
}

func snapshotRowVersion(fields map[string]json.RawMessage) string {
    value, code := snapshotManifestUint(fields["v"], 1)
    if code != "" || value != 1 { return "invalid-shape" }
    return ""
}

func parseSnapshotCatalogRow(line []byte) (snapshotCatalogRow, string) {
    fields, code := snapshotExactRow(line, "v", "sourceOrdinal", "sha256", "bytes")
    if code != "" { return snapshotCatalogRow{}, code }
    if code = snapshotRowVersion(fields); code != "" { return snapshotCatalogRow{}, code }
    ordinal, code := snapshotManifestUint(fields["sourceOrdinal"], maxSnapshotManifestRecords-1)
    if code != "" { return snapshotCatalogRow{}, code }
    digest, code := snapshotRowDigest(fields, "sha256")
    if code != "" { return snapshotCatalogRow{}, code }
    size, code := snapshotManifestUint(fields["bytes"], maxSnapshotObjectCheckBytes)
    if code != "" { return snapshotCatalogRow{}, code }
    if size == 0 { return snapshotCatalogRow{}, "invalid-shape" }
    return snapshotCatalogRow{ordinal: ordinal, digest: digest, bytes: size}, ""
}

func parseSnapshotBlockRow(line []byte) (snapshotBlockRow, string) {
    fields, code := snapshotExactRow(line, "v", "identityHash", "ecosystem", "name", "sourceOrdinal", "originalSHA256", "originalBytes", "affectedIndex")
    if code != "" { return snapshotBlockRow{}, code }
    if code = snapshotRowVersion(fields); code != "" { return snapshotBlockRow{}, code }
    identity, code := snapshotRowDigest(fields, "identityHash")
    if code != "" { return snapshotBlockRow{}, code }
    ecosystem, name := projectOSVString(fields, "ecosystem"), projectOSVString(fields, "name")
    if ecosystem.State != OSVFieldValue || ecosystem.Value != "npm" ||
        name.State != OSVFieldValue || !validOSVNPMName(name.Value) {
        return snapshotBlockRow{}, "invalid-shape"
    }
    ordinal, code := snapshotManifestUint(fields["sourceOrdinal"], maxSnapshotManifestRecords-1)
    if code != "" { return snapshotBlockRow{}, code }
    digest, code := snapshotRowDigest(fields, "originalSHA256")
    if code != "" { return snapshotBlockRow{}, code }
    size, code := snapshotManifestUint(fields["originalBytes"], maxSnapshotObjectCheckBytes)
    if code != "" { return snapshotBlockRow{}, code }
    if size == 0 { return snapshotBlockRow{}, "invalid-shape" }
    affected, code := snapshotManifestUint(fields["affectedIndex"], ^uint64(0))
    if code != "" { return snapshotBlockRow{}, code }
    computed := snapshotNPMIdentityHash(name.Value)
    if identity != computed { return snapshotBlockRow{}, "invalid-shape" }
    return snapshotBlockRow{identity: identity, ecosystem: ecosystem.Value, name: name.Value, ordinal: ordinal, digest: digest, bytes: size, affected: affected}, ""
}

func snapshotNPMIdentityHash(name string) [32]byte {
    h := sha256.New()
    _, _ = h.Write([]byte("npm"))
    _, _ = h.Write([]byte{0})
    _, _ = h.Write([]byte(name))
    var out [32]byte
    copy(out[:], h.Sum(nil))
    return out
}

func compareSnapshotBlockRows(a, b snapshotBlockRow) int {
    if n := bytes.Compare(a.identity[:], b.identity[:]); n != 0 { return n }
    if n := bytes.Compare([]byte(a.ecosystem), []byte(b.ecosystem)); n != 0 { return n }
    if n := bytes.Compare([]byte(a.name), []byte(b.name)); n != 0 { return n }
    if a.ordinal < b.ordinal { return -1 }; if a.ordinal > b.ordinal { return 1 }
    if a.affected < b.affected { return -1 }; if a.affected > b.affected { return 1 }
    return 0
}
```

- [ ] **Step 10: Add manifest guards, complete declaration accounting, gaps, and projection-size accounting.** These helpers are complete and do not authenticate fabricated typed structs.

```go
func snapshotBaselineGaps() []SnapshotGapKind {
    return []SnapshotGapKind{
        SnapshotGapIndexCompleteness, SnapshotGapCorrection, SnapshotGapActivity,
        SnapshotGapSourceQualification, SnapshotGapRegistryCorrespondence,
        SnapshotGapFindingAuthority, SnapshotGapGlobalStoreQuota,
        SnapshotGapPreparationByteIdentity,
    }
}

func snapshotAddGap(gaps []SnapshotGapKind, kind SnapshotGapKind) []SnapshotGapKind {
    for _, existing := range gaps { if existing == kind { return gaps } }
    return append(gaps, kind)
}

func validateSnapshotNPMReference(ref SnapshotObjectReference) string {
    if ref.Fields == nil || ref.Bytes > maxSnapshotManifestObjectBytes || ref.Records > maxSnapshotManifestRecords {
        return "invalid-shape"
    }
    if ref.Bytes == 0 && (ref.Records != 0 || ref.SHA256 != sha256.Sum256(nil)) {
        return "invalid-shape"
    }
    return ""
}

// The caller supplies an unchanged result from ParseSnapshotManifestV11.
// These cheap typed guards defend direct-reference fields/counters used for
// routing, allocation and budgets; they do not reparse raw manifest JSON or
// authenticate caller-fabricated evidence.
func validateSnapshotNPMManifest(manifest SnapshotManifest) string {
    if manifest.SchemaVersion != "1.1" || manifest.Fields == nil || manifest.Source.Fields == nil ||
        manifest.Source.ID == "" || manifest.Originals.Fields == nil || len(manifest.Blocks) != maxSnapshotManifestBlocks ||
        validateSnapshotNPMReference(manifest.Originals) != "" {
        return "invalid-shape"
    }
    lengths := map[[32]byte]uint64{manifest.Originals.SHA256: manifest.Originals.Bytes}
    blockCounts := make(map[[32]byte]uint64)
    remainingBytes := uint64(maxSnapshotManifestObjectBytes) - manifest.Originals.Bytes
    remainingRecords := uint64(maxSnapshotManifestRecords)
    for i, block := range manifest.Blocks {
        ref := block.Reference
        if block.Index != i || validateSnapshotNPMReference(ref) != "" { return "invalid-shape" }
        if length, shared := lengths[ref.SHA256]; shared {
            if length != ref.Bytes { return "invalid-shape" }
        } else {
            if ref.Bytes > remainingBytes { return "invalid-shape" }
            remainingBytes -= ref.Bytes
            lengths[ref.SHA256] = ref.Bytes
        }
        if count, shared := blockCounts[ref.SHA256]; shared && count != ref.Records {
            return "invalid-shape"
        }
        if ref.Records > remainingRecords { return "invalid-shape" }
        remainingRecords -= ref.Records
        blockCounts[ref.SHA256] = ref.Records
    }
    return ""
}

func snapshotAddDeclaration(lengths map[[32]byte]uint64, digest [32]byte, size uint64, remaining *uint64, retained *snapshotRetainedBudget, overflow *bool) string {
    if old, ok := lengths[digest]; ok {
        if old != size { return "invalid-shape" }
        return ""
    }
    if !retained.metadataEntry() || !retained.logicalBytes(40) { return "resource" }
    if size > *remaining {
        if overflow == nil { return "limit-exceeded" }
        *overflow = true
        *remaining = 0
    } else {
        *remaining -= size
    }
    lengths[digest] = size
    return ""
}

func snapshotProjectionLogicalBytes(header OSVHeader, affected OSVAffectedProjection, identity OSVNPMIdentityProjection, times OSVTimes) (uint64, bool) {
    var total uint64
    add := func(n int) bool {
        if uint64(n) > ^uint64(0)-total { return false }
        total += uint64(n)
        return true
    }
    addString := func(v OSVString) bool { return add(len(v.Value)) }
    if !addString(header.ID) || !addString(header.SchemaVersion) { return 0, false }
    for _, entry := range affected.Entries {
        if !addString(entry.Ecosystem) || !addString(entry.Name) || !addString(entry.PURL) { return 0, false }
        for _, version := range entry.Versions.Entries { if !addString(version) { return 0, false } }
        for _, r := range entry.Ranges.Entries {
            if !addString(r.Type) || !addString(r.Repo) { return 0, false }
            for _, event := range r.Events.Entries {
                for _, field := range event.Fields {
                    if !add(len(field.Name)) || !addString(field.Value) { return 0, false }
                }
            }
        }
    }
    for _, entry := range identity.Entries {
        if !addString(entry.Ecosystem) || !addString(entry.Name) || !addString(entry.PURL) || !add(len(entry.PURLName)) { return 0, false }
        for _, problem := range entry.Problems { if !add(len(problem.Field)) { return 0, false } }
    }
    for _, value := range []OSVTimestamp{times.Modified, times.Published, times.Withdrawn} {
        if !add(len(value.Text)) { return 0, false }
    }
    return total, true
}
```

- [ ] **Step 11: Implement the full consumer in the fixed phase order.** This is the complete algorithm. Keep local errors fixed and whole-zero; update `BytesRead` only on nonfatal returns.

```go
func ReadSnapshotNPMIdentity(ctx context.Context, manifest SnapshotManifest, name string, streams SnapshotNPMStreams) (SnapshotNPMEvidence, error) {
    fail := func(code string) (SnapshotNPMEvidence, error) {
        return SnapshotNPMEvidence{}, &ParseError{Code: code}
    }
    if ctx == nil { return fail("invalid-shape") }
    // Count every raw supplied slot, including nil and duplicates, before any
    // manifest-map inspection, result/map allocation, or stream read.
    if len(streams.Originals) > maxSnapshotSuppliedOriginalStreams {
        return fail("limit-exceeded")
    }
    if validateSnapshotNPMManifest(manifest) != "" || !validOSVNPMName(name) || streams.Block == nil || streams.Catalog == nil {
        return fail("invalid-shape")
    }
    identityHash := snapshotNPMIdentityHash(name)
    blockIndex := identityHash[0]
    out := SnapshotNPMEvidence{
        ManifestSHA256: manifest.SHA256, IdentityHash: identityHash,
        Ecosystem: "npm", Name: name, BlockIndex: blockIndex,
        Declaration: SnapshotDeclarationGap,
        Records: make([]SnapshotOriginalEvidence, 0),
        Gaps: snapshotBaselineGaps(),
    }
    readBudget := snapshotReadBudget{}
    retained := snapshotRetainedBudget{}
    if !retained.logicalBytes(uint64(len(name))) { out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource); return out, nil }

    pending := make([]snapshotPendingBinding, 0)
    var previous snapshotBlockRow
    havePrevious, selectionGap := false, false
    blockState, resource, code := readSnapshotJSONL(ctx, streams.Block, manifest.Blocks[int(blockIndex)].Reference, &readBudget, func(line []byte, _ uint64) string {
        row, code := parseSnapshotBlockRow(line)
        if code != "" { return code }
        if row.identity[0] != blockIndex { return "invalid-shape" }
        if havePrevious && compareSnapshotBlockRows(previous, row) >= 0 { return "invalid-shape" }
        previous, havePrevious = row, true
        if row.identity == identityHash && row.ecosystem == "npm" && row.name == name {
            if len(pending) == maxSnapshotRetainedBindings || !retained.metadataEntry() {
                selectionGap = true
                return ""
            }
            pending = append(pending, snapshotPendingBinding{ordinal: row.ordinal, affected: row.affected, digest: row.digest, bytes: row.bytes})
        }
        return ""
    })
    if code != "" { return fail(code) }
    out.BlockState, out.BytesRead = blockState, readBudget.used
    if resource || selectionGap {
        out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
        return out, nil
    }

    selected := make(map[uint64][]int, len(pending))
    for i := range pending { selected[pending[i].ordinal] = append(selected[pending[i].ordinal], i) }
    lengths := make(map[[32]byte]uint64)
    remainingDeclared := uint64(maxSnapshotManifestObjectBytes)
    addDirect := func(ref SnapshotObjectReference) string {
        return snapshotAddDeclaration(lengths, ref.SHA256, ref.Bytes, &remainingDeclared, &retained, nil)
    }
    if code = addDirect(manifest.Originals); code != "" { if code == "resource" { out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource); return out, nil }; return fail(code) }
    for _, block := range manifest.Blocks {
        if code = addDirect(block.Reference); code != "" { if code == "resource" { out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource); return out, nil }; return fail(code) }
    }
    declarationOverflow := false
    catalogState, resource, code := readSnapshotJSONL(ctx, streams.Catalog, manifest.Originals, &readBudget, func(line []byte, physical uint64) string {
        row, code := parseSnapshotCatalogRow(line)
        if code != "" { return code }
        if row.ordinal != physical { return "invalid-shape" }
        if code = snapshotAddDeclaration(lengths, row.digest, row.bytes, &remainingDeclared, &retained, &declarationOverflow); code != "" { return code }
        for _, index := range selected[row.ordinal] {
            if pending[index].digest != row.digest || pending[index].bytes != row.bytes { return "invalid-shape" }
            pending[index].catalogBound = true
        }
        return ""
    })
    if code != "" { if code == "resource" { out.CatalogState = SnapshotStreamUnavailable; out.BytesRead = readBudget.used; out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource); return out, nil }; return fail(code) }
    out.CatalogState, out.BytesRead = catalogState, readBudget.used
    if resource {
        out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
        return out, nil
    }
    for _, binding := range pending {
        if !binding.catalogBound { return fail("invalid-shape") }
    }
    if declarationOverflow { return fail("limit-exceeded") }
    out.Declaration = SnapshotDeclarationVerified

    supplied := make(map[[32]byte]io.Reader, len(streams.Originals))
    for _, item := range streams.Originals {
        if item.Reader == nil { continue }
        if _, duplicate := supplied[item.SHA256]; duplicate { return fail("invalid-shape") }
        supplied[item.SHA256] = item.Reader
    }
    order := make([][32]byte, 0)
    grouped := make(map[[32]byte][]SnapshotAffectedBinding)
    expected := make(map[[32]byte]uint64)
    for _, item := range pending {
        if old, ok := expected[item.digest]; ok && old != item.bytes { return fail("invalid-shape") }
        if _, ok := grouped[item.digest]; !ok {
            if len(order) == maxSnapshotUniqueOriginals || !retained.metadataEntry() {
                out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
                out.BytesRead = readBudget.used
                return out, nil
            }
            order = append(order, item.digest)
            expected[item.digest] = item.bytes
        }
        grouped[item.digest] = append(grouped[item.digest], SnapshotAffectedBinding{
            SourceOrdinal: item.ordinal, AffectedIndex: item.affected,
            State: SnapshotBindingGap, Problem: SnapshotBindingProblemOriginal,
        })
    }

    for _, digest := range order {
        record := SnapshotOriginalEvidence{
            SHA256: digest, Bytes: expected[digest], State: SnapshotOriginalUnavailable,
            Bindings: append([]SnapshotAffectedBinding(nil), grouped[digest]...),
        }
        reader, ok := supplied[digest]
        if !ok {
            record.Problem = SnapshotOriginalProblemMissing
            out.Records = append(out.Records, record)
            continue
        }
        if record.Bytes > maxSnapshotRetainedOriginalBytes-retained.raw ||
            record.Bytes > maxSnapshotLogicalBytes-retained.logical {
            record.Problem = SnapshotOriginalProblemResource
            out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
            out.Records = append(out.Records, record)
            continue
        }
        raw, resource, readCode := readSnapshotOriginalBytes(ctx, reader, record.Bytes, &readBudget)
        out.BytesRead = readBudget.used
        if readCode == "canceled" { return fail(readCode) }
        if resource || readCode == "limit-exceeded" {
            record.Problem = SnapshotOriginalProblemResource
            out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
            out.Records = append(out.Records, record)
            continue
        }
        if readCode == "read-failed" { record.Problem = SnapshotOriginalProblemRead; out.Records = append(out.Records, record); continue }
        if readCode == "length-mismatch" { record.Problem = SnapshotOriginalProblemLength; out.Records = append(out.Records, record); continue }
        if readCode != "" { return fail(readCode) }
        check, err := CheckSnapshotObject(SnapshotObjectReference{SHA256: digest, Bytes: record.Bytes}, raw)
        if err != nil { record.Problem = SnapshotOriginalProblemResource; out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource); out.Records = append(out.Records, record); continue }
        if check.State == SnapshotObjectCheckLengthMismatch { record.Problem = SnapshotOriginalProblemLength; out.Records = append(out.Records, record); continue }
        if check.State != SnapshotObjectCheckBytesEqual { record.Problem = SnapshotOriginalProblemDigest; out.Records = append(out.Records, record); continue }
        doc, err := ParseOSVRecord(raw)
        if err != nil { record.Problem = SnapshotOriginalProblemParse; out.Records = append(out.Records, record); continue }
        header, hErr := ProjectOSVHeader(doc)
        affected, aErr := ProjectOSVAffected(doc)
        identity, iErr := QualifyOSVNPMIdentities(header, affected)
        times, tErr := ProjectOSVTimes(doc)
        if hErr != nil || aErr != nil || iErr != nil || tErr != nil ||
            doc.SHA256 != digest || header.SourceSHA256 != digest || affected.SourceSHA256 != digest ||
            identity.SourceSHA256 != digest || times.SourceSHA256 != digest {
            record.Problem = SnapshotOriginalProblemProjection
            out.Records = append(out.Records, record)
            continue
        }
        projectionBytes, ok := snapshotProjectionLogicalBytes(header, affected, identity, times)
        if !ok || !retained.reserveOriginal(record.Bytes, projectionBytes) {
            record.Problem = SnapshotOriginalProblemResource
            out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
            out.Records = append(out.Records, record)
            continue
        }
        record.Raw, record.Header, record.Affected, record.Identity, record.Times = raw, header, affected, identity, times
        record.State, record.Problem = SnapshotOriginalVerified, SnapshotOriginalProblemNone
        for i := range record.Bindings {
            binding := &record.Bindings[i]
            if binding.AffectedIndex >= uint64(len(identity.Entries)) || binding.AffectedIndex >= uint64(len(affected.Entries)) {
                binding.Problem = SnapshotBindingProblemAffectedIndex
                continue
            }
            entry := identity.Entries[int(binding.AffectedIndex)]
            if entry.Qualification != OSVNPMIdentityCandidate || entry.Ecosystem.State != OSVFieldValue ||
                entry.Ecosystem.Value != "npm" || entry.Name.State != OSVFieldValue || entry.Name.Value != name ||
                snapshotNPMIdentityHash(entry.Name.Value) != identityHash {
                binding.Problem = SnapshotBindingProblemIdentity
                continue
            }
            binding.State, binding.Problem = SnapshotBindingEligible, SnapshotBindingProblemNone
        }
        out.Records = append(out.Records, record)
    }
    return out, nil
}
```

During implementation review, correct only compile-time details that preserve this algorithm and frozen API. Any semantic change—especially corruption versus resource result, EOF evidence, limits, field names/states, or gap set—requires coordinator/owner review, not inference.

- [ ] **Step 12: Add the remaining exact limit/ownership tests.**

`TestReadSnapshotNPMIdentityLimits` must cover:

- original size 4,194,304 with synthetically padded valid JSON accepted; catalog `bytes:4194305` whole-zero `limit-exceeded`;
- selected block over 4 MiB succeeds by using five valid ≤1 MiB padded rows in sorted order; the test may allocate roughly 5 MiB, never 8 GiB;
- retained binding 4,096 accepted and 4,097 returns resource gap after full block verification;
- raw supplied `Originals` slots 1,024 accepted and 1,025 returns whole-zero `limit-exceeded` before result/map allocation or any block/catalog/original read; nil and duplicate slots count toward this bound;
- unique selected originals 1,024 accepted structurally and 1,025 returns resource gap before original reads; both cases supply an empty `Originals` slice while their sorted block/catalog rows reference distinct synthetic digests, so the supplied-slot ceiling cannot mask the selected-unique ceiling. The 1,024 case retains missing-original states without a resource gap; the 1,025 case returns a resource gap before materializing records;
- catalog physical rows exercise the actual production `snapshotPhysicalRowNext` branch using `TestSnapshotReadBudgetPhysicalRows` above, not a reconstructed oracle or two million heap-heavy fixture objects; 2,000,001 returns `limit-exceeded`;
- direct+catalog unique declarations exactly 32 GiB accepted as declaration-valid without reading those originals; +1 returns whole-zero `limit-exceeded`;
- actual 8 GiB boundary uses initialized private counter math shown above, not an 8 GiB object;
- raw 16 MiB/logical 256 MiB boundaries use private retained-counter arithmetic with small payloads, not equivalent allocations; one test proves a failed combined raw+projection reservation changes neither counter;
- metadata 2,100,000 boundary uses private counter initialization, not millions of maps.

`TestReadSnapshotNPMIdentityGapsPrivacyOwnership` must assert:

- baseline gap slice is exactly the eight ordered values on positive and empty selected-block results;
- empty block gives zero records but retains `SnapshotGapIndexCompleteness`, `SnapshotGapCorrection`, and `SnapshotGapFindingAuthority`;
- reader error `errors.New("private-path:/secret/raw-marker")`, malformed row marker, and source locator marker never occur in returned/fatal error text;
- clearing original input bytes after return does not alter `record.Raw` or projections;
- mutating returned `Raw`, `Affected.Entries`, `Identity.Entries`, or `Bindings` does not alter caller bytes or a fresh call;
- two bindings for one digest share only indices into one record-level projection; no row-level projection/raw fields exist;
- no test expects authenticated source, registry qualification, active/correction-free advisory, complete index, finding, or applicability.

Add this exact scope guard so the version evaluator and operational imports cannot enter the owned consumer unnoticed:

```go
func TestReadSnapshotNPMIdentitySourceScope(t *testing.T) {
    file, err := parser.ParseFile(token.NewFileSet(), "snapshot_npm_stream.go", nil, 0)
    if err != nil { t.Fatal("cannot inspect consumer source", err) }
    allowed := map[string]bool{
        "bytes": true, "context": true, "crypto/sha256": true,
        "encoding/hex": true, "encoding/json": true, "io": true,
        "packtrace/internal/jsoninput": true,
    }
    for _, imp := range file.Imports {
        path, err := strconv.Unquote(imp.Path.Value)
        if err != nil || !allowed[path] { t.Fatal("operational or dependency import entered consumer") }
    }
    for _, decl := range file.Decls {
        if d, ok := decl.(*ast.GenDecl); ok && d.Tok == token.VAR {
            t.Fatal("mutable package global entered consumer")
        }
    }
    ast.Inspect(file, func(node ast.Node) bool {
        call, ok := node.(*ast.CallExpr)
        if !ok { return true }
        if id, ok := call.Fun.(*ast.Ident); ok {
            switch id.Name {
            case "EvaluateOSVVersionConditions", "panic", "print", "println":
                t.Fatal("version/panic/output authority entered consumer")
            }
        }
        return true
    })
}
```

- [ ] **Step 13: Run focused GREEN.**

```nu
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go test -count=1 -run '^(TestReadSnapshotNPMIdentity|TestSnapshotReadBudget)' ./internal/intel
}
```

Expected: every named test/subtest passes. Record actual test counts/output; do not reuse historical counts.

#### Task 2C — Mutation checks, broader verification, checkpoint

- [ ] **Step 14: Run restored mutations one at a time.** Save the production-file digest outside the repo before each mutation and restore it exactly afterward.

| Mutation | Tests that must fail |
|---|---|
| charge declared bytes before reading | positive accounting + counter tests |
| omit detection byte/assume EOF at exact length | `no-budget-for-eof`, `detection-byte` |
| reset budget between block/catalog/original | reread/global-budget tests |
| accept CRLF or missing final LF | JSONL framing tests |
| omit streaming BOM prefix check | short/over-profile BOM tests |
| classify sink/extra-byte failure before post-read cancellation | cancel-plus-malformed/extra-byte tests and `TestSnapshotReadBudgetCancellationCharge` |
| move returned-byte charging after post-read cancellation | `TestSnapshotReadBudgetCancellationCharge` |
| weaken production physical-row ceiling | `TestSnapshotReadBudgetPhysicalRows` |
| treat selected block/catalog read error as a resource gap | `StreamReadErrors` |
| change selection to first-byte + ecosystem only, removing both full-hash and exact-name equality while retaining per-row hash recomputation | real `pkg-3`/`pkg-6` same-prefix test |
| use another affected slot when indexed slot differs | no-cross-slot binding test |
| duplicate projections per binding | duplicate-occurrence ownership/shape test |
| call/equate version evaluator | source AST/exclusion test |
| convert bad original to whole-query fatal | sibling-retention tests |
| convert corrupt block/catalog to resource gap | fatal whole-zero corruption tests |
| omit one baseline authority gap | authority-gap test |
| leak underlying reader/raw/path error | privacy test |

Expected: at least one named test fails for every compiling mutation. Compiler-only failures do not count. After each mutation, restore and verify the saved digest before proceeding.

- [ ] **Step 15: Format and run focused then root verification only after implementation approval.**

```nu
gofmt -w internal/intel/snapshot_npm_stream.go internal/intel/snapshot_npm_stream_test.go
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go version
    go test -count=1 -run '^(TestParseSnapshotManifest|TestReadSnapshotNPMIdentity|TestSnapshotReadBudget)' ./internal/intel
    if $env.LAST_EXIT_CODE != 0 { error make {msg: "focused tests failed"} }
    go test -count=1 ./...
    if $env.LAST_EXIT_CODE != 0 { error make {msg: "root tests failed"} }
    go vet ./...
    if $env.LAST_EXIT_CODE != 0 { error make {msg: "go vet failed"} }
    go build ./...
    if $env.LAST_EXIT_CODE != 0 { error make {msg: "go build failed"} }
}
```

These checks are synthetic and offline by dependency configuration, not OS-enforced network denial, native qualification, CI, release, or scanner availability. The fresh owned build is a compile/link regression check, not a working-scanner claim.

- [ ] **Step 16: Preserve the legacy CLI byte contract before checkpoint/publication.** The complete deterministic driver below preserves the 162 existing case/format invocations: 72 npm inspect, 40 batch, 12 demo and 38 Bun. It uses synthetic literal inputs only; it executes only the two approved, freshly built PackTrace executables, with 20-second invocation timeouts. It must not run during preparation. The coordinator supplies `$baseline_cli` from a fresh build of the exact verified development base, `$candidate_cli` from the exact candidate head, and an absent `$legacy_evidence` directory outside every checkout. Do not reuse a historical executable as fresh-build evidence. All stdout/stderr/exit triples must agree, including the synthetic Bun privacy/candidate assertions. Failure blocks the checkpoint; do not update expected output for this intel-only slice.

The driver is versioned as documentation in this same brief, not another product helper or document. Its exact UTF-8 source SHA-256 is `bab2c62e577f8e17fdbce91b71563a4e06d3a72108f63827e13a37585795ac0b`. After execution approval, extract that frozen block and invoke it using the following local Nushell commands. `$legacy_driver` must be a new file in the coordinator's owned external evidence directory; the baseline/candidate/evidence paths are frozen in the delivery receipt before these commands run. Neither extraction nor comparison authorizes fetching dependencies, opening a target project, or running target executables.

```nu
# The coordinator supplies these exact, frozen external evidence paths.
let legacy_driver = $env.PACKTRACE_LEGACY_DRIVER
let baseline_cli = $env.PACKTRACE_BASELINE_CLI
let candidate_cli = $env.PACKTRACE_CANDIDATE_CLI
let legacy_evidence = $env.PACKTRACE_LEGACY_EVIDENCE
let brief = "docs/increments/issue-54-multiplatform-offline-scan-program.md"
let extraction = 'import pathlib,re,hashlib,sys; text=pathlib.Path(sys.argv[1]).read_bytes(); pattern=rb"<!-- LEGACY_MATRIX_DRIVER_BEGIN -->\n```python\n(.*?)\n```\n<!-- LEGACY_MATRIX_DRIVER_END -->"; match=re.search(pattern,text,re.S); assert match; body=match.group(1)+b"\n"; assert hashlib.sha256(body).hexdigest()==sys.argv[3]; pathlib.Path(sys.argv[2]).open("xb").write(body)'
python -I -c $extraction $brief $legacy_driver "bab2c62e577f8e17fdbce91b71563a4e06d3a72108f63827e13a37585795ac0b"
if $env.LAST_EXIT_CODE != 0 { error make {msg: "driver extraction failed"} }
python -I $legacy_driver --baseline $baseline_cli --candidate $candidate_cli --evidence-dir $legacy_evidence
if $env.LAST_EXIT_CODE != 0 { error make {msg: "legacy byte comparison failed"} }
```

<!-- LEGACY_MATRIX_DRIVER_BEGIN -->
```python
import pathlib, subprocess, json, copy, argparse, hashlib
parser = argparse.ArgumentParser()
parser.add_argument("--baseline", required=True)
parser.add_argument("--candidate", required=True)
parser.add_argument("--evidence-dir", required=True)
args = parser.parse_args()
old = pathlib.Path(args.baseline).resolve()
new = pathlib.Path(args.candidate).resolve()
assert old != new, "baseline and candidate paths must be distinct"
assert new.is_file() and old.is_file()
D = pathlib.Path(args.evidence_dir)
D.mkdir(parents=True, exist_ok=False)
identities = {
    "baseline": {"path": str(old), "sha256": hashlib.sha256(old.read_bytes()).hexdigest()},
    "candidate": {"path": str(new), "sha256": hashlib.sha256(new.read_bytes()).hexdigest()},
}
(D / "executable-identities.json").write_text(json.dumps(identities, indent=2) + "\n", encoding="utf-8")
def call(bin,args,data):return subprocess.run([str(bin),*args],input=data,capture_output=True,timeout=20)
def pack(b,ad):return json.dumps({'lockfile_text':b,'advisory':ad}).encode()
def lock(pk,ws=None):return json.dumps({'lockfileVersion':1,'workspaces':ws or {},'packages':pk})
ad={'id':'PRIVATE-AD','modified':'2026-01-01T00:00:00Z','affected':[{'package':{'ecosystem':'npm','name':'private-marker-package'},'versions':['1.2.3']}]}
tuple=['private-marker-package@1.2.3','',{},'PRIVATE-INTEGRITY']
cases=[]
def add(name,b,a,count,exit=3):cases.append((name,pack(b,a),count,exit))
add('npm', '// PRIVATE-COMMENT\n'+lock({'PRIVATE-KEY':tuple})[:-1]+',}',ad,1)
sc=copy.deepcopy(ad);sc['affected'][0]['package']['name']='@scope/example';add('scoped',lock({'PRIVATE':['@scope/example@1.2.3','',{},'PRIVATE-INTEGRITY']}),sc,1)
add('empty-key-and-root',lock({'':tuple,'root':['@root:',{}]}),ad,1)
add('duplicate-claims',lock({'a':tuple,'z':tuple}),ad,2)
for name,bad in [('unknown',['private-marker-package@1.2.3',None,{},'PRIVATE-INTEGRITY']),('git',['private-marker-package@git+ssh://PRIVATE@host',{},'tag']),('link',['private-marker-package@link:PRIVATE',{}]),('workspace',['private-marker-package@workspace:PRIVATE']),('invalid-version',['private-marker-package@latest','',{},'PRIVATE-INTEGRITY'])]:add(name+'-with-sibling',lock({'a':bad,'z':tuple}),ad,1)
for name,w in [('withdrawn','2026-01-02T00:00:00Z'),('unknown-withdrawal',None)]:a=copy.deepcopy(ad);a['withdrawn']=w;add(name,lock({'a':tuple}),a,0)
a=copy.deepcopy(ad);a['affected']=[{'package':{'ecosystem':'npm','name':'other'},'versions':['1.2.3']},{'package':{'ecosystem':'npm','name':'private-marker-package'},'versions':['9.9.9']}];add('cross-slot',lock({'a':tuple}),a,0)
a=copy.deepcopy(ad);a['affected'][0].pop('versions');a['affected'][0]['ranges']=[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'1.2.3'}]}];add('fixed',lock({'a':tuple}),a,0)
add('empty-inventory',lock({}),ad,0)
a=copy.deepcopy(ad);a['affected']*=64;add('4096-pairs',lock({str(i):tuple for i in range(64)}),a,4096)
add('packages-overflow',lock({str(i):[] for i in range(65)}),ad,0,2)
add('workspaces-overflow',lock({'a':tuple},{str(i):{} for i in range(65)}),ad,0,2)
a=copy.deepcopy(ad);a['affected']*=65;add('affected-overflow',lock({'a':tuple}),a,0,2)
add('inner-malformed','PRIVATE-BROKEN',ad,0,2)
for name,data,count,exit in cases:
 for fmt in ['terminal','json']:
  r=call(new,['inspect-bun','--format',fmt],data);(D/(name+'-'+fmt+'.stdout')).write_bytes(r.stdout);(D/(name+'-'+fmt+'.stderr')).write_bytes(r.stderr)
  assert r.returncode==exit,(name,fmt,r.returncode)
  previous=call(old,['inspect-bun','--format',fmt],data);assert (r.returncode,r.stdout,r.stderr)==(previous.returncode,previous.stdout,previous.stderr),('Bun regression',name,fmt)
  assert not any(x in r.stdout+r.stderr for x in [b'PRIVATE',b'private-marker-package',b'1.2.3',b'@scope/example']),name
  if exit==2:assert not r.stdout and r.stderr
  else:
   assert not r.stderr
   if fmt=='json':
    v=json.loads(r.stdout);assert len(v['candidates'])==count and not v['findings'] and all(not x['enforcement_eligible'] and x['kind']=='bun-tuple-name-version-only' for x in v['candidates'])
    assert v['schema']=='packtrace.inspect.bun.v1' and any(c['check']=='advisory-applicability' and c['outcome']=='incomplete' for c in v['coverage'])
   else:assert f'Candidates: {count}'.encode() in r.stdout and b'Required coverage: incomplete' in r.stdout
(D/'owned-input.json').write_bytes(cases[0][1])
print('OWNED_COMPILED_BUN_CASES',len(cases),'BOTH_FORMATS',flush=True)
# Compare real legacy outputs, not just semantics/counts.
base={'lockfileVersion':3,'packages':{'':{},'node_modules/private-marker-package':{'name':'private-marker-package','version':'1.2.3'}}};legacy=[]
for change in [{},{'name':None},{'name':42},{'name':''},{'name':'other'},{'link':True},{'link':False},{'link':None},{'link':42},{'version':'latest'},{'version':None},{'version':42}]:b=copy.deepcopy(base);b['packages']['node_modules/private-marker-package'].update(change);legacy.append((b,ad))
b=copy.deepcopy(base);b['packages']['node_modules/private-marker-package'].pop('name');legacy.append((b,ad))
for change in [{'withdrawn':None},{'withdrawn':'2026-01-02T00:00:00Z'},{'affected':[]},{'affected':[{'package':{'ecosystem':'npm','name':'other'},'versions':['1.2.3']}]},{'affected':[{'package':{'ecosystem':'npm','name':'private-marker-package'},'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'}]}]}]}]:a=copy.deepcopy(ad);a.update(change);legacy.append((base,a))
checks=0
for b,a in legacy:
 for profile in ['explicit-only','npm-lock-v2-v3']:
  for fmt in ['terminal','json']:
   data=json.dumps({'lockfile':b,'advisory':a}).encode();args=['inspect','--format',fmt,'--identity-profile',profile];x=call(new,args,data);y=call(old,args,data);assert (x.returncode,x.stdout,x.stderr)==(y.returncode,y.stdout,y.stderr),('inspect regression',profile,fmt);checks+=1
batchchecks=0
for b,a in legacy[:10]:
 for profile in ['explicit-only','npm-lock-v2-v3']:
  for fmt in ['terminal','json']:
   data=json.dumps({'lockfile':b,'advisories':[a,42,a]}).encode();args=['inspect-batch','--format',fmt,'--identity-profile',profile];x=call(new,args,data);y=call(old,args,data);assert (x.returncode,x.stdout,x.stderr)==(y.returncode,y.stdout,y.stderr),'batch regression';batchchecks+=1
for scenario in ['candidate','no-version-match','unsupported','withdrawn','different-identity','malformed']:
 for fmt in ['terminal','json']:
  args=['demo','--scenario',scenario,'--format',fmt];x=call(new,args,b'');y=call(old,args,b'');assert (x.returncode,x.stdout,x.stderr)==(y.returncode,y.stdout,y.stderr),'demo regression'
print('BYTE_IDENTICAL_LEGACY',checks,'INSPECT',batchchecks,'BATCH',12,'DEMO',flush=True)
(D/'executable-verification.json').write_text(json.dumps({'owned_bun_cases':len(cases),'formats':2,'legacy_inspect':checks,'legacy_batch':batchchecks,'legacy_demo':12}))
assert len(cases) == 19 and checks == 72 and batchchecks == 40
assert len(cases) * 2 + checks + batchchecks + 12 == 162
print("BYTE_IDENTICAL_TOTAL", 162, flush=True)
```
<!-- LEGACY_MATRIX_DRIVER_END -->

Expected only after approved execution: `BYTE_IDENTICAL_TOTAL 162`, exit zero, and the driver-created evidence summary. This is not native/platform qualification. Preparation syntax parsing of this driver establishes neither successful compilation of the Go plan nor byte-identical behavior.

- [ ] **Step 17: Make the second file-scoped checkpoint only after restored GREEN and all 162 comparisons.**

```nu
jj diff --name-only
jj commit internal/intel/snapshot_npm_stream.go internal/intel/snapshot_npm_stream_test.go -m "feat: read supplied npm snapshot streams"
```

Expected path scope: only the two task-2 files. Do not include the brief, unrelated ledgers, module files, probes, or another workspace's changes. No `--allow-new`, direct push, force push, or branch deletion.

- [ ] **Step 18: Fresh task-2 and whole-branch review gates.** A fresh task-2 reviewer checks the exact second commit and restored evidence. After accepted fixes and reruns, a different fresh reviewer checks the combined task-1 + task-2 branch, including interfaces, five review-focus classes, exclusions, and exact file scope. Publication/integration remains blocked until both reviews accept.

### Approved bounded full-cycle publication and integration

I selected this full-cycle path for issue #56, subject to the exact task, review, acceptance and integration gates below. Section 16 records the approval; permissions do not extend to unrelated work or native acquisition.

1. Create **one bounded new child issue under #9** for this exact supplied-stream consumer. It references the approved section-12 contract, this plan, frozen files/API, and all exclusions. It does not close #9 or any other capability parent/epic; closed historical issue #21 is outside this slice.
2. Move only that child through Preparation → Ready after written plan/execution approval and satisfied dependencies; then In progress for one primary owner, Review after local evidence and fresh review, and Done only after accepted PR integration and closure evidence.
3. Create a new isolated issue workspace at the explicitly verified base before source work. Read-only repository metadata currently records SSH origin `git@github.com:landroval/PackTrace.git` and `origin/development` at `f7689f2e3c46a30f098a748a364d4690d8140b5e`. Add the workspace at that exact revision, then perform only a scoped SSH fetch of `development` inside the new workspace. If fetched `development@origin` differs, stop for coordinator base review; do not silently rebase. Do not run `jj new` in the existing workspace that carries the 21 unrelated historical ledger deletions, and do not perform a full-remote fetch. Preserve every other head/bookmark/workspace and unrelated `.pi/todos` state.
4. Publish one draft PR targeting `development`, initially `Refs #N`. Use `Closes #N` only if the PR itself meets the bounded child issue's complete acceptance. Never infer parent closure.
5. Preserve the subagent-driven sequence: fresh task-1 review before task 2, fresh task-2 review, then a different fresh whole-branch review. Verify focused/root tests, fresh owned build, and the 162 existing legacy CLI case/format stdout/stderr/exit byte comparisons (72 npm inspect, 40 batch, 12 demo, 38 Bun) on the exact PR head; rerun focused/root tests/vet/build on the combined development candidate and actual merged tree.
6. The standing administrator waiver remains persistent, PR-only and operationally development-only. This slice neither creates, removes, restores, narrows, nor widens it. No direct/force push, protection/ruleset change, branch deletion, peer-approval substitution, release, or main-branch bypass.
7. After accepted integration, close only the bounded child with its evidence and manually mark only its Project item Done. Preserve #9, #22, #38, PR #40 and all other actual open capability parents/epics unless their own acceptance is separately executed. Existing issue #21 is closed historical evidence, not an epic or an open gate for this slice.
8. The coordinator alone updates section 14/brief evidence. The implementer does not edit the brief or claim publication/integration completion.

Proposed setup commands, run only after authorization from the repository's coordinator workspace to create the new isolated workspace; they do not mutate the existing deletion-bearing workspace's working-copy commit:

```nu
# Exact paths and the owned socket/key are verified by the coordinator first.
cd $env.PACKTRACE_COORDINATOR_WORKSPACE
let expected_base = "f7689f2e3c46a30f098a748a364d4690d8140b5e"
let origin_url = (git remote get-url origin | str trim)
if $origin_url != "git@github.com:landroval/PackTrace.git" {
    error make {msg: "origin is not the verified SSH remote"}
}
let workspace = $env.PACKTRACE_NEW_WORKSPACE
jj workspace add --name issue-snapshot-npm-stream --revision $expected_base $workspace
cd $workspace
with-env {SSH_AUTH_SOCK: $env.PACKTRACE_VERIFIED_SSH_AGENT_SOCKET} {
    jj git fetch --remote origin --branch development
}
let fetched_base = (jj log --no-graph -r 'development@origin' -T 'commit_id ++ "\n"' | str trim)
if $fetched_base != $expected_base {
    error make {msg: "development moved; coordinator must verify a new base"}
}
jj status
jj log -r '@ | development@origin'
```

No `jj new` or unscoped `jj git fetch` is part of setup.

After the two scoped GREEN commits and approved publication only:

```nu
jj log -r '@ | @- | @--'
jj bookmark create issue-snapshot-npm-stream -r @-
jj git push --remote origin --bookmark issue-snapshot-npm-stream
gh pr create --repo landroval/PackTrace --base development --head issue-snapshot-npm-stream --draft --title "Intel: read supplied npm snapshot streams" --body "Refs the bounded child of #9. Scope, approvals, frozen interfaces, RED/GREEN, limits and exclusions are linked in the issue."
```

The exact new issue number is intentionally absent because creating it is not approved. Before publication, the coordinator replaces the body reference with that real issue URL/number and verifies the exact remote head. This is not a dangling implementation helper or permission to invent an issue number.

### Plan self-review

- **Spec coverage:** Tasks cover explicit manifest 1.1, unchanged 1.0, exact catalog/block rows, routing, order, five bindings, complete declaration accounting, one actual read counter, EOF semantics, original/projection reuse, record-local failures, retained siblings, all fixed bounds, cancellation limitations, authority gaps, and publication gates.
- **Excluded authority:** No filesystem/native/store/source/registry/CLI/report/finding/version-evaluation implementation appears. Global quota and preparation byte identity remain gaps.
- **Placeholder scan:** Production snippets define every helper they call. Test snippets name exact fixtures, outputs, error codes, and fail conditions. The table cases are mandatory named subtests, not generic “add tests” instructions.
- **Type consistency:** Frozen types/signatures match every task/snippet. `affectedIndex` stays `uint64` until checked against projection length; no unsafe conversion precedes the bound. The consumer assumes a parsed, unchanged 1.1 manifest but cheaply rechecks every consumed typed direct-reference index/range/coherence/aggregate before reading; it does not reparse JSON or claim authenticity.
- **Review Focus mapping:** Each of the five failure classes names its owning test above.
- **Task sizing:** Task 1 independently delivers explicit compatible 1.1 parsing. Task 2 independently delivers the complete smallest meaningful supplied-stream consumer. No setup/scaffolding microtask or speculative abstraction is split out.

### Recorded approvals before implementation

The following approvals were all granted by my full-cycle selection and recorded in section 16 before code; the listed boundaries remain binding.

1. Owner approval of this frozen API and resource profile: 1 MiB line, 4,096 bindings, 1,024 supplied original slots including nil/duplicates, 1,024 unique originals, 16 MiB raw, 2,100,000 metadata entries, 256 MiB logical payload, fixed 8 GiB actual reads; these are payload limits, not an RSS guarantee or worker-budget authority.
2. Separate explicit authorization for subagent-driven Go/test execution and restored mutations.
3. Separate explicit selection of the proposed full-cycle issue/PR/development integration/closure path; until selected, no GitHub or product-workspace/branch mutation. The coordinator's authorized brief-only planning checkpoints do not grant that full-cycle authority.

## 16. Approved supplied-stream execution and acceptance ledger — #56

I selected **Ciclo completo (recomendado)** after reviewing the prepared section-15 plan at `c722c8acc565a64cf6f3f7796025907d80f3e221`. This approves the exact internal API and resource profile, fresh task implementers/reviews, TDD, actually executed/restored compiling mutations, root tests/vet/build/gofmt, the frozen 162-case synthetic CLI comparison, one bounded child [#56](https://github.com/landroval/PackTrace/issues/56) of #9, PR/development integration and this child's completed/Done tracking after acceptance. I own the increment. The existing persistent PR-only waiver remains operationally development-only; it is not peer approval, new feature permission outside this scope, or a security change.

The implementation base is `f7689f2e3c46a30f098a748a364d4690d8140b5e`, verified against current development before execution. Baseline root verification passed **3,079 tests/subtests** under `go1.27.1-X:nodwarf5 linux/amd64`, with `GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0`. That observed toolchain and dependency configuration are not official/native/hosted-CI/release qualification or OS-enforced network isolation.

Only the four listed Go paths and this existing brief are approved public paths. Task 1 produces the explicit 1.1 parser consumed by task 2; its fresh review is required before task 2 starts. One coordinator owns the brief and GitHub/jj. No parent closure, #22/#38/PR #40 modification, new dependency, native/source-study extension, target execution, filesystem acquisition, CI, release, protection change, direct/force push, or branch/workspace deletion is permitted. All five native rows remain NOT RUN; macOS safety remains BLOCKED and `scan` unavailable.

- [x] Exact plan/API/profile/full-cycle approval recorded before new Go.
- [x] Current base, live scope, agreed ownership and parent #9 verified; baseline checks recorded.
- [x] Task 1: missing-API compiler RED (0 behavioral failures), compiling-stub
  behavioral RED (1 failure), focused GREEN **360** and root GREEN **3,080**
  tests/subtests. Checkpoint `bd22c1dcb15fa5047812118615afd456a9d985ae`.
  Fresh task review approved spec compliance and quality, with no findings.
  The 1.0 parser body/error order is unchanged except its private version parameter.
- [x] Task 2: missing-API compiler RED (0 behavioral failures); initial compiling-stub RED recorded 46 failures before a test-index panic. The guard was corrected and the replay reached all 17 top-level tests without panic/build failure: 85 failing events across 16 runtime top-level tests, with counter arithmetic and the static AST policy check explicitly passing. Restored focused GREEN **447**, root GREEN **3,167**. Code checkpoint `49e5c03369114550bf19d68f4ebc130646c05967`; test-only review fixes `369fec21930fd3200c2af258a3af5da4d0ef1b7a`. Fresh task review first required fixes, then approved spec and quality after resolving all three findings: guarded indexing/full RED, exact cancellation mutation selectors and unsupported-header integration. No API/profile/production behavior changed in that fix.
- [x] All **17** compiling mutations discriminated and restored exactly: **16 runtime-fixture** mutations and **1 static AST-scope** mutation for forbidden version evaluation. The corrected replay retained actual patches and pre/mutated/post hashes; the coordinator independently reconstructed every patch hash and checked all 19 failing invocation artifacts. Mutation 06 includes the private budget assertion plus both consumer cancellation cases; compiler-only mutation credit is zero.
- [x] Coordinator fresh restored-source root **3,167**, vet, all-package build, separate CLI build and gofmt checks; all **162** synthetic legacy stdout/stderr/exit comparisons are byte-identical against a separate fresh exact-base executable. Resource/privacy/ownership/sibling evidence remains bounded supplied-stream evidence, not filesystem or native qualification.
- [x] Fresh whole-branch review. Initial review found two Important precedence defects, also present in illustrative snippets: detection bytes reached the sink before length rejection; a catalog-prefix declaration overflow bypassed complete object verification. Both controlling approved rules remain unchanged. The root helper now rejects charged detection bytes after cancellation but before hash/sink; catalog overflow is remembered while bounded parsing/coherence/duplicate checks and full framing/count/length/digest/EOF verification continue. New pre-fix regressions compiled and demonstrated the concrete wrong codes, then passed; two compiling defect mutations failed and restored exactly. Fresh focused **465**, root **3,185**, vet/gofmt passed. The reference bodies above were corrected without API/profile expansion. Independent whole-branch follow-up accepted the corrected range through `891e3c3b7adbbc47847865ca44ed44e548426ab9`: Ready to publish YES for the review gate, no unresolved findings. Initial NO is retained as historical evidence. The coordinator renewed root **3,185**, vet/all-package and CLI builds/gofmt and all **162** byte-identical legacy comparisons on the restored fix-2 source. The 17-mutation matrix qualifies the earlier `c404200c` source; the two additional old-defect mutations qualify final `f390fa37` source. These 19 distinct mutation scenarios were executed across their respective phases, not all re-executed on the final source. The corrected exact-32-GiB slash-aware named test and final root run passed; the first fix-2 focused selector had not selected that case. Exact public/combined/actual merged-tree qualification remains a separate unchecked gate.
- [ ] Exact public head, combined prospect and actual merged-tree acceptance.
- [ ] Child #56 completed closure and only its Project item Done after verified development integration.
