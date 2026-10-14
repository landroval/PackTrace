# Issue #22: macOS regular-file opening qualification gap

## Result and disposition

**Result: BLOCKED documentary gap; native qualification NOT RUN.**

Issue #22 permits either review of a credible macOS handle-relative regular-file opening mechanism or documentation of the unresolved gap without claiming impossibility. This report selects and completes the second alternative. The current bounded evidence does not establish a complete pre-content-open chain that both accepts qualified in-root links and excludes special-device opening before side effects. It also does not establish that no such macOS mechanism can exist.

After second-person documentary review and verified integration, this report may satisfy issue #22 and support closing that child as **gap documented**. That closure is not a native PASS, does not qualify a runner or scanner, does not remove any platform row, and does not complete parent capability [#7](https://github.com/landroval/PackTrace/issues/7).

I explicitly authorize this bounded two-file documentary #22 modification, issue-specific PR-only integration, and #22 closure after reviewed integration. This supersedes the remaining-stage gates in section 10 of [issue #54's program record](issue-54-multiplatform-offline-scan-program.md) and the explicit #22 modification exclusion in section 16 only for this documentary alternative. It does not authorize or prove source acquisition, a credible mechanism, prototype/native code, runner provisioning, native execution, a platform row, a device or scanner result, production implementation or qualification, workflow or security changes, or closure of capability #7.

## Preserved source record

No new source was acquired or inspected for this report. The evidence below is the already executed, bounded upstream study recorded in [issue #54 section 13](issue-54-multiplatform-offline-scan-program.md#13-executed-bounded-upstream-macos-source-study), read with [Probe B](../native-safety-probe.md) and [design decision 27](../design-decisions.md#27-native-feasibility-gate).

### Exact pins and provenance

- Go contract: official Go **1.27.1** [`os.Root`](https://pkg.go.dev/os@go1.27.1#Root) documentation. `os.Root` supplies beneath-root containment but does not prohibit filesystem crossings or Unix device access; `Lstat → Open` re-resolves the name and is not a same-object guarantee.
- XNU source pin: **`xnu-11215.1.10`**:
  - [`bsd/vfs/vfs_syscalls.c`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/vfs/vfs_syscalls.c): `openat_internal`, `open1at`, `open1`
  - [`bsd/vfs/vfs_vnops.c`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/vfs/vfs_vnops.c): `vn_open_auth`, `vn_open_auth_finish`, `vn_read`, `vn_stat_noauth`
  - [`bsd/sys/fcntl.h`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/sys/fcntl.h): `O_EVTONLY`, `FFLAGS`, `FMASK`, `FCNTLFLAGS`
  - [`bsd/kern/kern_descrip.c`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/kern/kern_descrip.c): `fstat`, `sys_fcntl_nocancel`, `dupfdopen`, `fo_read`
  - [`bsd/vfs/kpi_vfs.c`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/vfs/kpi_vfs.c): `VNOP_OPEN`
  - [`bsd/miscfs/specfs/spec_vnops.c`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/miscfs/specfs/spec_vnops.c): `spec_vnodeop_entries`, `spec_open`, `spec_ioctl`
- Existing cached Go surface: **`golang.org/x/sys v0.44.0`**, limited in the bounded study to `unix/zerrors_darwin_arm64.go` and `unix/syscall_darwin.go`. It showed arm64 declarations for `O_EVTONLY`, `Open`, `Openat`, and `Dup`; it did not establish the complete public `Fstat`/generated-stub chain, amd64 parity, or a CGO-free build result.

These pins are reasoning references. XNU `11215.1.10` is not evidence for a future runner's installed kernel, and cached declarations are not build or runtime qualification.

### Conditional opening chain and unresolved branches

1. `open`/`openat` enter `openat_internal → open1at → open1`. `open1` strips `FREAD|FWRITE` only when both `O_EVTONLY` and `proc_disallow_rw_for_o_evtonly(p)` are true. The policy callee was outside the bounded study, so the stripping condition remains **BLOCKED**.
2. `vn_open_auth` may use `VNOP_COMPOUND_OPEN`; a successful compound open suppresses the later ordinary `VNOP_OPEN`. Compound-open implementations and mount-specific availability remain **BLOCKED**. On the traditional branch, `vn_open_auth` calls `vn_authorize_open_existing` before `VNOP_OPEN`; that authorization implementation was outside the bounded study, so absence of a denial is not a complete positive permission chain.
3. On the demonstrated ordinary branch, `VNOP_OPEN` dynamically dispatches a special vnode to `spec_open`. `spec_open` has no `O_EVTONLY` bypass in the pinned body: character and block cases conditionally call their driver's `d_open`, with some successful device opens proceeding to ioctls. `open1` can also conditionally issue `TIOCSCTTY` for a tty unless `O_NOCTTY` or process state prevents it. These are conditional consequences only if the earlier authorization and dispatch conditions permit them; they do not establish universal reachability, universal safety, or impossibility.
4. `fstat` occurs after an fd exists. It therefore cannot retroactively exclude a driver-open side effect. The mapped `spec_getattr` body was outside the study, so its callback behavior also remains **BLOCKED**.
5. `open1` stores a vnode in the fileglob, and `vn_read` later uses that stored vnode and propagates `IO_EVTONLY` to `VNOP_READ`. A same-vnode content transition would still require retained `FREAD` and permission through the generic read-entry path. The process policy and generic read gate remain **BLOCKED**. If `FREAD` was stripped, the inspected `F_SETFL` and dup paths did not restore broader access; a path-based reopen would re-resolve and lose the same-object property. The bounded files do not prove that no other transition exists.
6. The complete Go chain remains **BLOCKED**: `os.Root` containment plus `Lstat/Open` does not establish a stable metadata-only reference, pre-driver regular-file exclusion, or same-object content transition. No new Go API or fallback is proposed here.

## Unresolved safety obligations

A future mechanism must satisfy all of the following together; denying every read is not acceptance.

- **Containment and positive access:** open the selected root once; permit ordinary regular files and qualified single- and multi-component in-root links with cycle detection; return correct bytes and stable object identity without target writes.
- **Negative boundary access:** refuse relative escapes, absolute/outside-root links, link cycles, mount/filesystem boundary violations, and namespace aliases; never read the controlled outside-root canary.
- **Special objects before unsafe opening:** reject FIFO, socket, character/block devices, and other unsupported objects before content I/O or driver-open side effects. No blocking open may be reported as safe rejection. Inert device fixtures still require separate approval; no physical or arbitrary device is implied.
- **Deterministic replacement:** synchronize a regular entry or ancestor changing to an outside-root link, directory, FIFO/socket, or separately approved inert special object between inspection and access. The boundary must hold at access time, and instrumentation must show no prohibited `d_open`/ioctl or outside read. Stress alone is insufficient.
- **Same-vnode content transition:** prove that content is read from the exact vnode/object whose regular type and identity were accepted, without path re-resolution, and identify the authorization/read gates that make the transition possible. Record fd/vnode identity before and after.
- **Live content transition:** truncate, grow, and rewrite an already opened regular file under deterministic synchronization. Reads must remain bounded; identity/metadata disagreement or observed change must produce explicit instability rather than an immutable-snapshot claim.
- **Cancellation and cleanup:** demonstrate cooperative cancellation, stalled read/worker handling, bounded forced termination, parent death, pipe backpressure, and cleanup completion for proven-owned processes. A signal request or timeout is not proof of exit.
- **Process and object identity:** retain pid plus start/handle identity for supervisor and worker; never act by broad process name. Preserve file/volume/vnode identities sufficient to detect replacement and avoid confusing a reused pid or path with the original object.
- **RSS evidence:** sample only supervisor and worker resident usage every 100 ms through the qualified macOS `proc_pidinfo` task-information interface. Verify the ABI, returned structure size, `pti_resident_size` units, API errors, and both process identities; record sampling gaps, overhead, and nonzero controlled allocations. Conservatively sum only the supervisor and worker observations, report trusted harness memory separately, state that shared pages may be counted twice, and do not represent sampling as a hard cap. The per-allocating-process touched-allocation bound, sampled RSS, and harness-observed stop threshold are distinct evidence.
- **Preflight refusal:** if any mandatory opening, sampling, identity, timeout, or policy-required hard-limit mechanism is unavailable, refuse before target access and distinguish unsupported environment from empty/successful investigation.

## Required future native evidence

| Evidence group | Required positive evidence | Required negative or transition evidence |
| --- | --- | --- |
| Opening | Ordinary regular files/directories and qualified in-root links; correct bytes and same accepted object | Outside-root links/canary, cycles, mount boundary, FIFO/socket/special object rejection before side effects |
| Replacement | Stable regular-object identity through accepted access | Deterministic regular→outside-link/directory/special replacement and ancestor replacement; no prohibited read or driver callback |
| Content change | Bounded read from the accepted same vnode | Deterministic truncate/grow/rewrite; explicit instability and before/after identity/metadata evidence |
| Lifecycle | Cooperative cancellation and known clean worker exit | Stall, backpressure, crash, parent death, bounded termination, known leftovers rather than false success |
| Memory | Nonzero controlled supervisor/worker samples with verified ABI/units/identity | Query failure and sampling gaps remain visible; no RSS hard-cap or unique-physical-memory claim |

No designated macOS 15 runner exists, so none of this evidence was executed. Provisioning is unnecessary for this documentation branch.

## Runner metadata and native matrix

Each architecture requires its own native run. Cross-compilation, Rosetta/translation, emulation, or evidence from the other architecture cannot fill a row.

| Environment | Current status | Metadata required before an authorized run |
| --- | --- | --- |
| macOS 15 arm64 | **NOT RUN / BLOCKED** | Designated runner identity/owner/provider; native arm64 hardware and observed architecture; exact macOS version/build and Darwin kernel; match or difference from XNU `xnu-11215.1.10`; filesystem/volume type, mount options and case sensitivity; privileges, sandbox/security state and available APIs; official Go 1.27.1 artifact URL/checksum and observed version; `CGO_ENABLED=0`; `x/sys v0.44.0` module checksum/build provenance; binary digest/settings; fixture identities; independent timeout/recovery; cleanup owner; clock and evidence timestamps |
| macOS 15 amd64 | **NOT RUN / BLOCKED** | The same fields, demonstrated on native amd64 rather than translation; amd64 generated declarations/build provenance must be recorded independently |
| Ubuntu 24.04 amd64 | **NOT RUN** | Unchanged Probe B prerequisite: designated native runner and qualified complete access chain |
| Ubuntu 24.04 arm64 | **NOT RUN** | Unchanged Probe B prerequisite: designated native runner and architecture-specific evidence |
| Windows Server 2022 amd64 | **NOT RUN** | Unchanged Probe B prerequisite: designated runner and qualified namespace/reparse chain |

No row is passed, failed, removed, or narrowed by this report.

## Limits for any separately authorized future native run

These are the existing Probe B bounds, not permission to consume resources now:

| Resource | Bound |
| --- | --- |
| Native test execution per authorized row | 15 minutes, including cleanup attempts |
| Individual test child | 10 seconds; cleanup must also remain inside the row deadline |
| Test child launches / stress repetitions per race | 100 / 50 |
| Concurrent test workers / fixture mutators | 1 / 1, plus the trusted supervisor |
| Synthetic fixture data / entries | 32 MiB / 1,000 |
| Deliberately touched allocation per allocating process | 64 MiB maximum |
| Harness-observed aggregate process stop threshold | 512 MiB; not represented as hard prevention |
| Captured evidence / stderr per child | 32 MiB per row / 64 KiB |
| New build cache per runner | 2 GiB |

The limits apply together; they do not promise that every maximum fits simultaneously. The 64 MiB deliberately touched allocation per allocating process, 100 ms sampled supervisor-plus-worker RSS, and 512 MiB harness-observed aggregate stop threshold are distinct quantities. Harness memory is reported separately. Lower thresholds may exercise stop logic without inducing real exhaustion, and runtime/RSS observations are feasibility measurements rather than the production benchmark. Provisioning and build preparation are separate from the row execution deadline and require separately approved resources.

Stop on outside-root access, observer write, unsafe device open, uncontrolled process, or an absent mandatory safeguard. Retain PASS/FAIL/BLOCKED/NOT RUN separately and do not retry until a desired result while discarding failures.

## Review and CI boundary

This is a documentation-only issue result. Go RED/GREEN, native tests, scanner execution, and device evidence are not applicable and must not be fabricated. Acceptance requires second-person review of the report and link amendment, with exact integrated content and the non-qualification language preserved.

If the coordinator elects to request publication regression evidence, the proposal is limited to **at most three initial jobs already present in the repository's official root CI workflow, at most 15 minutes per job, retaining the same SDK/toolchain and dependency pins already used by those jobs**. If the existing workflow cannot meet that condition, record the check as BLOCKED; do not add or edit jobs. No manual dispatch, rerun, workflow change, security/protection change, dependency upgrade, native job, or runner provisioning is included. The native design baseline remains official Go 1.27.1 with `CGO_ENABLED=0` and the `x/sys v0.44.0` candidate; root CI does not establish that native baseline. Existing root CI can check documentation/link/root regression only; it cannot qualify macOS opening, any native row, the scanner, devices, or #7.

## Acceptance mapping

| Issue #22 acceptance bullet | This delivery |
| --- | --- |
| Document containment, pre-open special-file exclusion, identity/change checks, and relevant source evidence | “Preserved source record” and “Unresolved safety obligations” record the conditional chain and the exact missing proofs without an impossibility claim |
| Identify exact native runner/architecture and positive/negative/race evidence | “Required future native evidence” and “Runner metadata and native matrix” specify both macOS architectures and the required evidence; both remain NOT RUN / BLOCKED |
| Request separate authorization before acquisition, provisioning, prototype creation, or native execution | “Next authorization gate” below preserves a new explicit gate |
| Implementation RED/GREEN/root tests-vet, or documentation review evidence | No implementation exists in this issue; “Review and CI boundary” requires documentary review and forbids fabricated Go/native evidence |
| Record toolchain, provenance, limits, and what remains unqualified | Pins/provenance, runner metadata, limits, matrix, and “What this does not qualify” provide the record |

## Next authorization gate

Before any continuation, the owner must explicitly approve the exact next scope and distinguish at least:

1. Any additional source acquisition or expansion beyond the already recorded pins/files.
2. The proposed mechanism or approved design change, including any new binding, helper, sandbox, special mount, cgo/build change, or dependency effect.
3. Exact macOS 15 runner identity and architecture, provisioning/toolchain artifacts and checksums, filesystem/security state, independent timeout/recovery, and cleanup ownership.
4. Exact case groups and instrumentation, including whether separately reviewed inert special-device or privileged fixtures are allowed.
5. Prototype/native code creation and its isolated path, followed separately by permission to execute it.

Absent that authorization, no acquisition, provisioning, code, native execution, device/mount/security change, or platform claim is permitted. No such action is needed to deliver this reviewed documentary branch.

## What this does not qualify

This report does not provide a credible completed opening mechanism, production implementation, native source/API qualification, designated runner, official build result, macOS arm64/amd64 result, device result, scanner result, memory/termination result, CI enforcement, platform support, or release evidence. It does not close #7 or change the five-row matrix. It records why the mechanism remains unresolved and exactly what evidence and authorization a later attempt would require.
