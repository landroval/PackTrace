# Owned macOS clone feasibility probe

Isolated module; no production API, root-module dependency or default-CI coupling.
**Always `not-qualified`; source-object binding always `not-established`.**
Native execution is deferred until owner manual merge and the single authorized
manual workflow run. Do not run against projects, devices or caller-selected data.

## Operations

From this directory, with the **pinned official Go 1.27.1** and verified selected
`golang.org/x/sys v0.44.0` already in isolated caches:

```text
go build -o OWNROOT/maccloneprobe .
OWNROOT/maccloneprobe --evidence-dir OWNPRIVATEEMPTYDIR
```

`OWNROOT` is controller-owned output outside the checkout. `OWNPRIVATEEMPTYDIR`
must already exist, be canonical/absolute (including resolved ancestors), empty,
owned by the current unprivileged UID and mode 0700. It is only an output/fixture
parent, never a source/target selector. CI independently verifies it is outside
**the entire checkout**; the helper additionally rejects descendants of its cwd.
The supplied directory itself is retained, never deleted. No other CLI options
are accepted. `--observer` is private inherited-FD IPC, not a public command; it
rejects invocation without its capability and has no caller-selectable paths.

Use `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off CGO_ENABLED=0 GOENV=off`,
with private `GOCACHE`, `GOMODCACHE`, `TMPDIR` and clean environment. Offline Go
settings are **not** network isolation. Ordinary portable checks are `go test
./...` and `go vet ./...`; a Darwin arm64 cross-build is source verification only.
Portable tests parameterize profile validation, not the actual native guard.

## Envelope and cases

Before any fixture creation, the actual executable requires Darwin, arm64,
macOS 15.x, runtime Go exactly `go1.27.1`, build CGO0, non-root UID, plain private
root and writable local APFS. Official compiler authenticity is established by
CI's pinned archive/hash, **not** by the executable's version string alone.
No fallback backend, source read/hash, hardlink, directory experiment, helper,
privilege operation or mount operation exists.

The trusted harness creates retained directories `fixtures`, `stage`; two
16-byte regular files A/B and the literal `link -> source`. One same-binary
observer uses retained directory FDs 3/4 and a random 32-byte capability through
FD5. Fixed 512-byte frames carry only enum operations, case IDs and fixed-size
observations, never status or qualification. Only the harness mutates sources.
The capability is private launch coordination, **not** a sandbox against a
malicious same-UID process that can replace the executable or forge inherited FDs.

| Case | Controlled observation |
| --- | --- |
| `regular` | A clone bytes equal A, separate inode on same device |
| `cow` | clone A; harness overwrites retained source with B; then hash C as A |
| `direct-link` | ANY=0x8 + NOOWNERCOPY=0x2 refuses link with Darwin ELOOP; no C |
| `selected-link` | one exact owned `source` component selected after bounded readlink; **not a production resolver** |
| `swap` | before sample A; harness substitutes B; clone; post-call path sample B; harness restores A; after sample A, C bytes B |

The header pin for the locally named ANY flag is in `platform_darwin.go`.
ENOTSUP/EXDEV/ENOSYS/EINVAL mean unavailable capability (BLOCKED), not fallback.
Other unexpected API errors fail. All five cases are required; no native retry.

Cumulative ceiling, not per-case: supplied root 1 + directories 2 + originals 2
+ link 1 + at most five destination creations = **11 fixture entries**. Renames
add no inode/entry creation. All literal writes and potential cloned bytes are
at most 150 bytes (including the unexpected link-clone possibility). Reserve
one external receipt entry and 16KiB receipt bytes: **12 entries / 16,534 bytes**
even when counting that evidence against the 16-entry/64KiB envelope. No log or
receipt files are written inside the fixture parent. Compiler/cache/binary and
outer evidence budgets are separate CI-owned preparation/32MiB row budgets.

One observer, one harness mutator, no descendants. Observer active budget 8s,
with 2s reserved for kill/reap (10s total supervision deadline). Retained pipes,
fixed frames, bounded destination read (17 bytes), EOF/trailing-output checks,
64KiB stderr cap (overflow fails) and bounded exec pipe draining avoid unbounded
decoders/output waits. Outer CI independently enforces native-phase 15min and
process-group recovery; there is no hard RSS or kernel-syscall latency claim.

Cleanup unlinks only enumerated, identity/type-checked owned names. Interrupted
C is attributable only after observer reap in the exclusively owned stage.
Unknown types/names/identities are retained as residue; there is no recursive
RemoveAll or deletion of the supplied root/parent. Residue or unconfirmed reap
forces fatal failure, never a success claim.

## Receipt

Normal CLI stdout is exactly one JSON object + LF, at most 16KiB, with fixed
`schema="packtrace.macos-clone-probe.v1"`, `scope="controlled-fixture-feasibility"`,
`qualification="not-qualified"`, `sourceObjectBinding="not-established"`,
`status`, `cases`, `environment`, `cleanup`. Exit PASS=0, FAIL=1, protocol/internal
fatal=2, BLOCKED=3. Fatal receipts have overall FAIL, even if earlier cases passed.
No caller/worker string can set the qualifiers or verdicts.

Each case has `id,status,reason,actualDataEqual,distinctDestination,
cowIndependenceObserved,notOriginalBindingObserved,atomicCOWClaim` and optional
`observation`. Status is PASS/FAIL/BLOCKED/NOT RUN. `atomicCOWClaim` is only
`clonefileat-contract-only` after a regular clone call; data equality/distinctness
and COW independence are separate observations, **not** measurement of atomicity.

Observations contain `errno`, `sourceBefore`, `sourceAtCloneSample`, `sourceAfter`,
`destination`, `bytes`, `sha256Bytes` (32 numeric bytes). Each sample has
`device,inode,ctimeSec,ctimeNsec,nlink,mode,size`. `sourceAtCloneSample` means the
**path sample after the clone syscall**, before the harness is released; it is
not an original-vnode identity token. Zero destination sample means no C exists.
Source/destination IDs, ctime and nlink are samples, **not immutability claims**.
Swap B bytes with surrounding A path samples demonstrate why these statistics
cannot certify original A binding; no original constructor inode is invented.
Only a classified owned regular C is opened/hashed; cloned links are never followed.

Environment reports actual runtime/build profile, kernel, OS build, filesystem,
mount/flags, UID and API flags; unknown case setting is null. It does not invent
sandbox/SIP/security provenance. CI separately records actual compiler/module,
source and binary hashes. `cleanup` contains `clean,workerReaped,residue`.
Portable test workers exercise protocol/control only. **Native Darwin API TDD
execution and all five native case outcomes remain NOT RUN until authorization.**
