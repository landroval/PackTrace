# Linux exact-artifact lifetime accounting: decision required

Status: **optional private Linux channel implemented after explicit fresh owner
grant**. This is operational evidence, not a new qualification mechanism.
The investigation below records the historical blocker at immutable
`40d92ec594c7e73bcfb24dc40e85ed82b7bd102c`.

## Approved narrow channel

The real CLI accepts `scan --private-lifetime-fd=N ...` only by explicit argument
**immediately after `scan`, before every public option or operand**, never by
environment discovery. This deliberately narrow prefix is not a public parser
option: tokens after `--`, used as ordinary option values, after the first operand,
or even after another public option are passed unchanged to the public parser
and never authorize descriptor probing, modification, writes or close. Any
subsequent occurrence follows ordinary public parsing (an actual unknown option
is rejected); it is not a second opt-in. The retained external runner already
inserts the prefix in this position. N is a canonical decimal descriptor from 3 through
1048576. The external owner must supply an exclusively owned, already nonblocking,
write-only **anonymous Linux pipe**. Validation requires S_IFIFO and pipefs
(PIPEFS_MAGIC), not just S_IFIFO: named filesystem FIFOs are intentionally rejected,
as are regular files, terminals, sockets, read/read-write endpoints, closed FDs,
and device/inode aliases of any stdio descriptor. No path is opened or written,
no `/proc` discovery occurs, and shared open-description status flags are not
changed. The descriptor is marked close-on-exec, is never placed in worker
ExtraFiles/arguments/environments, and is closed by the supervisor after use.
The caller must not concurrently replace it, change its flags, or share its use.
Other platforms reject the opt-in; Intel/legacy paths cannot activate it.

The existing `runMainObserved` hook captures exactly one post-Finish receipt.
After caller exit adjudication, one atomic nonblocking write emits at most 4096
bytes (Linux PIPE_BUF), including its newline, with no retry or blocking fallback.
There are at most 16 actual admitted role entries; these are a transport cap,
not a universal launch bound. Overflow, absent observer, encoding/transport
failure, EAGAIN, EPIPE, short write, or unsupported endpoint fails closed with
exit 2; an already selected cancellation remains 130. Invalid endpoints use the
existing CLI argument diagnostic. Post-Finish transport failure performs no
further diagnostic I/O, since an inherited stderr might itself be blocked.
Earlier failure/incompleteness cannot become success. No receipt is promised
when argument validation prevents a scan from starting. A pipe accepting bytes
is not acknowledgment that its reader retained or validated them.

The version-1 JSON projection has fixed keys, fixed role names `scan` and
`scan-writer`, native wait and sampled peaks, sample counters and maximum sampling
gap, actual Wait/reap/control-exchange/stderr joins, exchange success and child
exit, cleanup/Finish and finalization states, resource-failure booleans, bounded
context labels, the first fault's bounded stage/code/role, and selected CLI exit.
Unknown diagnostic labels become `other`; unknown roles fail serialization.
There are no PIDs, absolute timestamps, target/package/store/key identities,
paths, policy data, errno details, or raw errors. A zero/missing peak or failed
join is retained as missing evidence, never a measured zero/pass. The transport
does not replace the first fault with a later output error.

The owner must validate one complete bounded record (including duplicate-key and
record rejection), bind it to its launch/executable hash and provenance, check
actual fixture-specific role order/completeness and joins, then use its own real
supervisor wait4 status and rusage **after exit**. Do not substitute the receipt's
predicted status, internal self query, RUSAGE_CHILDREN, or a test executable.
Add the positive per-child native wait peaks to the positive supervisor wait
peak with explicit missing/overflow rejection. This metric is the conservative
Linux wait high-water sum, which may include descendant maxima, **not own-only,
simultaneous RSS, a hard ceiling, or B6 acceptance**. Failed operational cases
have no successful aggregate measurement. Public resident/native coverage remains
incomplete; private parsing grants no authority or qualification.

Reproducible external runner, negative parser oracles, exact-artifact controls,
actual numbers, and source/build/test provenance are retained in the unique owned
local directory:

`/home/justcharles/.local/state/packtrace/advisory-completeness-RIKjKdJf/scale-fix/private-lifetime-5OA2OgXC`

`runner.py SOURCE BINARY FIXTURE OUTPUT` uses an owned session, a 120-second
watchdog, finite captures, actual wait4 ownership, and the two authored npm
fixtures' launch contract (two sequential scan roles, then one stdout writer).
It runs opt-out/opt-in and broken/blocked controls, preserves public coverage,
and checks freshness rather than silently renewing source dates. Its
`--selftest` rejects absent, truncated, duplicate, oversized, missing/zero/overflow
metrics, missing/failed joins, cancellation, first/final faults, changed roles,
and outer exit mismatch. The retained source generators may be used offline
in a **new owned directory** if the original fixtures have aged; no real
acquisition or new keys are necessary. Existing owned tests also cover late
source-close/finalization faults and cancellation precedence. Fault-injected
threshold tests remain fault tests, not actual memory-budget campaigns.

No public schema, coverage predicate, authority, install path, runtime threshold,
worker/wait ownership, or campaign budget changes. The rest of this document
is historical investigation and must not be read as undoing this narrow grant.

No production flags, environment hooks, observers, dependencies or behavior were
added. No ptrace, interception, privileges, taskstats subscription, host/security
changes, native campaign, performance run or deployment acceptance was used.
The existing B1 resource/execution obligation and B6 external benchmark gate
remain separate and unchanged.

## Existing useful evidence, not a missing implementation

- `cmd/packtrace/scan.go`: `runScanContextObserved` invokes the caller's private
  observer after `Finish` and final exit selection. Ordinary `runMain` supplies
  no observer. Production does not export the operational receipt.
- `internal/execution/scan_lifecycle.go`: the caller retains actual admitted-role
  receipts, waits, control/stderr joins and cleanup state. `ScanRun.finish` first
  stops/joins sampling and reaps owned roles, then attempts file-output,
  Bun-cache, intelligence and setup checks/closes when cleanup is certain.
- `internal/execution/scan_finalization.go` and `wait_peak_linux.go`: finalization
  retains native child wait peaks and queries supervisor `RUSAGE_SELF` after
  those attempted closes. The sum uses the larger of native and sampled peaks,
  with saturating addition. It ends at that query, **not supervisor exit**.
  Missing/failed observations and over-budget lower bounds fail closed.
- `cmd/packtrace/lifetime_receipt_linux_test.go` already combines the outer
  owner's actual supervisor wait result with the private post-Finish child
  receipts. Its owned fixture checks two sequential `scan` children and one
  `scan-writer`, including wait/reap and exchange/stderr joins. It runs a Go
  **test executable**, not the exact release-mode executable. Do not duplicate
  it or label its result exact-release evidence.
- `probes/offline-integrity/ci/linux_validation.py` reuses
  `probes/native-safety/ci/run.py`'s bounded process-group watchdog. It explicitly
  records aggregate peak RSS as not independently measured. It has no concealed
  per-role accounting source to reuse.

See [the implemented local checkpoint](linux-scan-finalization-checkpoint.md)
and [B1/B6](public-beta-readiness-plan.md). The new investigation does not remove
any of their limitations.

## Why a passive external exact sum is unavailable here

The external owner can wait for the real CLI and collect its kernel wait-rusage.
It cannot wait for workers which the CLI itself already waited for. Child wait
results are consumed by their actual parent; making an external monitor a
subreaper does not reroute waits of normally parented children. Orphans and
unreaped exceptional paths would not prove successful normal accounting.

`RUSAGE_CHILDREN` and Linux wait `ru_maxrss` propagate maxima, not an additive
ledger of each process's peak. Different worker peak lists can yield the same
returned maximum. Consequently an outer wait does not reconstruct their sum.
The current test correctly labels its wait-based sum conservative, not exact
own-only per-process accounting: a parent's wait peak can include a waited
descendant's larger high-water mark. This must be settled in the B6 measurement
contract too, rather than silently calling the value own-only RSS.

Polling `/proc` can miss short-lived roles and their terminal peaks; removed
entries do not become zero. Unprivileged per-PID taskstats queries do not supply
an external historical ledger of already reaped children, and privileged exit
notification subscription is outside this authorization. No taskstats probe was
attempted. ptrace fork/clone/vfork tracking could change the observability
boundary, but is explicitly forbidden, and was not attempted.

For a proven bound of N processes, N times a suitable maximum could be a
conservative mathematical upper bound. Neither a successful-path test's three
children nor a supervisor-only sample establishes that bound for every path.
Even a correctly proven bound is **not the agreed sum gate**. No bound-based pass
or replacement runner is supplied.

A tagged candidate observer could expose the existing caller receipt without
changing ordinary behavior, but its executable/hash, supervisor lifetime and
allocation/output work would differ. Equal public reports and exits do not
transfer memory measurements to the unmodified artifact. Here it would mainly
repeat the existing three-child private harness, not resolve exact-artifact
validation. No shadow candidate infrastructure is added.

## Narrow recommendation to the principal — not an approved API

Approve or reject **one opt-in caller-owned operational receipt channel in the
real production CLI**, before implementation. Prefer an explicitly selected,
parent-inherited dedicated descriptor/pipe, not an environment activation hook,
stdout/stderr scraping, target-controlled path or public comparison-report field.
This is a user-visible invocation/privacy decision even if the receipt remains
nonpublic and non-authoritative. It changes the executable, so requires a new
frozen artifact; it cannot retroactively qualify `40d92ec5`'s binary.

If approved, constrain the implementation to the existing `runMainObserved`
caller hook and a bounded receipt transport, not a new supervisor framework:

1. The external parent supplies the sink and owns its draining, deadline and
   capture limits. Specify descriptor validation, broken/blocked sink handling,
   finite byte/role caps and final exit precedence before coding. A receipt
   failure must not convert an operational failure into success. Do not inherit
   the observer sink into unrelated children as an additional capability.
2. Emit once, after `Finish` and caller adjudication, including every actually
   admitted child role's native wait peak, Wait/reap and join outcomes, cleanup,
   sampling gaps, first fault and selected final status. Restrict the projection
   to fixed roles, counters, booleans and bounded fault codes. Exclude target,
   package, source/store/key identities, paths, policy content and raw errors;
   decide whether PIDs/timings are necessary before exposing them.
3. The external parent binds captured bytes to its launch, exact executable hash
   and provenance, then performs the real supervisor wait. Its actual exit and
   native wait-rusage, **not the receipt's predicted status or self query**, close
   the lifetime window. Receipt parsing never grants qualification or authority.
4. Freeze the accepted metric: conservative per-role Linux wait high-water
   values (possibly including descendant maxima) versus own-only peaks. Existing
   waits support the former; promising the latter would require additional
   approved measurement. Validate role completeness against the actual launch
   contract, not merely a fixed count copied from the successful fixture.
5. Test absent/truncated/duplicate/oversized receipts, blocked/broken output,
   missing/zero metrics, partial admission, every actual role, late source-close
   failure, cancellation, writer failure, finalization failure and outer exit
   mismatch. Keep `130 > 2 > 3 > 1 > 0`, finite cleanup and first-fault retention.

This enables a subsequent small owned paired validation of the **new** exact
production artifact. It grants no performance/native campaign budget and does
not itself satisfy B6.

## Conditional B1 completion is not permission to weaken a row

The implemented finalization checkpoint already positively accounts for its
stated local observation window. It does not positively establish every source
close when cleanup is uncertain, or observe the supervisor's own exit.

The public comparison snapshot is constructed before output/Finish. Its
`resident-observation` row explicitly remains incomplete, with later lifecycle
work pending in the caller. Marking that row completed because a private future
receipt is expected would be false. Relabeling it a narrower sampling-only row
would change the required contract, not close it. This change does neither.

A future design can keep the immutable comparison row and separately expose
final operational evidence through the approved channel above. If instead a
public completion row is desired, explicitly approve the schema, predicate,
ordering and backward compatibility first; never recursively render another
report to pretend the first snapshot observed future output/reap.

## Local verification and exact-binary corroboration

Owned evidence directory:

`/home/justcharles/.local/state/packtrace/advisory-completeness-RIKjKdJf/scale-fix/lifetime-decision-Qpa2Bog4`

Before editing, the workspace had an empty jj child over the frozen baseline.
`source-before.txt` records the Git tree, jj state and kernel. CodeGraph reported
no index for this workspace; no index was created. Direct source inspection was
used instead.

`before.log` runs the existing lifetime, finalization and native exit-race tests
uncached. The private test reported supervisor wait **21,635,072 bytes** and
conservative sum **74,264,576 bytes** across supervisor and three children. These
are test-executable observations, **not production or benchmark measurements**.
The late-over-budget tests inject values; they are not actual memory campaigns.

`packtrace` was built from the unchanged clean frozen workspace with the existing
offline Go wrapper. `binary.txt` records Go 1.27.1, linux/amd64,
`vcs.revision=40d92ec594c7e73bcfb24dc40e85ed82b7bd102c`, `vcs.modified=false`, and
SHA-256 `036c6205dd8bcaa859004b31eb1e36e0bc5e107c89f265a9b5b0155b2789c0ea`.
This is an actual newly built baseline binary, not the older documentation-only
source-equivalent executable from prior evidence.

`replay.py` uses the existing bounded watchdog (120 seconds per case, 4 MiB total
capture) for two small owned npm CLI corroborations. It reuses the original
`fresh-exact-ceOi6owo` fixtures at their original paths; no copied store,
renewed timestamps, new keys, real acquisition or fixture regeneration.
`paired.json` records exact argv, binary/input hashes, exits, capture/cleanup
outcomes and coverage. Unaffected/affected have **0/2 advisory findings** and
**0/2 enforced unaccepted findings**, respectively; both actually exit **3**.
Both selected advisory rows and freshness remain completed in these runs;
resident observation and native qualification remain incomplete. This is **not
external lifetime validation** and collects no surrogate sum.

The first replay assertion incorrectly checked the top-level integrity finding
count instead of `advisories.findings`; `paired-attempt1.log` retains that harness
error. It was corrected in the evidence script, not in production. Successful
replay assertions check both advisory and policy counts.

`after.log`, `diff.txt`, `evidence.sha256` and `final-source.txt` retain post-edit
checks and the final frozen jj commit. The only versioned changes are this
contract/decision record and its checkpoint cross-reference. No qualification,
coverage, schema, runtime threshold or exit behavior was changed.

Reproduce from Nushell or Bash without loading shell configuration:

```text
bash /home/justcharles/.local/state/packtrace/advisory-completeness-RIKjKdJf/scale-fix/go.sh test ./cmd/packtrace ./internal/execution ./internal/nativeresource -run 'TestScanLifetimeWaitSumOwnedLinux|TestScanFinalPeak|TestSampleDuringOwnedChildExitDoesNotInventLiveQueryFailure' -count=1 -v
python3 -B /home/justcharles/.local/state/packtrace/advisory-completeness-RIKjKdJf/scale-fix/lifetime-decision-Qpa2Bog4/replay.py
```

The replay uses the retained exact baseline binary. Freshness naturally ages;
a later replay must report that change, not rewrite the source dates. Rebuilding
that binary requires the clean frozen baseline and recorded offline Go wrapper,
not the later documentation commit. Logs are local evidence, not portable native
acceptance receipts.
