# Local Linux SCAN finalization checkpoint

This implements only the positively supported local resource portion of B1 in
`public-beta-readiness-plan.md`, not B3 operational completion or B5/B6 acceptance.

`ScanRun.Finish` retains Linux child wait-rusage peaks and queries native
`RUSAGE_SELF` after the existing output attempt, sampling shutdown, owned reap,
and attempted source/output binding checks/closes. The supervisor window ends at
that query, **not its own exit**. Existing live sampling still stops before those
binding closes; this does not extend its sampling window or remove sample gaps.
Skipped closes under uncertain cleanup are not proven successful by the query.

The caller-only `ScanReceipt.Finalization` contains the native supervisor peak
and an overflow-saturating sum of individual supervisor/admitted-child peaks.
For each process, a larger already observed live peak is retained in the sum.
These are not simultaneous RSS, a process-tree peak, a hard runtime ceiling, or
proof of unobserved teardown. Linux KiB conversion treats nonpositive values as
missing and saturates positive unrepresentable values rather than wrapping.
Saturation cannot turn an observed over-budget lower bound into a pass.

States are `observed`, `missing`, `failed`, and `unsupported`; before this
checkpoint the state is empty. `observed` requires a positive native supervisor
peak and, for every actually admitted role (including each sequential worker and
writer), positive wait peak, reap, Wait return, control-exchange join, and stderr
join. Exchange success and exit success are separate facts: cancellation/failure
can still leave valid peak observations. No invented role is required on an
admission failure; the original failure remains authoritative. These fields are
internal caller diagnostics, never input qualification or public report evidence.

Missing metrics/joins on Linux use the existing stale resource failure; native
query errors use query-failed. Positive partial peaks remain available, and a sum
strictly above the unchanged 1-GiB threshold uses the existing resource stopped
failure even if another observation is missing. The final error preserves the
existing `130 > 2 > 3 > 1 > 0` caller adjudication. The first fault is retained,
including a first source-close fault after sampling finished. Repeated Finish
retains the checkpoint/error. Other platforms report unsupported for this new
checkpoint and retain their existing runtime behavior; no zero or measured pass
is inferred. Intel preparation and legacy batch paths do not invoke it.

Public report bytes, schema, reason strings, coverage, native qualification,
thresholds and policy enforcement are unchanged. The separate
[exact-artifact accounting investigation](linux-exact-lifetime-accounting-decision.md)
records why passive external waits cannot recover already-consumed child peaks,
and the explicit operational-output/privacy decision needed before exposing the
existing private receipt. It neither replaces nor weakens B6.

This checkpoint cannot satisfy
the plan's stronger whole-lifetime benchmark contract or establish production
0/1: supervisor exit, exact-artifact native qualification, and complete required
coverage remain outside this local slice.

Tests separate pure boundary/state models, a real owned writer/native query,
source mutation discovered only at Finish, and a late injected over-budget value
AFTER real owned writer join/reap. The latter is a fault-boundary test, not an
actual native memory-budget campaign. Evidence is retained separately under the
owner-selected local state directory; no campaign was run.
