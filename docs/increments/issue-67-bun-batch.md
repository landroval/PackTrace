# Issue 67: bounded supplied Bun advisory batches

Status: specification and [implementation plan](issue-67-bun-batch-plan.md) proposed
for [issue #67](https://github.com/landroval/PackTrace/issues/67), child of #8, in
Preparation. Proposed primary owner: jsustt, pending agreement. Neither document is
approved and no execution authority is recorded. This is synthetic/local metadata
inspection, not scanner, producer or platform qualification. Authority:
[design decisions](../design-decisions.md).

## Deliverable

Add `inspect-bun-batch [--format terminal|json]`, the Bun counterpart of
[`inspect-batch`](issue-50-inspect-batch.md), reusing the single-advisory
[`inspect-bun`](issue-52-bun-stdin-inspection.md) evaluation. #52 deferred Bun
batches explicitly; this delivers them without changing any existing command.

## Contract

- Stdin is one strict JSON object with exactly `lockfile_text` (a non-empty JSON
  string holding the original text `bun.lock`) and `advisories` (1–16 records).
  Whole-wire validation reuses `jsoninput.Object`, as `ReadBun` and `ReadBatch` do.
- No identity profile: `--identity-profile` in any form is `invalid-arguments`, as
  in `inspect-bun`. Help and invalid arguments do not read stdin.
- Bounds, all fatal before repeated evaluation: 1 MiB wire (read at most 1 MiB + 1),
  16 advisories, the `inspect-bun` lockfile limits (64 package tuples, 64 workspaces),
  64 aggregate `affected` slots including malformed records/members, the existing
  nested OSV budget, and at most 4,096 locked-entry × slot pairs. No truncation.
  The pair bound is kept for parity with `inspect-batch`; within the 64-tuple and
  64-slot caps it cannot be exceeded, so it is never the deciding check.
- Locked entries count projected package records except the `root:` tuple.
- Each advisory keeps its input position and reference `advisory-N`. A usable record
  is evaluated through `ReadBun` with the original `lockfile_text` bytes and that
  record; its nested report reference is rebound to `advisory-N`. An unusable record
  becomes `invalid-advisory` without discarding valid siblings, and marks
  `advisory-records` coverage incomplete.
- Result reuses `BatchResult`/`BatchAdvisory` and `RenderBatch` unchanged, with schema
  `packtrace.inspect.bun-batch.v1` and no `identity_profile`. Nested reports keep the
  existing `packtrace.inspect.bun.v1` portable allowlist. Findings stay empty,
  candidates are not enforcement eligible, applicability is incomplete, installed
  inventory and integrity are not run, usable exit 3, fatal private exit 2.
- Errors use the prefix `inspect-bun-batch:` with the existing codes `read-failed`,
  `limit-exceeded`, `invalid-input`, `invalid-lockfile`, `invalid-arguments`,
  `invalid-format` and `report-failed`.
- Portable output only: no raw names, versions, keys, requirements, IDs, URLs,
  hashes or caller diagnostics.

## Compatibility

`inspect`, `inspect-bun`, `inspect-batch` (both profiles) and all demos keep their
exact stdout, stderr and exit codes. Root help gains one usage line for the new
command; no other default output changes. If the advisory preflight is shared with
`ReadBatchProfile`, the shared helper must keep npm results byte-identical.

## Acceptance and exclusions

Synthetic RED/GREEN tests cover: usable, mixed and all-invalid batches; position and
reference order with duplicate advisories; each reachable fatal bound at its exact
limit and one over, plus the nested OSV budget as fatal (the pair bound is only
tested at its 4,096 maximum, since it cannot be exceeded); wrong wire shapes; profile rejection; both formats; root help; and privacy
of raw lockfile/advisory strings. A differential check compares the existing
commands' outputs on the base commit and on the change. Full root tests and `go vet`
must pass.

No Bun identity profiles, project discovery or disk access, `bun.lockb`, Bun
execution, installed inventory, producer fixtures, new dependencies, network or
publication beyond the issue branch and PR.
