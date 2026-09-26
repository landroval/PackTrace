# Root requirement comparison implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:executing-plans`
> for approved inline execution. The user approved this plan and explicitly authorized
> inline implementation, offline verification, and scoped code/docs commits.

**Goal:** compare recorded root requirements without claiming semantic or installed differences.
**Architecture:** consume existing successful projections, guard their basic group
layout/budgets, then merge their sorted memberships within each group. Preserve
both source digests, source states, usable results, and explicit incompleteness.
**Tech stack:** current Go module and standard library only.
**Spec:** [approved root-comparison contract](06-root-comparison.md).

## Global constraints

- Root location is exactly `""`; missing root is indeterminate, not an empty root.
- Four groups stay separate and in their existing order; exact decoded names/text.
- Side limits remain 20,000 memberships each; output has at most 40,000 union rows.
- No new parser, range semantics, I/O, dependencies, native probes, or public schema.
- Invalid layout/excess produces a controlled error and zero result; unusable source
  values produce incomplete results without erasing other usable comparisons.
- Inline execution/review in current jj workspace, scoped commits, exclude task ledgers.

## Review focus

1. An empty string requirement is a value, not absence; escaped equivalent strings compare equal.
2. Missing root must not manufacture manifest-only rows, even with workspace/link records.
3. Null/invalid values take precedence over one-sided outcomes; valid siblings survive.
4. Absent versus empty groups retain different source states, despite both enumerating zero entries.
5. Cumulative side limits must hold across groups; disjoint maxima require 40,000 rows without truncation.

## Task 1: implement the internal root comparator

**Create:** `internal/inventory/root_comparison.go` and `root_comparison_test.go`.
**Consumes:** `ManifestProjection`, `NPMLockProjection`, `DependencyGroup`,
`DeclaredDependency`, `LockField[string]`, `FieldState`, existing limits/errors.
**Produces:**

```go
type RequirementOutcome string
const (
    RequirementEqual RequirementOutcome = "equal"
    RequirementManifestOnly RequirementOutcome = "manifest-only"
    RequirementLockOnly RequirementOutcome = "lock-only"
    RequirementTextChanged RequirementOutcome = "text-changed"
    RequirementIndeterminate RequirementOutcome = "indeterminate"
)
type RequirementComparison struct {
    Name string
    Manifest, Locked LockField[string]
    Outcome RequirementOutcome
}
type RootGroupComparison struct {
    Name string
    ManifestState, LockState FieldState
    Complete bool
    Entries []RequirementComparison
}
type RootComparison struct {
    ManifestSHA256, LockSHA256 [32]byte
    RootPresent, Complete bool
    Groups []RootGroupComparison
}
func CompareRootRequirements(manifest ManifestProjection, lock NPMLockProjection) (RootComparison, error)
```

- [x] Write table tests from real parser/projector outputs. Start with this assertion
  after projecting a manifest `{"dependencies":{"p":"1.x"}}` and a v3 lockfile
  `{"lockfileVersion":3,"packages":{"":{"dependencies":{"p":">=1 <2"}}}}`:

```go
got, err := CompareRootRequirements(manifest, lock)
if err != nil || !got.RootPresent || !got.Complete || len(got.Groups) != 4 {
    t.Fatal("comparison unavailable", err)
}
rows := got.Groups[0].Entries
if len(rows) != 1 || rows[0].Outcome != RequirementTextChanged ||
    rows[0].Manifest.Value != "1.x" || rows[0].Locked.Value != ">=1 <2" {
    t.Fatal("text difference lost or semantically interpreted")
}
```

  Cover both lockfile versions and all five outcomes, exact names including empty/
  case-sensitive names, decoded escapes, whitespace, aliases, repeated names across
  groups, empty string values, all group states and requirement states, mixed usable
  and indeterminate siblings, missing/empty root, unrelated workspace/link records,
  digest binding and immutable input/output. Use full expected structures where
  nil/empty distinctions matter. Check all groups, not only dependencies.
- [x] Test nil records, wrong group count/name/order, and invalid manifest layout
  even without a lock root. Construct defensive oversized projection inputs for
  20,001 memberships on either side, spread across groups; require zero results and
  sanitized `invalid-shape`/`limit-exceeded` errors. Valid 20,000-member projections
  on each side with disjoint names must yield all 40,000 sorted rows.
- [x] Run new tests before implementation. Observe the missing API failure, then
  introduce only types/constants and a zero-result stub; rerun for behavioral RED.
- [x] Implement group-layout/budget guard: exactly the four canonical names in order;
  before any output-row allocation, reject `len(group.Entries) > remaining`, then
  subtract it. Manifest receives `maxManifestDeclarations`, root receives
  `maxLockedRequirements`. Nil lock records reject, but non-nil empty records do not.
  Validate manifest first; copy digests; if the sorted first record is not root or
  there are no records, return the incomplete root-absent result with nil groups.
- [x] With a root, validate its groups, then allocate four result groups. Copy names
  and both group states. A state is comparable only when absent or value. Unusable
  groups leave nil entries and mark overall incompleteness. For comparable groups,
  allocate non-nil entries with capacity at most the sum of both input lengths;
  advance two indices over the sorted arrays, taking the smaller next name and
  consuming both entries on a tie. Copy each present side's state/requirement into
  `LockField[string]`; leave a missing side at its absent zero value. Classify rows:

```go
switch {
case !comparableState(row.Manifest.State) || !comparableState(row.Locked.State):
    row.Outcome = RequirementIndeterminate
    group.Complete, result.Complete = false, false
case row.Manifest.State == FieldAbsent:
    row.Outcome = RequirementLockOnly
case row.Locked.State == FieldAbsent:
    row.Outcome = RequirementManifestOnly
case row.Manifest.Value == row.Locked.Value:
    row.Outcome = RequirementEqual
default:
    row.Outcome = RequirementTextChanged
}
```

  `comparableState` returns `state == FieldAbsent || state == FieldValue`; use it
  for group and member states. Initialize overall/group completeness to true only
  after establishing root presence/enumerability. Never reuse mutable input slices.
- [x] Format both files; run focused tests, all root tests and vet; review against
  all specification rules and five review-focus cases. Rerun full verification after
  review. Confirm old Go files/module/probes unchanged; review is inline, not independent.
- [x] Commit only the two new Go files, then record actual results and an appropriately
  scoped nested milestone in a separate docs commit. Close the task ledger.

## Verification and scoped commit (Nushell)

```nu
gofmt -w internal/inventory/root_comparison.go internal/inventory/root_comparison_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 -run TestCompareRoot ./internal/inventory
    go test -count=1 ./...
    go vet ./...
}
jj commit -m "feat: compare root dependency requirements" internal/inventory/root_comparison.go internal/inventory/root_comparison_test.go
```

Each verification command must pass before committing. No platform qualification,
matching, installed-inventory, or scanner completion follows from synthetic success.

## Execution evidence

- RED: absent API/types first prevented compilation. With only the types/constants
  and a zero-result stub, all 110 new tests/subtests failed at runtime before behavior
  was implemented. No existing source or test files were modified.
- GREEN: 110 comparison tests/subtests and 297 full root tests/subtests passed;
  root `go vet` passed. Full tests/vet rerun after inline review. Module listing:
  only `packtrace`; development toolchain `go1.27.1-X:nodwarf5 linux/amd64`.
- Review checked root absence versus emptiness, group/member indeterminacy before
  absence outcomes, retained positive siblings, sorted union/ties/exhausted sides,
  basic layout guards, cumulative limits before allocation, copied digests and
  output independence. Review was inline, not independent.
- Exact bound verified through successful producer outputs: 20,000 memberships per
  side yield 40,000 disjoint union rows across groups. Defensive oversize projections
  on either side produce zero results and controlled errors.
- Code commit `8d5c8077` contains only `root_comparison.go` (122 lines) and
  `root_comparison_test.go` (286 lines). No downloads, new dependencies, native
  probes, investigated-project reads, reader/projector changes, or qualification.
