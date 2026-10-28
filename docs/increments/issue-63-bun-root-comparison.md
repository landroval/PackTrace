# Issue 63: compare Bun root declarations

Status: specification and [implementation plan](issue-63-bun-root-comparison-plan.md)
proposed for [issue #63](https://github.com/landroval/PackTrace/issues/63), child of
#5, in Preparation. Proposed primary owner: jsustt, pending agreement. Neither
document is approved and no execution authority is recorded. This is not scanner,
producer or platform qualification. Authority: [design decisions](../design-decisions.md).

## Deliverable and inputs

Compare the [manifest's declared groups](04-manifest-declarations.md) with the
requirements recorded in the root workspace of a `bun.lock`
([Bun workspace declarations](issue-16-bun-workspaces.md)), in memory. Reuse
`ManifestProjection` and `BunWorkspaceProjection`; do not parse again.

The caller supplies unchanged successful projections and explicitly pairs the root
manifest with its chosen `bun.lock`. As in [increment 6](06-root-comparison.md),
this function cannot verify that they belong to the same project, discover files,
select the effective input, authenticate source digests or tolerate concurrent
input mutation. These are internal analysis types, not a public report schema.

Entry point: `CompareBunRootRequirements(manifest ManifestProjection, lock BunWorkspaceProjection) (RootComparison, error)`.

## Result shape and rules

Reuse the increment 6 result types unchanged: `RootComparison`,
`RootGroupComparison`, `RequirementComparison` and the five `Requirement*`
outcomes. No new outcome, field or state.

Every comparison rule of increment 6 applies unchanged, with one substitution: the
locked side is the workspace record whose `Location` is exactly `""`, not the npm
package record at `""`.

1. Compare **only** the root workspace `""`. Other workspaces are not substitutes.
   `ProjectBunWorkspaces` sorts locations, so a present root is the first record.
2. A missing root is an ordinary indeterminate result: both digests retained,
   `RootPresent=false`, `Complete=false`, `Groups=nil`.
3. With a root, return the four groups in their fixed order. Both sides come from
   `projectDependencyGroups`, so names and order already match.
4. Group states, row union, decoded-text equality, indeterminate precedence and
   completeness follow increment 6 rules 4–8 exactly.

**Complete/equal describe this bounded textual comparison only.** They establish
neither valid Bun requirements, semantic equivalence, lockfile freshness, installed
drift, safe packages nor scan coverage.

## Bounds and errors

Keep the producers' bounds: at most 20,000 manifest memberships and 20,000
memberships across all workspaces of the Bun projection, so at most 40,000 rows.
Check each side against its allowance before allocating rows. Nil `Records` is an
invalid zero projection; a non-nil empty slice is a valid projection with no root.
Validate manifest layout even when the root is missing.

Invalid layout returns `invalid-shape`; excess returns `limit-exceeded`. Errors use
`ParseError` and return a zero `RootComparison`.

## Implementation boundary

- New `internal/inventory/bun_root_comparison.go` and its test file.
- In `internal/inventory/root_comparison.go`, move the shared group comparison out
  of `CompareRootRequirements` into an unexported helper used by both entry points.
  The npm function keeps its signature, guards, error order and results; its
  existing tests must pass unchanged.

## Acceptance and exclusions

Synthetic tests cover all outcomes, decoded equality versus text change, missing
root versus empty root, non-root workspace non-substitution, digest retention,
input/output independence, layout guards, the lock-side bound and the 40,000-row
union, plus parity with `CompareRootRequirements` for the same declarations. All
existing root tests and `go vet` must continue passing.

No parser or projection changes, non-root workspaces, workspace attribution, INFO
dependency groups, overrides/catalogs, semantic ranges, installed reads, CLI/report
schemas, network/dependencies, native probes or producer qualification.
