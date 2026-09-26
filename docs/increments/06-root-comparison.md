# Increment 6: compare root declarations

Status: scope selected; written specification awaiting approval. Plan and execution
approval remain separate. Authority: [design decisions](../design-decisions.md).

## Deliverable and inputs

Compare the [manifest's declared groups](04-manifest-declarations.md) with the
[requirements recorded in the npm lockfile root](05-locked-requirements.md), in
memory. Reuse `ManifestProjection` and `NPMLockProjection`; do not parse again.

The caller supplies unchanged successful projections and explicitly pairs the root
manifest with its chosen lockfile. This function cannot verify that they belong to
the same project, discover files, select the effective lockfile, authenticate
source digests, or tolerate concurrent input mutation. These are internal analysis
types, not a public report schema.

Proposed entry point: `CompareRootRequirements(manifest ManifestProjection, lock NPMLockProjection) (RootComparison, error)`.

## Result shape

- `RootComparison`: `ManifestSHA256`, `LockSHA256` (copied `[32]byte` values),
  `RootPresent`, `Complete` (booleans), and `Groups []RootGroupComparison`.
- `RootGroupComparison`: `Name`, `ManifestState`, `LockState`, `Complete`, and
  `Entries []RequirementComparison`. Source states use existing `FieldState`.
- `RequirementComparison`: exact decoded `Name`, `Manifest` and `Locked` values
  using existing `LockField[string]`, and a typed `RequirementOutcome`.
- Outcomes: `equal`, `manifest-only`, `lock-only`, `text-changed`, `indeterminate`.
  Define corresponding constants prefixed `Requirement`.

The enclosing side preserves evidence class despite reuse of the scalar value
shape. Locator: corresponding source digest + manifest group/name, or lockfile
location `""` + group/name. Input data is unchanged; returned structures do not
alias mutable input slices/entries. Source strings are not normalized or interpreted.

## Comparison rules

1. Compare **only** the exact root location `""`. Other records, including workspaces
   and links, are not substitutes or graph destinations. Successful lock projections
   are sorted, so a present root is the first record.
2. A missing root is an ordinary indeterminate result, not an invocation error:
   both digests retained, `RootPresent=false`, `Complete=false`, `Groups=nil`.
   Do not fabricate absent lockfile groups or manifest-only requirements.
3. With a root, return exactly the four existing groups in their fixed order. Keep
   both source group states. Absent groups are enumerable as zero recorded members;
   valid empty objects are also enumerable, but their source states remain distinct.
4. A null or invalid-type group on either side prevents comparison of that group:
   `Complete=false`, `Entries=nil`. Do not infer membership absence from unusable
   data. Continue comparing other groups.
5. For enumerable groups, return one row per name in their sorted, case-sensitive
   union. Never merge across groups. Rows retain both requirement states and values;
   a missing member has `FieldAbsent` with an empty value. A valid string, including
   an empty string, retains `FieldValue`.
6. If either present requirement is null or invalid-type, the row is `indeterminate`
   and that group is incomplete. This takes precedence over presence-only outcomes.
   Other usable rows in the same group remain available.
7. Otherwise, a member absent from the lock root is `manifest-only`, one absent
   from the manifest is `lock-only`, two exactly equal decoded strings are `equal`,
   and different strings are `text-changed`. This is not byte-for-byte JSON equality:
   equivalent JSON escapes decode to the same text. No trimming or range equivalence.
8. Enumerable groups have non-nil entries, including an empty slice when both are
   empty. Their `Complete` is true only when every row is determinate. Overall
   `Complete` requires a present root and four complete groups.

**Complete/equal describe this bounded textual comparison only.** They establish
neither valid npm requirements, semantic equivalence/incompatibility, lockfile
freshness/correctness, installed drift, safe packages, nor scan coverage. Differences
are not vulnerability/malicious/integrity findings and have no enforcement effect.

## Bounds and errors

Keep the producers' bounds: at most 20,000 manifest memberships and 20,000 locked
memberships across the whole lock projection. Thus the root comparison can contain
at most **40,000 rows** across all groups, including equal/indeterminate rows.

Before allocating comparison rows, check each compared side's membership total
against its existing allowance. Do not reset it per group. Check group layout:
exactly four expected names/order; nil lock records are an invalid zero projection
(a non-nil empty records slice is a valid projection with no root). Validate manifest
layout even if the root is missing; validate root groups only when a root exists.
These guards do not revalidate forged projections, sort inputs, or authenticate them.

Invalid basic layout returns existing `invalid-shape`; excess returns
`limit-exceeded`. Errors use `ParseError` and return a zero `RootComparison`, not a
prefix. A missing root, unusable group, or unusable requirement is represented in
result state, not promoted to an error or silently converted to empty data.

## Acceptance and exclusions

Synthetic tests cover v2/v3 sources, all outcomes, decoded string equality versus
text change, exact names/order, all four groups, absent versus empty, null/invalid
groups and requirements, mixed determinate/indeterminate rows, missing root versus
empty root, workspace/link non-substitution, source digest retention, input/output
independence, zero/layout guards, cumulative side bounds, and the 40,000-row union.
All existing root tests/vet must continue passing.

No parser changes, discovery, root/workspace inference, semantic resolver, installed
reads, advisory matching, CLI/report schemas, network/dependencies, native probes,
SCALIBR work, or producer/native qualification. Plan and implementation remain gated
on their own explicit approval after this specification.
