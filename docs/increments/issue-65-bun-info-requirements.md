# Issue 65: Bun package INFO requirements

Status: @jsustt's INFO projection is integrated through
[PR #66](https://github.com/landroval/PackTrace/pull/66). The owner accepted its
stricter CLI admission during review; this follow-up records that clarification
and adds CLI boundary regressions before closing
[issue #65](https://github.com/landroval/PackTrace/issues/65), child of #5.
The [plan](issue-65-bun-info-requirements-plan.md) retains the historical author
execution record. This is not scanner, producer or platform qualification.
Authority: [design decisions](../design-decisions.md).

## Deliverable

Extend [typed Bun locked records](13-bun-lock-projection.md) with the dependency
requirements recorded in each tuple's INFO object, reusing the
[increment 5](05-locked-requirements.md) group shape and projection helper. No new
parser, dependency, I/O, resolver or installed graph.

Add `Requirements []DependencyGroup` to `BunLockedRecord`. `ProjectBunLock` remains
the entry point. For admitted inputs, existing fields, including the raw `Info`
copy, kinds, record order and digest, stay unchanged. The new allowance adds the
fatal rejection described below.

## Contract

- A record whose projected `Info` is a JSON object gets exactly four groups in the
  fixed order `dependencies`, `devDependencies`, `optionalDependencies`,
  `peerDependencies`, produced by `projectDependencyGroups`. Group and entry states,
  nil versus empty slices, decoded names and lexical order follow increment 5 exactly.
- A record without INFO evidence has `Requirements == nil`: `BunKindUnknown` records
  and `workspace:` tuples without INFO (lockfile versions 1 and later). Nil means
  "no INFO to read", which is distinct from four absent groups in an empty INFO.
- These are **requirements recorded in a lockfile tuple**, not manifest declarations,
  workspace declarations (#16) or resolved edges. The enclosing record, its key and
  the projection digest define provenance. Locator: source digest + package key +
  group + name.
- Other INFO members (`optionalPeers`, `bin`, `os`, `cpu` and unknown fields) are
  not projected; they remain in the raw `Info` copy and the original document.
- Repeated names across records and groups stay independent. Do not follow
  workspaces/links, infer identities or resolve ranges, aliases or catalogs.
- New slices, entries and strings are independent of later input mutation and of
  other records.

## Bound and errors

Add a **20,000-membership bound across all package records** of one projection,
counting every entry of every object group, including null/invalid requirements and
repeated names. It is separate from the 20,000-record bound and from the workspace
projection's own allowance; no counter resets another.

Exceeding it returns `limit-exceeded` and a zero `BunLockProjection`, including when
a later record exceeds the remaining allowance. No truncation or usable prefix. This
is a new fatal case for `ProjectBunLock`. The owner explicitly accepted its CLI
compatibility effect during review: the 64-package cap does not bound the number
of INFO requirements, and one tuple can exceed this allowance while its wire
input remains below 1 MiB.

`inspect-bun` and `inspect-bun-batch` admit exactly 20,000 INFO memberships but
reject 20,001 before returning a report, even for one package. Their existing
private diagnostics are `inspect-bun: invalid-metadata` and
`inspect-bun-batch: invalid-lockfile`, respectively; both return exit 2 and empty
stdout on overflow. Before this increment the same supplied metadata returned a
partial report with exit 3. This stricter admission is intentional, not a claim
that all previous CLI outputs remain unchanged; the INFO allowance is not relaxed.

## Acceptance and exclusions

Synthetic RED/GREEN tests cover: INFO groups for each kind that carries INFO (npm,
git, GitHub, tarball, folder, link, root, version-0 workspace); all four groups with
value, null, invalid-type and absent states; mixed valid/invalid requirements;
stable ordering; repeated names across records; nil requirements for unknown records
and workspaces without INFO versus four absent groups for an empty INFO; unchanged
existing fields and raw `Info`; input/output independence; and exact 20,000/20,001
memberships spread across several records and groups. Existing Bun, npm and demo
tests and `go vet` must still pass.

No `optionalPeers` or other INFO semantics, dependency edges, range or origin
matching, root comparison changes, overrides/catalogs, installed inventory,
CLI/report schemas, dependency acquisition, native probes or producer qualification.
