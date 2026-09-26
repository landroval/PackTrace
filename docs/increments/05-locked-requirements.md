# Increment 5: locked dependency requirements

Status: scope selected; written specification awaiting approval. Plan and execution
approval remain separate. Authority: [design decisions](../design-decisions.md).

## Deliverable

Extend [typed locked records](03-npm-locked-records.md) with their recorded dependency
requirements, reusing the [manifest group's](04-manifest-declarations.md) value shape
and projection logic. No new parser, dependency, I/O, resolver, or installed graph.

Add `Requirements []DependencyGroup` to `LockedRecord`. Keep existing internal
function signatures, fields, state definitions, and controlled error prefix unchanged.
`ProjectNPMLock` remains the entry point; no separate projection/adapter is needed.

## Contract

- Each lockfile record has four requirements groups in the existing fixed order:
  `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`.
  Apply exactly the manifest projection's absence/null/object/invalid-type states,
  requirement typing, nil versus empty slices, decoded-key preservation, and
  lexical entry ordering. Invalid fields/groups do not erase usable siblings.
- These are **requirements recorded in a lockfile entry**, not current manifest
  declarations or resolved dependency edges. Sharing `DependencyGroup` and
  `DeclaredDependency` as value shapes does not merge evidence classes: the
  enclosing `LockedRecord`, its location, and projection source digest define
  provenance. Evidence locator: source digest + record location + group + name.
- Preserve repeated names independently across records and groups, including root,
  workspace, link, and nested package entries. Do not follow links, infer identities,
  apply group precedence, or resolve ranges/aliases/non-registry strings.
- Do not project the top-level legacy `Document.Fields["dependencies"]` into these
  groups, merge it, or use it to fill absent entry fields. Unknown fields, peer
  metadata, and legacy conflicts stay in the unchanged raw document.
- Existing scalar fields, record order, digests, ownership, empty-input behavior,
  nil guards, and the 20,000-record bound remain intact. New group slices, entries,
  and strings are independent of later input mutation and of other records.

## Additional bound and shared implementation

Add a **20,000-membership bound across the entire lockfile projection**, not per
record or group. Count every entry in an object group, including null/wrong-type
requirements and repeated names. This is separate from the existing record bound
and the manifest's own 20,000-membership bound; none resets another's counter.

Exceeding either lockfile projection bound returns `limit-exceeded` and a zero
`NPMLockProjection`, including when a later record/group exceeds the allowance.
No silent truncation or usable prefix. Raw parsing behavior and the original
`Document` remain unchanged/available.

Factor the current group projection into one private helper accepting a remaining
membership allowance and returning groups plus the number consumed. The manifest
passes its full allowance; the lockfile passes its remaining whole-document allowance
to each record. Decode raw group objects under the existing input-byte bounds, then
check counts before sorting/allocating their output entries. This bound is not a
hard memory guarantee or prevention of allocations during JSON decoding.

## Acceptance and exclusions

Require synthetic RED/GREEN and root tests/vet for npm v2/v3: all four groups and
states; mixed valid/invalid requirements; stable ordering; repeated names across
records/groups; root/workspace/link entries without resolution; raw legacy conflicts
and unknown data unchanged; independent ownership; empty/nil inputs; and exact
20,000/20,001 memberships distributed across multiple records and groups, including
null/invalid memberships. Existing manifest and lockfile regressions must still pass.

No target discovery, manifest/lockfile comparison, semantic range or origin matching,
resolved edges, installed inventory, CLI/reporting, dependency acquisition, native
probe, SCALIBR change, or producer/native qualification. Native runner availability
does not block this in-memory increment; it still gates later native mechanisms.
