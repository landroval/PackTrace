# Increment 10: explicit OSV affected versions

Status: scope selected; written specification awaiting approval. Plan and execution
approval remain separate. Authority: [design decisions](../design-decisions.md).

## Deliverable

Extend the existing [affected projection](09-osv-affected.md), not a second adapter:

```go
type OSVVersions struct {
    State OSVFieldState
    Entries []OSVString
}
// Additional field on OSVAffectedEntry:
Versions OSVVersions
```

Keep `ProjectOSVAffected` and all existing reader/projection signatures unchanged.
Reuse intel's `OSVFieldState`, `OSVString`, and raw type decoder. These are recorded
version strings, not validated concrete versions, constraints to resolve, installed
observations, matching results, or a public schema.

## Evidence and states

- Versions are read from each **affected element**, not its nested package object.
  An object element can expose versions even when package is absent/null/invalid.
  Package field problems must not erase these independent claims.
- A null/non-object affected element leaves Versions unavailable with nil Entries.
- In an object element, missing/null/non-array/array versions yield
  absent/null/invalid-type/value. Non-value lists have nil Entries; valid empty
  arrays have non-nil empty Entries. Neither absence nor emptiness is a no-match.
- Preserve every array position, original order and duplicates, including identical
  strings across different affected entries. Locator: source digest + affected Index
  + `versions` + zero-based position in Entries. Do not sort or deduplicate.
- Each present version string, including empty, yields OSVFieldValue with its exact
  decoded content; null yields OSVFieldNull; every other type yields OSVFieldInvalidType
  with empty content. Members never have absent/unavailable states.
- Do not trim, parse SemVer, normalize prefixes/case, interpret aliases/ranges, infer
  package identity, or reconcile these lists with ranges. Unknown/non-npm records
  remain present. Raw ranges/unknown fields and all existing identity states remain
  unchanged. Original digest and independent input/output ownership remain required.

## Cumulative bound

Add **20,000 version slots across the whole advisory projection**, independent of
its existing 20,000 affected-entry bound. Count null/invalid/duplicate slots, including
those attached to an unusable package. Do not reset the allowance per affected entry.
Missing/null/invalid lists consume no version slots because they are not enumerable;
they still retain their explicit uncertainty states.

Decode a list under the unchanged 4 MiB/depth-128 raw-reader limits, then check its
length against the remaining allowance before allocating output members or
projecting them. This does not prevent raw JSON decoding allocations
or establish a hard RSS bound. A zero remaining allowance still permits later empty
or absent lists.

Any excess, even in a later affected entry, returns existing intel `limit-exceeded`
and a zero OSVAffectedProjection; no truncated/partial projection. The raw document
and raw reader's acceptance remain unchanged. Keep current nil-input/type/error
contracts, copied digest, and unchanged-successful-input/no-concurrent-mutation
preconditions. Controlled errors contain no source data.

## Acceptance and exclusions

Synthetic RED/GREEN tests cover parent/list/member states, lists with mixed usable
and unusable values, exact strings/duplicates/order, source locators and ownership,
versions independent of package usability, wrong-level package.versions ignored,
raw ranges/conflicts unchanged, cumulative 20,000/20,001 slots across records, null/
invalid/duplicate counting, and later empty lists at zero allowance.

Existing affected tests may update their expected structures only for the new field:
object elements with no versions now expose absent lists, and the existing realistic
fixture exposes its already-present versions. Other production behavior/tests remain
unchanged; full root tests/vet must pass.

No range/event interpretation, schema/identity/version qualification, matching,
clock/freshness decisions, network/target access, dependencies, native probes,
SCALIBR changes, CLI/reporting, or platform qualification.
