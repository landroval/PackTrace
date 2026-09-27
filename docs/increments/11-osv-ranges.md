# Increment 11: OSV ranges and events

Status: specification (complete event fields and combined 20,000-unit budget) and
[plan](11-osv-ranges-plan.md) approved; inline execution explicitly authorized and
completed. Code `63a06daa`; 553 root tests/subtests and vet pass.
Authority: [design decisions](../design-decisions.md).

## Deliverable

Extend the existing [affected/version projection](10-osv-versions.md) with recorded
range and event evidence. Do not add another reader or change ProjectOSVAffected's
signature. New internal types:

```go
type OSVRanges struct {
    State OSVFieldState
    Entries []OSVRange
}
type OSVRange struct {
    Index int
    State OSVFieldState
    Type, Repo OSVString
    Events OSVEvents
}
type OSVEvents struct {
    State OSVFieldState
    Entries []OSVEvent
}
type OSVEvent struct {
    Index int
    State OSVFieldState
    Fields []OSVEventField
}
type OSVEventField struct {
    Name string
    Value OSVString
}
// Additional field on OSVAffectedEntry:
Ranges OSVRanges
```

Reuse OSVFieldState/OSVString and the raw type decoder. No public report/IPC schema.

## Evidence and states

- `ranges` belongs to the affected object independently of package, versions, or
  temporal usability. An unusable affected element leaves Ranges unavailable.
- Within an object, missing/null/non-array/array ranges yield absent/null/invalid-type/
  value. Non-value lists have nil Entries; valid empty arrays have non-nil empty Entries.
- Preserve each range's zero-based Index, original array order and duplicates. Null
  or non-object ranges retain null/invalid-type state and leave Type, Repo and Events
  unavailable. Object ranges expose `type`/`repo` through the existing string states.
- In an object range, project `events` independently of type/repo validity. Its list
  states and nil/empty rules match ranges. Preserve all event positions and duplicates.
- A null/non-object event has null/invalid-type state and nil Fields. An object event
  has value state and one field per exact decoded key, sorted lexically for deterministic
  object-field output; an empty event object has non-nil empty Fields.
- Preserve **every event field**, including introduced/fixed/last_affected/limit,
  unknown names, empty names, and multiple apparently contradictory bounds. Do not
  select a preferred event kind or discard extensions. Each field value uses OSVString:
  string (including empty) -> value with exact decoded content, null -> null, other
  JSON types -> invalid-type with empty string. No member is absent/unavailable.
- Unknown/nonstandard range types and repo strings remain uninterpreted; never fetch
  a repo, parse Git, normalize strings, reorder events, construct intervals, or resolve
  versions. Preserve invalid siblings and usable claims independently.
- Unknown range-level and other advisory fields remain in the raw document. A typed
  projection is not full schema validation, even when all projected fields are usable.
- Locator: source digest + affected Index + ranges Index + events Index + field Name.
  Preserve raw document/digest and independent ownership through every nested level.

## Combined range budget

Add **20,000 units per whole advisory projection**. One unit for each range array
slot, each event array slot, and each field in an object event. Count null/invalid
slots, repeated events, unknown fields, and unusable field values. Fixed type/repo
fields require no separate units; their number is bounded by range slots.

This is separate from the existing affected-entry and enumerated-version budgets.
No reset per affected entry, range, or event. Empty/non-value lists and empty event
objects add no child units, but their containing array positions still count.

Decode each raw collection under existing 4 MiB/depth-128 input bounds, check its
length against the remaining allowance before output allocation or sorting, then
consume it. This does not prevent raw decoding allocations or guarantee hard RSS.
Any excess, including a late event field, returns existing intel limit-exceeded and
a zero whole OSVAffectedProjection. No truncation or usable prefix. Zero remaining
allowance permits later empty/absent lists or already-counted empty event objects.

## Compatibility, acceptance and exclusions

Keep reader/temporal/inventory APIs and behavior, current errors, old nil-input guards,
raw ownership, and unchanged-successful-document/no-concurrent-mutation preconditions.
Unusable shapes remain states, not fatal errors. Existing affected-test expectations
may change only for the additive Ranges field (absent or already-recorded raw ranges).

Synthetic tests must cover all hierarchy states, exact strings, array order/duplicates,
sorted complete event field sets, unknown/multi-bound events, package/type/repo/versions
independence, nil/empty distinctions, source and nested ownership, and exact 20,000/
20,001 mixed units across affected entries/ranges/events/fields with late zero-result
failure. Existing tests/vet must continue passing.

No schema/identity/range-semantic qualification, SemVer/Git/ECOSYSTEM evaluation,
matching, active/freshness decisions, network/dependencies, target access, native
probes, SCALIBR work, CLI/reporting or platform qualification.
