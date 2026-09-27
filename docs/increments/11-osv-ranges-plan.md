# OSV ranges and events implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:executing-plans`
> for approved inline execution. Await plan review and execution authorization.

**Goal:** retain all recorded range/event claims without interval evaluation.
**Architecture:** extend affected entries with one range projection; nested helpers
share a single remaining-unit counter owned by ProjectOSVAffected. Reuse raw shape
and string decoding, keeping unusable children unavailable.
**Tech stack:** Go standard library (`encoding/json`, `maps`, `slices`).
**Spec:** [approved range/event contract and type definitions](11-osv-ranges.md).

## Global constraints

- One cumulative 20,000-unit range budget: range slots + event slots + event fields.
- Existing affected/version budgets remain independent and unchanged.
- Preserve all arrays in source order with indices; sort complete object-event keys,
  not events. Keep unknown and multiple event keys rather than choosing a bound.
- Unusable shapes are states; budget excess yields controlled error/zero whole result.
- No semantic evaluation, schema qualification, matching, dependencies, network,
  target access, readers/temporal changes, probes or platform qualification.
- Current jj workspace/file ledger, inline review, scoped commits only.

## Review focus

1. Events with unknown or simultaneous known keys must not silently become one known event.
2. Events remain available with unusable range type/repo; ranges with unusable package/versions.
3. Parent null/invalid versus empty objects must preserve unavailable/absent distinctions.
4. All three unit kinds count across every nested boundary, including invalid slots/values.
5. A shallow outer copy cannot prove nested slice/map ownership; use snapshots and mutations.

## Task 1: add bounded range/event evidence

**Create:** `internal/intel/osv_ranges.go`, `internal/intel/osv_ranges_test.go`.
**Modify:** `internal/intel/osv_affected.go`, `internal/intel/osv_affected_test.go`.
**Consumes:** OSVFieldState, OSVString, decodeOSVField, projectOSVString, ParseError.
**Produces:** spec types, additive `OSVAffectedEntry.Ranges OSVRanges`, and private
`projectOSVRanges(fields map[string]json.RawMessage, remaining *int) (OSVRanges, error)`.

- [ ] Write tests through the existing affectedDocument helper. Begin with a range
  whose type is null and events contain `{"introduced":"0","fixed":"2","future":false}`:

```go
got, err := ProjectOSVAffected(doc)
if err != nil || len(got.Entries) != 1 || len(got.Entries[0].Ranges.Entries) != 1 {
    t.Fatal("range lost", err)
}
r := got.Entries[0].Ranges.Entries[0]
if r.Type.State != OSVFieldNull || len(r.Events.Entries) != 1 {
    t.Fatal("type failure erased event evidence")
}
f := r.Events.Entries[0].Fields
if len(f) != 3 || f[0].Name != "fixed" || f[1].Name != "future" ||
    f[1].Value.State != OSVFieldInvalidType || f[2].Name != "introduced" {
    t.Fatal("unknown/multiple event fields hidden or unsorted")
}
```

  Test every parent/list/object/string state, empty arrays/objects/keys/strings,
  duplicate ranges/events, exact decoded keys/values, all known event names plus
  unknowns, invalid siblings, wrong-level data ignored, nonstandard types/repo
  strings, independent package/versions/type/repo usability, digest and raw retention.
  Snapshot nested output, mutate source, then one returned event field to verify
  other entries/events and source remain independent.
- [ ] Build a mixed cumulative-bound fixture across two affected entries. First:
  two range slots (one null), two event slots (one null), and two fields in the
  object event (one invalid unknown field): six units. Second: one range with
  19,993 empty-object events: 19,994 units. Total 20,000 succeeds, including later
  empty/absent range lists. Add one unknown null field to the last event for 20,001;
  require controlled limit-exceeded and zero whole projection. This pins all three
  unit kinds and prevents per-record/range/event reset.
- [ ] Observe missing type/field compile RED. Add only type definitions and Ranges
  field; rerun focused tests for runtime RED. Update old affected expectations only
  for absent Ranges on object entries and the already-present UNKNOWN/introduced
  range in the repeated fixture. Do not change old fixtures or prior-field assertions.
- [ ] Implement `maxRangeUnits = 20_000` and a private counter helper:

```go
func consumeOSVRangeUnits(remaining *int, count int) error {
    if count > *remaining { return &ParseError{Code: "limit-exceeded"} }
    *remaining -= count
    return nil
}
```

  Callers pass a private nonnegative remaining counter and nonnegative collection
  lengths; no new generic quota framework. Check/consume after raw decoding but
  before output allocation, child projection, or key sorting.
- [ ] Implement projectOSVRanges: decode the ranges list via decodeOSVField; non-value
  returns its state with nil entries. Consume len(items), allocate non-nil output,
  iterate in source order and decode each element object. Always retain Index/state;
  only objects project Type/Repo plus Events using private
  `projectOSVEvents(fields map[string]json.RawMessage, remaining *int) (OSVEvents, error)`.
- [ ] Implement projectOSVEvents analogously: consume event slots before output;
  for each object event, consume len(fields), allocate non-nil field output, then
  iterate `slices.Sorted(maps.Keys(fields))` and append
  `OSVEventField{Name: name, Value: projectOSVString(fields, name)}`. Null/invalid
  event elements retain state/index with nil fields. Empty objects retain empty fields.
  Propagate errors as zero helper results; do not discard unfamiliar names or choose
  an event kind. Range type/repo validity cannot gate event decoding.
- [ ] In ProjectOSVAffected initialize `remainingRanges := maxRangeUnits` once before
  its loop. For each object affected entry, outside package/versions-success gating:

```go
ranges, err := projectOSVRanges(fields, &remainingRanges)
if err != nil { return OSVAffectedProjection{}, err }
entry.Ranges = ranges
```

  Existing fatal version-budget errors remain fatal; unusable version list states
  do not block ranges. Keep all prior identity/version assignments and root guards.
- [ ] Format four files, run focused and full root tests/vet; inspect counter sharing,
  type-gating, complete field enumeration and nested ownership. Verify changes outside
  four-file scope absent; rerun full tests/vet after inline review.
- [ ] Commit the four Go files only; separately record actual verification and a
  nested milestone, preserving all semantic/matching/native gates. Close the ledger.

## Commands (Nushell)

```nu
gofmt -w internal/intel/osv_ranges.go internal/intel/osv_ranges_test.go internal/intel/osv_affected.go internal/intel/osv_affected_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 -run TestProjectOSVRanges ./internal/intel
    go test -count=1 ./...
    go vet ./...
}
jj commit -m "feat: project OSV range and event evidence" internal/intel/osv_ranges.go internal/intel/osv_ranges_test.go internal/intel/osv_affected.go internal/intel/osv_affected_test.go
```

Require successful verification before commit. Review is inline, not independent;
retained event strings are not evaluated intervals or confirmed affected versions.
