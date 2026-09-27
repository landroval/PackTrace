# OSV affected identities implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:executing-plans`
> for approved inline execution. User approved the plan and explicitly authorized
> two new Go files, offline synthetic verification, and scoped code/docs commits.

**Goal:** expose positional package identity claims without filtering or qualification.
**Architecture:** a bounded array projection with explicit states at root, element,
package and string levels. Unavailable children retain zero/unavailable states;
only an inspectable parent can establish a field's absence.
**Tech stack:** current Go module, standard library only.
**Spec:** [approved affected identity contract/types](09-osv-affected.md).

## Global constraints

- Preserve order, duplicates, source digest, raw document and exact decoded strings.
- At most 20,000 affected entries, including null/invalid/repeated positions; check
  after array decode and before output allocation/child projection.
- No versions/ranges, ecosystem filtering, PURL parsing, normalization, inference,
  matching, new dependencies, network, target access, probes or qualification.
- Existing reader/temporal/inventory code and tests remain unchanged.
- Use current jj workspace and ledger, inline review and scoped code/docs commits.

## Review focus

1. A null/invalid element cannot prove package absence; unavailable is distinct.
2. Missing/null/invalid package cannot prove its name/ecosystem/PURL are absent.
3. Duplicate names and non-npm or contradictory PURL claims must survive independently.
4. Empty arrays/objects/strings have different meanings and nil/empty output shapes.
5. The limit counts array slots, not usable or unique identities, and never truncates.

## Task 1: implement the affected/package projection

**Create:** `internal/intel/osv_affected.go` and `internal/intel/osv_affected_test.go`.
**Consumes:** `OSVDocument`, existing intel `ParseError`, owned raw JSON fields.
**Produces:** the types/constants in the spec and
`ProjectOSVAffected(doc OSVDocument) (OSVAffectedProjection, error)`.

- [x] Add table tests using ParseOSVRecord-produced documents. Begin with a record
  whose affected array is `[null,{}, {"package":{}}, {"package":{"name":""}}]`:

```go
got, err := ProjectOSVAffected(doc)
if err != nil || got.State != OSVFieldValue || len(got.Entries) != 4 {
    t.Fatal("array positions lost", err)
}
if got.Entries[0].PackageState != OSVFieldUnavailable ||
    got.Entries[1].PackageState != OSVFieldAbsent ||
    got.Entries[1].Name.State != OSVFieldUnavailable ||
    got.Entries[2].Name.State != OSVFieldAbsent ||
    got.Entries[3].Name.State != OSVFieldValue || got.Entries[3].Name.Value != "" {
    t.Fatal("unavailable/absent/empty states collapsed")
}
```

  Cover root missing/null/non-array/empty array; element null/non-object/object;
  package missing/null/non-object/empty/object; each string absent/null/wrong-type/
  empty/value. Assert exact indices/order, duplicate entries, invalid siblings,
  non-npm ecosystems, conflicting PURLs and uninterpreted values. Snapshot raw data
  including versions/ranges/unknowns before/after; mutate source and output to verify
  owned results, independent entries and copied digest. Nil Fields -> zero projection
  and exact controlled invalid-shape error.
- [x] Generate exactly 20,000 array slots mixing null, wrong-type and repeated valid
  package objects; assert every position/state and preserved duplicate identity.
  Add one slot for controlled limit-exceeded/zero projection. No old fixture changes.
- [x] Observe missing-symbol compile RED, add only types/constants and zero-result
  stub, then observe behavioral RED before implementing projection.
- [x] Implement private `decodeOSVField` for the three actual raw shapes used here:

```go
func decodeOSVField[T string | []json.RawMessage | map[string]json.RawMessage](raw json.RawMessage, present bool) (T, OSVFieldState) {
    var value T
    if !present { return value, OSVFieldAbsent }
    if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) { return value, OSVFieldNull }
    if err := json.Unmarshal(raw, &value); err != nil {
        var zero T
        return zero, OSVFieldInvalidType
    }
    return value, OSVFieldValue
}
```

  This helper checks JSON type only; raw syntax/duplicates/depth were validated by
  the reader. Add private `projectOSVString(fields, key)` returning OSVString from
  the raw lookup plus decodeOSVField[string]; no inventory coupling or type moves.
- [x] Implement nil Fields guard, then decode affected into []json.RawMessage. Copy
  source digest/root state; non-value root returns nil Entries with nil error.
  Array count above `maxAffectedEntries = 20_000` returns zero result/limit-exceeded.
  Otherwise allocate non-nil output capacity equal to slot count and iterate in order:

```go
fields, state := decodeOSVField[map[string]json.RawMessage](raw, true)
entry := OSVAffectedEntry{Index: index, State: state}
if state == OSVFieldValue {
    packageRaw, present := fields["package"]
    packageFields, packageState := decodeOSVField[map[string]json.RawMessage](packageRaw, present)
    entry.PackageState = packageState
    if packageState == OSVFieldValue {
        entry.Ecosystem = projectOSVString(packageFields, "ecosystem")
        entry.Name = projectOSVString(packageFields, "name")
        entry.PURL = projectOSVString(packageFields, "purl")
    }
}
result.Entries = append(result.Entries, entry)
```

  Never synthesize child absence for an unusable parent. Leave unknown raw fields
  untouched, and return the full result only within the bound.
- [x] Format, run focused and full root tests/vet, review every parent/child state,
  cumulative slot count, ownership and evidence locator. Verify old Go files unchanged;
  rerun full tests/vet after inline review. Do not claim independent/native review.
- [x] Commit only the two Go files; separately update docs and the nested milestone,
  preserving all matching/qualification gates. Close the task ledger.

## Commands (Nushell)

```nu
gofmt -w internal/intel/osv_affected.go internal/intel/osv_affected_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 -run TestProjectOSVAffected ./internal/intel
    go test -count=1 ./...
    go vet ./...
}
jj commit -m "feat: project OSV affected identities" internal/intel/osv_affected.go internal/intel/osv_affected_test.go
```

Every verification command must succeed before commit. Type-correct identity claims
are not validated npm names/PURLs, applicability evidence or supported-schema proof.

## Execution evidence

- RED: missing API/types failed compilation. Types/constants plus a zero-result stub
  produced 52 behavioral test/subtest failures before implementation.
- GREEN: 52 new projection tests/subtests and all 420 previous cases pass (472 total),
  plus root vet. Full tests/vet rerun after inline review. Module listing remains
  only `packtrace`, using offline flags and the existing development toolchain.
- Tests cover every hierarchy level, missing versus unavailable children, exact
  strings, preserved duplicates/order, non-npm/conflicting identities, raw range/
  version/unknown fields, copied digest, ownership and controlled zero-result errors.
- Exactly 20,000 mixed null/invalid/repeated slots succeed with every position checked;
  20,001 fails without truncation. This is not an installed-instance count or RSS cap.
- Inline review checked all generic decoder instantiations, parent gating, count
  placement and returned ownership. All prior Go source/test files byte-identical
  to plan base `7109d143`; no independent or platform-review claim.
- Code `e93464b1` includes only the two approved files. No new dependencies, readers,
  timestamp changes, downloads, target access, SCALIBR/native probes or matching.
