# Explicit OSV versions implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:executing-plans`
> for approved inline execution. User approved the plan and explicitly authorized
> three Go files, offline synthetic verification, and scoped code/docs commits.

**Goal:** preserve enumerated versions at their affected-entry positions without interpretation.
**Architecture:** extend ProjectOSVAffected using its existing shape decoder and
states. A private list helper consumes a remaining whole-advisory version allowance.
**Tech stack:** current Go module, standard library only.
**Spec:** [approved versions contract](10-osv-versions.md).

## Global constraints

- Version lists belong to object affected elements, independently of package usability.
- Existing 20,000 affected-entry cap plus independent 20,000 cumulative version slots.
- Count duplicate/null/invalid slots; preserve order, positions and raw evidence.
- Unusable parent -> unavailable list; absent/null/invalid list -> nil Entries;
  array -> non-nil Entries, including empty. Member strings are not qualified versions.
- No readers, temporal code, dependencies, network, target access, probes or matching changes.
- Current jj workspace, file-backed ledger, inline review, scoped code/docs commits.

## Review focus

1. Nesting version projection under package-success would erase independent evidence.
2. Null/invalid members and duplicate strings still consume the cumulative budget.
3. A late excess must return a zero projection, not earlier affected entries.
4. Zero allowance still permits later empty/absent lists.
5. New nested slices require ownership tests, not only shallow copies of entry structs.

## Task 1: extend affected entries with enumerated versions

**Modify:** `internal/intel/osv_affected.go`, `internal/intel/osv_affected_test.go`.
**Create:** `internal/intel/osv_versions_test.go`.
**Consumes:** OSVDocument, OSVFieldState, OSVString, decodeOSVField, existing test helpers.
**Produces:** `OSVVersions { State OSVFieldState; Entries []OSVString }` and
`OSVAffectedEntry.Versions OSVVersions`; ProjectOSVAffected signature unchanged.

- [x] Write focused tests through affectedDocument/ProjectOSVAffected. A first case
  uses `[{"package":null,"versions":["1",null,false,"1"]}]` and asserts:

```go
got, err := ProjectOSVAffected(doc)
if err != nil || len(got.Entries) != 1 { t.Fatal("entry lost", err) }
want := OSVVersions{State: OSVFieldValue, Entries: []OSVString{
    {State: OSVFieldValue, Value: "1"}, {State: OSVFieldNull},
    {State: OSVFieldInvalidType}, {State: OSVFieldValue, Value: "1"},
}}
if !reflect.DeepEqual(got.Entries[0].Versions, want) {
    t.Fatal("independent versions lost, coerced, or deduplicated")
}
```

  Include invalid/null affected parents, absent/null/non-array/empty lists, every
  wrong-type member, empty/exact/escaped/uninterpreted strings, package missing and
  wrong type, package.versions ignored, multiple affected entries and raw conflicting
  ranges untouched. Serialize output before source mutation to avoid shallow-copy
  false positives; mutate one returned version and check other entries/input unchanged.
- [x] Add two lists of 10,000 members across different affected entries, mixing null,
  invalid and repeated strings with unusable packages. A later empty list and absent
  list still succeed. Adding one member to the later list must fail with existing
  assertAffectedError and zero projection. Check every returned member/position.
- [x] Observe missing-field/type compile RED, add only the new type and entry field,
  rerun focused tests for behavioral RED before projection logic. Update old expected
  structures only for the additive field: object entries without versions get absent,
  realistic repeated fixture gets value list `["9"]`; unusable parents stay unavailable.
  Do not alter fixtures or existing assertions for prior fields.
- [x] Add `maxAffectedVersions = 20_000`; initialize remaining once before the affected
  loop. Add private `projectOSVVersions(fields map[string]json.RawMessage, remaining int)
  (OSVVersions, int, error)`: decode versions array with existing helper, return state/
  zero consumption for non-value lists, reject excess before output allocation, otherwise
  allocate non-nil Entries and decode each member with `decodeOSVField[string](raw,true)`.
  Return the list and len(items), counting all entries rather than just strings.
- [x] For every object affected element, **outside** the package-success condition:

```go
versions, used, err := projectOSVVersions(fields, remaining)
if err != nil { return OSVAffectedProjection{}, err }
remaining -= used
entry.Versions = versions
```

  Keep all existing package projection assignments and nil/root/entry-count guards.
  Return zero OSVVersions/count on helper errors, zero whole projection on any error.
- [x] Format three files, run focused versions tests, all root tests and vet. Review
  counter lifetime, parent gating, nil/empty differences, source/duplicate ownership,
  and the narrow old-test expectation changes. Rerun full tests/vet after inline review.
- [x] Commit only the three Go files; separately record verification/nested milestone
  without closing matching/qualification gates. Close the task ledger.

## Commands (Nushell)

```nu
gofmt -w internal/intel/osv_affected.go internal/intel/osv_affected_test.go internal/intel/osv_versions_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 -run TestProjectOSVVersions ./internal/intel
    go test -count=1 ./...
    go vet ./...
}
jj commit -m "feat: project explicit OSV versions" internal/intel/osv_affected.go internal/intel/osv_affected_test.go internal/intel/osv_versions_test.go
```

Require successful verification before commit. Review remains inline, not independent;
synthetic success is not schema, version, native or production matching qualification.

## Execution evidence

- RED: absent field/type prevented compilation. With only the new field/type,
  13 of 16 new tests/subtests failed at runtime; the three existing unavailable-parent
  behaviors already passed. Projection logic followed this behavioral RED gate.
- GREEN: all 16 new cases and the previous 472 pass (488 total), plus root vet;
  full tests/vet rerun after inline review. Module listing remains only `packtrace`.
- Existing affected tests changed only four expectation sites for the additive field:
  absent lists for object elements, and `["9"]` already present in the repeated fixture.
  All Go files outside the approved three-file scope are byte-identical to base `9e834f4f`.
- Review verified one remaining-version counter across affected entries, version
  projection independent of package success, all-slot counting, error/zero-result
  behavior, and no range interpretation. Two 10,000-member lists plus later empty/
  absent lists pass; adding one late member fails without a partial projection.
- Ownership tests serialize nested output before source mutation and separately mutate
  returned list members to check no cross-entry/input aliasing. Raw ranges remain intact.
- Code `9b3548c9` contains only approved source/tests. Offline environment above,
  existing development toolchain, inline review only; no downloads, new dependencies,
  readers, target access, native probes, or qualification changes.
