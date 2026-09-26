# Typed npm locked records implementation plan

> **For agentic workers:** use `superpowers:executing-plans` for approved inline
> execution. The user approved this plan and explicitly authorized implementation,
> local synthetic tests/vet, and scoped code/docs commits in the current jj workspace.

**Goal:** expose typed, evidence-linked lockfile records without inferred semantics.
**Architecture:** project the existing `Document`, retaining it unchanged; sort
locations and decode only four string fields and one boolean field.
**Tech stack:** existing Go module and standard library only.
**Spec:** [approved increment-3 specification](03-npm-locked-records.md), including
all type declarations and the unchanged-document precondition.

## Global constraints

- No filesystem/network access, new dependency, CLI, native probe, or SCALIBR change.
- Preserve the existing reader and its v2/v3 acceptance contract unchanged.
- Additional projection maximum: 20,000 records including root/workspace/link.
  Above it, return a zero projection and `limit-exceeded` before sorting/allocation.
- Four distinct field states; invalid fields retain their record and valid siblings.
- No name inference, path normalization, deduplication, legacy merge, or validation
  of identity/version/origin/digest semantics. No public report/IPC schema.
- Test only synthetic local inputs, with the existing offline development toolchain.
- jj commits must exclude pre-existing and new `.pi/todos` metadata.

## Review focus

1. Common npm records omit `name`: do not derive it from `node_modules` keys.
2. Link/workspace/root entries are not installed dependency instances: retain them
   separately without following or resolving anything.
3. Empty string and false are present values: distinguish them from absent/null.
4. Bad field types must not erase valid sibling fields or become coerced values.
5. A late invalid record or excess count must not return an apparently usable prefix.

## Task 1: implement the projection and tests

**Create:** `internal/inventory/npmlock_projection.go` and
`internal/inventory/npmlock_projection_test.go`.
**Consumes:** `Document` returned unchanged by `ParseNPMLock` and existing `ParseError`.
**Produces:** the types and `ProjectNPMLock(Document) (NPMLockProjection, error)`
exactly specified in the linked contract. No shared-interface change is needed.

- [x] Write tests first, parsing synthetic v2/v3 bytes with the existing reader.
  Start with a minimal positive assertion of preserved ordering and explicit data:

```go
func TestProjectNPMLockOrdersRecords(t *testing.T) {
    doc, err := ParseNPMLock([]byte(`{"lockfileVersion":3,"packages":{"node_modules/z":{"name":"same"},"":{"name":"root"},"node_modules/a":{"name":"same"}}}`))
    if err != nil { t.Fatal(err) }
    got, err := ProjectNPMLock(doc)
    if err != nil { t.Fatal(err) }
    if len(got.Records) != 3 { t.Fatal("lost lockfile records") }
    for i, want := range []string{"", "node_modules/a", "node_modules/z"} {
        if got.Records[i].Location != want { t.Fatal("order or location changed") }
    }
    if got.Records[1].Name != (LockField[string]{State: FieldValue, Value: "same"}) {
        t.Fatal("explicit name lost")
    }
    if got.SourceSHA256 != doc.SHA256 { t.Fatal("evidence digest lost") }
}
```

- [x] Extend that fixture/test across both versions with workspace, link, alias,
  unusual keys, missing names, and uninterpreted range/source/digest strings.
  Use a literal expected order and explicit scalar expectations. Snapshot the raw
  document with `json.Marshal` before/after projection, including an unknown field
  and conflicting legacy data; then mutate raw field bytes, maps, and the document
  digest and assert the previously returned projection is unchanged.
- [x] Add a table that applies the same raw value to `name`, `version`, `resolved`,
  and `integrity`, plus an independently supplied `link` value:

| String-field JSON / link JSON | Expected states and values |
| --- | --- |
| fields absent | absent, zero values |
| `null` / `null` | null, zero values |
| `""` / `false` | value, empty string / false |
| `"text"` / `true` | value, text / true |
| `"\ud83d\ude00"` / `true` | value, decoded emoji / true |
| `42` / `"false"` | invalid type, zero values |
| `true` / `0` | invalid type, zero values |
| `[]` / `[]` | invalid type, zero values |
| `{}` / `{}` | invalid type, zero values |

  Add a mixed-type record with invalid name but usable version/resolved/integrity
  and link; assert the record and valid fields survive, without fabricated names.
- [x] Cover parsed empty packages (non-nil empty records), zero document, nil Fields,
  nil Packages, and a nil record after a valid sorted record. Use the existing typed
  error/category contract and assert both zero digest and nil records on rejection.
  Build synthetic parsed documents containing exactly 20,000 and 20,001 entries
  with `strings.Builder`/`fmt.Fprintf`; assert full success versus zero-result limit
  error. Do not change the parser's limits or run package managers.
- [x] Run the tests to observe the initially missing API. Then introduce only the
  specified type declarations and a compiling stub returning
  `NPMLockProjection{}, nil`. Rerun the projection tests: missing-record and expected-
  error assertions must fail at runtime. Missing-symbol compilation errors alone
  do not satisfy this RED gate.
- [x] Implement the minimum function: nil guards, count guard, `slices.Sorted` over
  `maps.Keys`, one output slot per key, nil-record rejection, and the five fields.
  Decode field state through one helper used by string and bool fields:

```go
func projectField[T string | bool](fields map[string]json.RawMessage, key string) LockField[T] {
    raw, ok := fields[key]
    if !ok { return LockField[T]{State: FieldAbsent} }
    if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
        return LockField[T]{State: FieldNull}
    }
    var value T
    if err := json.Unmarshal(raw, &value); err != nil {
        return LockField[T]{State: FieldInvalidType}
    }
    return LockField[T]{State: FieldValue, Value: value}
}
```

  Use `make([]LockedRecord, 0, len(doc.Packages))` so empty input has a non-nil
  slice. Append records in sorted order; copy `doc.SHA256` only into successful
  results. Reject with `NPMLockProjection{}, &ParseError{Code: ...}` using the exact
  `invalid-shape` and `limit-exceeded` categories, never raw decoder errors.
- [x] Format both new files; run all root tests and vet; inspect the diff against
  every acceptance item. Confirm old reader/tests/module are unchanged and no
  import introduces I/O. Review is inline, not independent/native qualification.
- [x] Commit only the two new Go files with jj, then record completion in these
  increment documents and a nested shipping milestone in a separate docs commit.

## Commands (Nushell)

RED: use `go test -count=1 -run TestProjectNPMLock ./internal/inventory` in the
following offline environment. GREEN runs the complete root suite:

```nu
gofmt -w internal/inventory/npmlock_projection.go internal/inventory/npmlock_projection_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 ./...
    go vet ./...
}
jj commit -m "feat: project typed npm locked records" internal/inventory/npmlock_projection.go internal/inventory/npmlock_projection_test.go
```

Record actual toolchain and results. Do not download/install anything, execute
existing probes, claim full npm support, or expand to another increment.

## Execution evidence

- Initial compilation failed for the absent projection API. After adding only the
  specified types and a zero-result stub, all 36 projection tests/subtests failed
  at runtime: missing records/evidence, lost field-state results, or missing errors.
  This second run established behavioral RED before implementation.
- GREEN: 139 root tests/subtests passed; root `go vet ./...` passed. Both were rerun
  after inline review. `go list -m all` listed only `packtrace`.
- Development toolchain: `go1.27.1-X:nodwarf5 linux/amd64`, with the offline flags
  above. No downloads, native qualification, or probe execution/changes.
- Existing `npmlock.go`, `npmlock_test.go`, and `go.mod` were unchanged. New
  production code uses only bytes/JSON/maps/slices; no filesystem or network I/O.
- Scoped code commit: `8ef999fe`. Review was inline, not independent.
- Markdown link verification excludes fenced and inline code: Go signatures such as
  `projectField[T](...)` are code, not document links.
