# Manifest declarations implementation plan

> **For agentic workers:** use `superpowers:executing-plans` for approved inline
> execution. Await plan review and explicit execution authorization.

**Goal:** read manifest bytes and retain typed dependency declarations separately
from locked and installed evidence.
**Architecture:** share strict JSON-object decoding with the npm reader; reuse
`FieldState` and the scalar decoder; no new framework or dependency.
**Tech stack:** existing Go module and standard library.
**Spec:** [approved increment-4 specification](04-manifest-declarations.md).

## Global constraints

- Manifest limit 2 MiB; lockfile limit remains 64 MiB; both have 128-container depth.
- One authoritative strict validator, unchanged duplicate/Unicode/trailing checks.
- At most 20,000 projected declarations across all four groups; all memberships
  count, including invalid/null values and repeats. No truncation or partial return.
- Original SHA-256, raw fields, independent ownership, and explicit field states.
- No semantic resolution, execution, target I/O, network, dependency acquisition,
  native qualification, or probe changes. Existing APIs/types retain their names.
- Only the approved internal error-prefix change: `inventory: CODE`.
- Work inline in the current jj workspace; exclude `.pi/todos` from commits.

## Review focus

1. Requirements resembling versions, aliases, paths, or URLs must remain strings,
   not resolved identities or evidence of installation.
2. The same key in multiple groups must survive, with conflicting requirements.
3. Null/invalid groups and requirements cannot silently become absent/empty-success.
4. A cumulative limit reached in a later group must invalidate the whole projection.
5. Shared decoding must retain all old lockfile rejection and byte-limit behavior.

## Task 1: implement the manifest reader and projection

**Create:** `internal/inventory/manifest.go`, `internal/inventory/manifest_test.go`.
**Modify:** `internal/inventory/npmlock.go` (factor shared decoding and neutral error
prefix), `npmlock_test.go` and `npmlock_projection_test.go` (error prefix assertions
only). All paths are under `internal/inventory/`.
**Consumes:** existing `ParseError`, `validateValue`, `validSurrogates`, `FieldState`,
and `projectField[string]` without duplicating their logic.
**Produces:** the types/functions declared in the spec, plus the private
`parseJSONFields(data []byte, byteLimit int) (map[string]json.RawMessage, error)`.
No change to `ParseNPMLock`, `ProjectNPMLock`, or their data type signatures.

- [ ] Write manifest tests first. Begin with a literal retained declaration:

```go
func TestManifestDeclaredGroups(t *testing.T) {
    const input = `{"dependencies":{"same":"^1","alias":"npm:real@~2"},"devDependencies":{"same":"^3"}}`
    doc, err := ParseManifest([]byte(input))
    if err != nil { t.Fatal(err) }
    got, err := ProjectManifest(doc)
    if err != nil || len(got.Groups) != 4 { t.Fatal("four groups required", err) }
    if got.Groups[0].Name != "dependencies" || got.Groups[0].State != FieldValue ||
        len(got.Groups[0].Entries) != 2 { t.Fatal("declared group lost") }
    if got.Groups[0].Entries[0] != (DeclaredDependency{Name: "alias", Requirement: "npm:real@~2", State: FieldValue}) {
        t.Fatal("alias declaration changed")
    }
    if got.Groups[1].Entries[0].Requirement != "^3" { t.Fatal("groups merged") }
}
```

  Extend this into guarded assertions (check lengths before indexing) for all four
  group names, fixed order, lexical entry order, repeated names, file/workspace/Git/
  URL/range strings, raw scripts/peer metadata/unknown precise numbers, original
  digest and unchanged raw document. Mutate source bytes after parsing and document
  data after projection to verify independent ownership.
- [ ] Add reader rejection tables for invalid/trailing/root-non-object JSON,
  duplicate keys including escaped equivalents and nested unknown/requirements,
  malformed UTF-8/surrogates, plus accepted Unicode and an uninterpreted
  `lockfileVersion` field. Check zero document and controlled errors on failure.
  Verify exactly 2 MiB vs 2 MiB+1 and 128 vs 129 containers; retain the old npm suite.
- [ ] Add these projection cases, keeping all valid sibling data:

| Group / requirement condition | Expected |
| --- | --- |
| missing group | absent, nil entries |
| null group | null, nil entries |
| number/string/bool/array group | invalid type, nil entries |
| empty object group | value, non-nil empty entries |
| string requirement, including empty/Unicode | value, exact decoded string |
| null requirement | null, empty requirement string |
| number/bool/array/object requirement | invalid type, empty requirement string |
| nil document Fields | invalid-shape, zero projection |
| parsed `{}` | four absent groups, source digest retained |

  Assert zero result and privacy-safe prefix on projection errors. Build bounded
  synthetic manifests with 10,000 null requirements in one group and 10,000 invalid
  requirements using the same names in another: all 20,000 memberships must survive.
  Add one more membership in a later group for zero-result `limit-exceeded`.
- [ ] Update the two existing error helpers to expect `inventory: `, without changing
  other expectations. Run tests to confirm the new API is absent; add only the
  specified types and zero-result stubs; rerun for runtime RED. Compilation errors
  alone do not establish the behavioral gate.
- [ ] Factor the existing size/UTF-8/token/depth/duplicate/surrogate/object checks
  from `ParseNPMLock` into `parseJSONFields`, in the same order. Use its `byteLimit`
  parameter for size rejection; retain `UseNumber`. Change the controlled error
  prefix. `ParseNPMLock` then starts with:

```go
fields, err := parseJSONFields(data, maxLockfileBytes)
if err != nil { return Document{}, err }
```

  Preserve its existing integer-version, package-shape, raw-retention and digest
  handling. `ParseManifest` calls the same helper with `2 << 20`, propagates safe
  errors with a zero document, and returns `ManifestDocument{SHA256: sha256.Sum256(data), Fields: fields}`.
- [ ] Implement `ProjectManifest`: reject nil Fields; allocate four named groups in
  the specified order; distinguish absence/null/non-object/object. Decode an object
  to `map[string]json.RawMessage`; before sorting or allocating its output entries:

```go
if len(entries) > maxManifestDeclarations-total {
    return ManifestProjection{}, &ParseError{Code: "limit-exceeded"}
}
total += len(entries)
```

  Set object groups to `FieldValue` and make non-nil entry slices. Iterate
  `slices.Sorted(maps.Keys(entries))`, decode with `projectField[string]`, and append
  `DeclaredDependency{Name: name, Requirement: field.Value, State: field.State}`.
  Return the source digest only with the successful complete group slice.
- [ ] Format the changed/new Go files, run all root tests/vet, and inspect the full
  diff and the shared validator's callers. Confirm no I/O imports, new dependencies,
  probe changes, or undeclared lockfile behavior changes. Review is inline.
- [ ] Commit only the five listed Go files with jj, then record verified completion
  and a nested shipping milestone in a separate documentation commit.

## Commands (Nushell)

Use the existing local toolchain, not a downloaded replacement. For RED, use
`go test -count=1 -run 'TestManifest|TestParseManifest|TestProjectManifest' ./internal/inventory`.
For final GREEN:

```nu
gofmt -w internal/inventory/manifest.go internal/inventory/manifest_test.go internal/inventory/npmlock.go internal/inventory/npmlock_test.go internal/inventory/npmlock_projection_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 ./...
    go vet ./...
}
jj commit -m "feat: read manifest dependency declarations" internal/inventory/manifest.go internal/inventory/manifest_test.go internal/inventory/npmlock.go internal/inventory/npmlock_test.go internal/inventory/npmlock_projection_test.go
```

Record actual development toolchain and test results. Do not run the nested
SCALIBR module or promote synthetic checks to producer/native qualification.
