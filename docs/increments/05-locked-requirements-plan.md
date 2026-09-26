# Locked requirements implementation plan

> **For agentic workers:** use `superpowers:executing-plans` for approved inline
> execution. Await plan review and explicit execution authorization.

**Goal:** expose requirements recorded per npm lockfile location without resolving them.
**Architecture:** one shared group projector, with a remaining allowance supplied
by each caller; separate enclosing manifest/lockfile evidence types.
**Tech stack:** existing Go module, standard library only.
**Spec:** [approved increment-5 specification](05-locked-requirements.md).

## Global constraints

- Preserve all existing parser APIs/behavior, field states, source evidence,
  ownership, and the lockfile's 20,000-record bound.
- Add 20,000 requirement memberships per whole lockfile projection, not per record.
  Count repeated, null, and invalid memberships; failures return a zero projection.
- Keep the manifest's independent 20,000-membership limit unchanged.
- No legacy-tree merging, range/alias/link resolution, graph construction, I/O,
  dependencies/downloads, native probes, SCALIBR changes, or qualification claims.
- Inline review and scoped jj commits; exclude `.pi/todos` metadata.

## Review focus

1. Root/workspace/link records must retain their own groups without following links.
2. A repeated name across records/groups must not be deduplicated or merged.
3. The budget cannot reset per record or silently exclude null/invalid requirements.
4. A full budget still permits later records with zero requirements.
5. A late excess must discard the projection prefix, not the retained raw document.

## Task 1: reuse dependency-group projection in locked records

**Modify:** `internal/inventory/manifest.go`, `npmlock_projection.go`, and
`npmlock_projection_test.go` (all under `internal/inventory/`). No new Go files.
**Consumes:** existing `DependencyGroup`, `DeclaredDependency`, `FieldState`,
`projectField[string]`, `Document`, and controlled errors.
**Produces:** `LockedRecord.Requirements []DependencyGroup` and private
`projectDependencyGroups(fields map[string]json.RawMessage, allowance int) ([]DependencyGroup, int, error)`.

- [ ] Write v2/v3 tests first. A minimal positive assertion starts with:

```go
func TestProjectNPMLockRequirements(t *testing.T) {
    doc := parseProjectionInput(t, `{"lockfileVersion":3,"packages":{"":{"dependencies":{"alias":"npm:real@^2","same":"^1"}},"node_modules/a":{"dependencies":{"same":"~3"}}}}`)
    got, err := ProjectNPMLock(doc)
    if err != nil || len(got.Records) != 2 { t.Fatal("lost records", err) }
    if len(got.Records[0].Requirements) != 4 || len(got.Records[1].Requirements) != 4 {
        t.Fatal("four per-record requirement groups required")
    }
    root := got.Records[0].Requirements[0]
    if len(root.Entries) != 2 || root.Entries[0].Requirement != "npm:real@^2" {
        t.Fatal("root alias requirement changed")
    }
    child := got.Records[1].Requirements[0]
    if len(child.Entries) != 1 || child.Entries[0].Requirement != "~3" {
        t.Fatal("requirements merged across records")
    }
}
```

  Extend across versions with absent/null/empty/invalid groups, mixed null/invalid/
  usable requirements, lexical ordering, root/workspace/link entries, and conflicting
  top-level legacy data. Snapshot raw document before/after; mutate source requirement
  bytes/maps after projection and assert independence. Mutate one returned group's
  metadata and confirm another record's groups do not alias it.
- [ ] Add cumulative-bound fixtures with two records: first has 10,000 null
  dependency entries; second has 5,000 invalid dev entries and 5,000 optional entries,
  reusing names across records/groups. A third record with an empty object group
  must still succeed at exactly 20,000. Give that later group one entry to require
  `limit-exceeded` and a zero projection. Use the existing error assertion helper.
- [ ] Run tests to observe the missing field, then add only the `Requirements` field
  to make them compile. Rerun for runtime RED: missing groups and missing cumulative
  error must fail before implementing projection behavior.
- [ ] Extract the existing group loop from `ProjectManifest` into the private helper.
  Use the argument `fields` instead of `doc.Fields`, and `allowance` instead of the
  manifest constant. Return `nil, 0, err` for a limit error, or `groups, total, nil`
  on success. Retain fixed group order, all states, independent slices, and decoding
  before the count check / sorting / output allocation. `ProjectManifest` becomes:

```go
if doc.Fields == nil {
    return ManifestProjection{}, &ParseError{Code: "invalid-shape"}
}
groups, _, err := projectDependencyGroups(doc.Fields, maxManifestDeclarations)
if err != nil { return ManifestProjection{}, err }
return ManifestProjection{SourceSHA256: doc.SHA256, Groups: groups}, nil
```

- [ ] Add `maxLockedRequirements = 20_000` alongside the record limit. Initialize
  `remaining := maxLockedRequirements` once before the record loop. After each
  record's existing nil guard:

```go
groups, used, err := projectDependencyGroups(fields, remaining)
if err != nil { return NPMLockProjection{}, err }
remaining -= used
```

  Assign `Requirements: groups` in that record's literal. Preserve existing scalar
  assignments and final source digest; never consume the top-level legacy tree.
- [ ] Format the three files; run all root tests/vet, including unchanged manifest
  regressions. Review helper callers, limits, nil/empty distinctions, error privacy,
  and the absence of parser/module/probe changes. Review is inline, not independent.
- [ ] Commit only those three Go files; record results and a nested shipping
  milestone in a separate documentation commit after verification.

## Commands (Nushell)

For RED, run `go test -count=1 -run 'TestProjectNPMLock.*Requirements' ./internal/inventory`
with the offline environment below. For final GREEN:

```nu
gofmt -w internal/inventory/manifest.go internal/inventory/npmlock_projection.go internal/inventory/npmlock_projection_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 ./...
    go vet ./...
}
jj commit -m "feat: project locked dependency requirements" internal/inventory/manifest.go internal/inventory/npmlock_projection.go internal/inventory/npmlock_projection_test.go
```

Use the existing development toolchain, record actual results, and do not run
package managers, nested probes, or native qualification merely to finish this task.
