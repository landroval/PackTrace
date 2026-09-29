# Typed Bun locked records implementation plan

> Plan submitted for review together with its implementation in the same pull
> request. Executed with local synthetic tests only. No downloads, new
> dependencies, Bun execution, or native probes are authorized by this plan.

**Goal:** Deliver the in-memory `bun.lock` projection and regression tests
described in the specification.
**Architecture:** One exported function over the existing `BunLockDocument`,
using two unexported steps per tuple: split the first element into name and
resolution, then classify the kind by resolution form and tuple shape. Reuse
`FieldState`, `LockField[T]`, `projectField`-style decoding, and `ParseError`.
**Tech stack:** Go standard library, `testing`, `go vet`.
**Spec:** [Typed Bun locked records specification](13-bun-lock-projection.md).

## Constraints

- Go module floor 1.27.1; use the available local toolchain for development and
  record its version. Do not claim release qualification.
- No network, external dependencies, real project inputs, Bun execution, or
  native probe execution. Fixtures are synthetic byte literals parsed with
  `ParseBunLock`, except nil and non-array guard cases built as documents.
- At most 20,000 records, checked with `len(doc.Packages)` before sorting or
  allocating.
- Errors carry category only; never echo raw values or package names.
- Do not change `bunlock.go`, `jsonc.go`, `npmlock_projection.go`, their tests,
  `internal/jsoninput`, or the SCALIBR probe.

## Files and interface

Create only these production/test files:

- `internal/inventory/bunlock_projection.go`: types, `ProjectBunLock`, and
  unexported helpers.
- `internal/inventory/bunlock_projection_test.go`: projection tables and
  boundary tests.

```go
type BunResolutionKind uint8

type BunLockedRecord struct {
    Key        string
    Kind       BunResolutionKind
    Name       LockField[string]
    Resolution LockField[string]
    Registry   LockField[string]
    Integrity  LockField[string]
    GitTag     LockField[string]
    Info       json.RawMessage
}

type BunLockProjection struct {
    SourceSHA256 [32]byte
    Records      []BunLockedRecord
}

func ProjectBunLock(doc BunLockDocument) (BunLockProjection, error)

func splitBunResolution(first LockField[string]) (name, resolution LockField[string])
func classifyBunTuple(resolution string, rest []json.RawMessage) BunResolutionKind
```

On failure return the zero `BunLockProjection` with `invalid-shape` or
`limit-exceeded`. Element decoding reuses the existing four-state rules: absent,
`null`, value of the expected JSON type, or invalid type.

## Review focus

- The split uses the first `@` after index 0; `@root:` is the only special case.
  A git resolution containing `@` must survive intact.
- Kind classification requires both the resolution form and the exact tuple
  shape; any mismatch is `BunKindUnknown`, never a partially trusted kind.
- `file:x.tgz` is a folder, because prefixes are checked before tarball suffixes.
- The fourth npm element and the optional git/tarball element are integrity; the
  third git element is a tag and must never land in `Integrity`.
- Unknown and malformed tuples stay as records; no tuple fails the projection.
- Returned strings and `Info` do not alias the document.

## Task 1: split and classify helpers

- [x] Write failing tests first in `bunlock_projection_test.go`:
  - Split table: `pkg@1.0.0`, `@scope/pkg@1.0.0`,
    `pkg@git+ssh://git@github.com/o/r#abc`, `@root:`, `pkg@`, `pkg`, `@scope/pkg`,
    `""`, and non-string/null/absent first elements, each with expected name and
    resolution states and values.
  - Classify table, one row per kind and shape from the specification, plus:
    `file:x.tgz` as folder; `HTTPS://x/y` and `./a.TAR.GZ` as tarball; git and
    tarball with and without optional integrity; npm with a non-string registry,
    missing integrity, or an extra element; git with a missing tag; link with a
    non-object INFO; workspace with a non-object element; root without an object;
    and an unrecognized form such as `catalog:` with a non-npm shape. All
    mismatches expect `BunKindUnknown`.
- [x] Run the tests and record the expected build failure because the helpers
  are absent. Then add the specified types and helper stubs returning zero
  values, rerun, and record runtime failures (behavioral RED).
- [x] Implement `splitBunResolution`: return states unchanged for non-values;
  handle `@root:`; search for `@` from index 1; reject a missing `@` or an empty
  resolution with `FieldInvalidType` for both fields.
- [x] Implement `classifyBunTuple` in the specification's order, using small
  shape checks (`isObject`, `isString`) over the raw elements. Compare the
  tarball suffixes and URL schemes ASCII case-insensitively.
- [x] Run the tests until they pass.

## Task 2: projection

- [x] Write failing tests first:
  - One synthetic document, parsed with `ParseBunLock`, containing every kind;
    assert `Kind`, `Name`, `Resolution`, `Registry`, `Integrity`, `GitTag`, and
    `Info` for each record, and that `Info` equals the raw INFO bytes.
  - Unknown and split-failure tuples kept as records with the specified states
    and every other field `FieldAbsent`; empty strings stored as values.
  - Deterministic order by `Key`, including two keys with the same name.
  - Digest copied; mutating the document's raw bytes and maps after projection
    does not change returned strings or `Info`; the document is not mutated.
  - Empty `packages` returns a non-nil empty slice. Nil `Fields`, nil `Packages`,
    a nil entry, and a non-array entry return zero projections with
    `invalid-shape`. Documents with exactly 20,000 and 20,001 entries return
    full success and `limit-exceeded` respectively.
- [x] Run the tests and record runtime RED against a stub returning
  `BunLockProjection{}, nil`.
- [x] Implement: nil guards, count guard, `slices.Sorted(maps.Keys(...))`,
  decode each entry into `[]json.RawMessage` (reject a decode failure as
  `invalid-shape`), split, classify, then fill fields by kind. Copy `Info` with
  `bytes.Clone`. Use `make([]BunLockedRecord, 0, len(doc.Packages))`.
- [x] Run the tests until they pass.

## Task 3: Verification

- [x] Format the two Go files and run the root checks:

```sh
gofmt -l internal/inventory
GOPROXY=off GOWORK=off CGO_ENABLED=0 go test -count=1 ./...
GOPROXY=off GOWORK=off CGO_ENABLED=0 go vet ./...
```

- [x] Review the diff against every specification requirement. Confirm that no
  dependency, disk or network access, INFO interpretation, SemVer or URL
  validation, or scanner support claim was introduced, and that existing tests
  still pass unchanged.
- [x] Commit only the two Go files as one scoped commit. Report red/green
  evidence, test/vet results, the development toolchain, and remaining
  qualification limits; record them here and in the specification in a separate
  docs commit.

## Execution boundary

This plan covers only the files listed above. It does not authorize downloads,
new dependencies, Bun execution, producer-generated fixtures, or changes to the
existing reader or probe.

## Execution evidence

- RED (Task 1): the build failed because `splitBunResolution` and
  `classifyBunTuple` were absent. With zero-value stubs, 33 split and classify
  subtests failed at runtime before implementation.
- RED (Task 2): against a `ProjectBunLock` stub returning
  `BunLockProjection{}, nil`, six top-level projection tests failed at runtime.
- GREEN: implementation and tests in `e02ac10`. The first GREEN run exposed that
  `json.Unmarshal` accepts `null` into a string, so an npm tuple with a `null`
  registry was classified as npm; `isJSONString` now rejects `null` and the case
  is `BunKindUnknown`.
- Parent review moved a misplaced `splitBunResolution` doc comment off
  `ProjectBunLock` and split the tarball condition into named booleans.
- Final result: 871 root tests/subtests (previously 773), `go vet`, and `gofmt -l`
  clean.
- Independent local review (reliability lens, medium risk) approved the change.
  One advisory suggestion is deferred: `BunKindUnknown` records do not copy their
  raw tuple. The tuple remains in `BunLockDocument.Packages` under the same key,
  as the specification requires, matching the npm projection.
- A branch-wide reliability review approved the change with one warning: no test
  covered a `null` INFO or root object. `isJSONObject` already rejects `null`, so the
  behavior was correct; six `null` cases now pin it. Removing the `null` check made
  all six fail. The root suite then had 877 tests/subtests.
- Development toolchain: `go1.27.1 darwin/arm64` with `GOPROXY=off`, `GOWORK=off`,
  and `CGO_ENABLED=0`; no release qualification claimed. The SCALIBR probe was
  not modified or rerun.
