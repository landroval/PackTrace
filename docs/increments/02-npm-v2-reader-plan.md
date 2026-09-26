# npm v2/v3 reader implementation plan

> **For agentic workers:** use `superpowers:executing-plans` for approved inline
> execution. The user approved the plan and explicitly authorized inline execution
> in the current jj workspace, local synthetic tests/vet, and scoped code/docs commits.

**Goal:** extend the existing byte reader to npm lockfile versions 2 and 3.
**Architecture:** reuse its validation and raw projection; one internal entry
point, no new models or compatibility wrappers.
**Tech stack:** existing Go 1.27.1 module, standard library only.
**Spec:** [approved increment-2 specification](02-npm-v2-reader.md).

## Global constraints

- No filesystem/network access by the reader; synthetic local tests only.
- Keep `Document` and `ParseError.Code`; change only the entry-point name,
  accepted versions, and error prefix described in the spec.
- Preserve original-byte SHA-256, owned raw values, exact decoded keys, precision,
  unknown/null fields, whole-input validation, and zero documents on errors.
- Keep 64 MiB and 128-container bounds, without claiming RSS/runtime guarantees.
- No downloads, new dependencies, native probes/runners, SCALIBR changes, or
  producer/native qualification. No permission for further increments.
- Use jj; preserve and exclude `.pi/todos` changes from scoped commits.

## Review focus

Tests below explicitly cover these failure modes:

1. Legacy records contradict package-location records: retain both, merge neither.
2. Legacy data exists without valid `packages`: reject; never reconstruct locations.
3. Legacy data is absent/null/non-object: retain that distinction, not an inferred graph.
4. Nested legacy data contains ambiguous keys or Unicode: whole-document rejection.
5. A new version bypasses existing security checks: exercise both versions, including
   exact input-size/depth boundaries and mutation-after-return ownership checks.

## Task 1: extend the shared reader

**Modify:** `internal/inventory/npmlock.go` and `internal/inventory/npmlock_test.go`.
No `go.mod` change or new production file is needed.

**Consumes:** the existing `Document`/`ParseError` and reader implementation.
**Produces:** `func ParseNPMLock(data []byte) (Document, error)` for versions 2/3.

- [x] Add a v2 preservation test against the existing entry point before renaming
  it. Start with this independent conflicting fixture and assertions:

```go
func TestParseNPMLockV2PreservesLegacy(t *testing.T) {
    const legacy = `{"a":{"version":"9.0.0","resolved":"legacy-source","integrity":"legacy-digest","dependencies":{"b":{"version":"2.0.0"}}},"legacy-only":{"version":"4.0.0"}}`
    src := []byte(`{"lockfileVersion":2,"packages":{"node_modules/a":{"version":"1.0.0","resolved":"package-source","integrity":"package-digest"},"node_modules/packages-only":{}},"dependencies":` + legacy + `}`)
    doc, err := ParseNPMLockV3(src)
    if err != nil { t.Fatal(err) }
    if string(doc.Fields["dependencies"]) != legacy { t.Fatal("legacy tree changed") }
    if len(doc.Packages) != 2 || string(doc.Packages["node_modules/a"]["version"]) != `"1.0.0"` {
        t.Fatal("legacy tree merged into packages")
    }
    if string(doc.Packages["node_modules/a"]["resolved"]) != `"package-source"` ||
        string(doc.Packages["node_modules/a"]["integrity"]) != `"package-digest"` {
        t.Fatal("legacy tree overwrote package evidence")
    }
    if doc.SHA256 != sha256.Sum256(src) { t.Fatal("digest changed") }
    before, err := json.Marshal(doc)
    if err != nil { t.Fatal(err) }
    for i := range src { src[i] = 'x' }
    after, err := json.Marshal(doc)
    if err != nil || !bytes.Equal(before, after) { t.Fatal("input aliases result") }
}
```

- [x] Update the old v2-rejection case to version 1 and add version 4. Generalize
  existing v3 fixtures to both versions using small version loops, not a new test
  framework. Keep independent expectations and all existing rejection assertions.
  Change the helper's expected error prefix to `npm lockfile: `.
- [x] Add these exact legacy/version cases to the tables:

| Input condition | Expected |
| --- | --- |
| `dependencies` absent, `null`, `[]`, `42` with valid `packages` | success; preserve each distinction |
| legacy object with missing, null, or array `packages` | `invalid-shape`; zero document |
| legacy value `{"a":{"dependencies":{"b":{},"\u0062":{}}}}` | `duplicate-key`; zero document |
| legacy value `{"a":{"version":"\uD800"}}` | `invalid-json`; zero document |
| `lockfileVersion` equal to `"2"`, `2.0`, `2e0` | `invalid-shape`; zero document |

  For successful opaque legacy cases, assert both raw value/presence and empty
  `Packages`, proving no fabricated installed/location records. Exercise size and
  nesting acceptance/rejection for v2 and v3 as well as the existing ownership,
  Unicode, duplicate-key, and trailing-input checks.
- [x] Run the tests with the offline environment below. Observe runtime failures:
  the existing parser rejects valid v2 fixtures with `unsupported-version`, and
  errors still have the old prefix. This is behavioral RED, not just missing symbols.
- [x] Rename the production entry point and migrate every test caller. Keep the
  validator/projection unchanged; replace only the version guard and prefix:

```go
func (e *ParseError) Error() string { return "npm lockfile: " + e.Code }
// Inside ParseNPMLock, after the existing integerLiteral check:
if string(version) != "2" && string(version) != "3" {
    return Document{}, &ParseError{Code: "unsupported-version"}
}
```

- [x] Format both files, run the complete root suite and vet, and inspect the diff
  against the spec. Confirm no old production entry point remains, no new module
  requirements, and no probe files changed. Review is inline, not independent.
- [x] Commit only the two Go files with jj. Then record evidence and approvals in
  these increment documents and add only a nested shipping-checklist milestone;
  do not check the parent npm-support item. Commit that documentation separately.

## Commands (Nushell)

Use the same existing local toolchain; its custom build is development evidence,
not official release qualification. RED uses `-run TestParseNPMLockV2PreservesLegacy`;
GREEN runs the full suite:

```nu
gofmt -w internal/inventory/npmlock.go internal/inventory/npmlock_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 ./...
    go vet ./...
}
jj commit -m "feat: extend lockfile reader to npm v2" internal/inventory/npmlock.go internal/inventory/npmlock_test.go
```

Record actual test results and toolchain;
do not run the separate SCALIBR module or treat historical probe failures as root
module failures. Stop on unexpected failures and diagnose before proceeding.

## Execution evidence

- RED: with the original production reader unchanged, the new v2 legacy fixture
  failed with `unsupported-version`; the selected v3 error case failed its new
  neutral-prefix assertion. A test-source typo was fixed before behavioral RED.
- GREEN: 103 passing tests/subtests in the root suite; `go vet ./...` passed.
  Final verification reran both successfully; `go list -m all` listed only
  `packtrace`. No old entry point remains in production/tests.
- Development toolchain: `go1.27.1-X:nodwarf5 linux/amd64`, offline environment as
  above. No downloads, native qualification, or SCALIBR probe changes/execution.
- Inline diff/spec review: four production lines changed; existing generic
  validation and projection were reused unchanged. Review was not independent.
- Scoped implementation commit: `957f6f08`. Local `.pi/todos` state was excluded.
