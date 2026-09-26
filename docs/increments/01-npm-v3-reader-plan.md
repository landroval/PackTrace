# npm v3 reader implementation plan

> **For agentic workers:** Use `superpowers:executing-plans` for inline execution.
> Await plan approval and explicit execution authorization before changing code.

**Goal:** Deliver the approved in-memory npm v3 reader and regression tests.
**Architecture:** One internal package; validation precedes raw-field projection.
No CLI, filesystem adapter, general parser framework, or external dependencies.
**Tech stack:** Go standard library, `testing`, `go vet`, existing jj workspace.
**Spec:** [Approved reader specification](01-npm-v3-reader.md).

## Constraints

- Go module floor 1.27.1; use the available local Go for development and record its
  version. Do not download/change toolchains or claim release qualification.
- No network, external dependencies, real project inputs, or native probe execution.
- Input limit 64 MiB; maximum 128 nested containers, counting the root object.
- Errors carry category only; never echo raw values or package names.
- Preserve current docs, local todos, and the separate SCALIBR module unchanged.
- Work inline in the current jj workspace; commit only the files listed below.

## Files and interface

Create only these production/test files:

- `go.mod`: `module packtrace`, `go 1.27.1`; no dependencies.
- `internal/inventory/npmlock.go`: reader, input validation, controlled errors.
- `internal/inventory/npmlock_test.go`: synthetic regression and boundary tests.

```go
type Document struct {
    SHA256   [32]byte
    Fields   map[string]json.RawMessage
    Packages map[string]map[string]json.RawMessage
}

type ParseError struct { Code string }
func (e *ParseError) Error() string { return "npm v3: " + e.Code }
```

Produce `ParseNPMLockV3(data []byte) (Document, error)`. On failure return the zero
`Document`. Error codes: `invalid-json`, `duplicate-key`, `limit-exceeded`,
`unsupported-version`, `invalid-shape`. Values retained as raw JSON are not public
report output. Their ownership is independent of the input slice.

## Review focus

- Escaped duplicate names (`"a"` and `"\u0061"`) must not overwrite each other.
- Large/precise unknown numbers must survive; use `Decoder.UseNumber` in validation.
- Literal escaped backslashes are not Unicode escapes; valid surrogate pairs pass.
- Null versus missing versus empty objects must remain distinguishable.
- Length/depth limit boundaries and post-parse input mutation need explicit tests.

## Single task: validated, field-preserving reader

- [ ] Create the module and failing tests first. Initial smoke test:

```go
func TestParseNPMLockV3(t *testing.T) {
    src := []byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.2.3","future":null}}}`)
    doc, err := ParseNPMLockV3(src)
    if err != nil { t.Fatal(err) }
    if doc.SHA256 != sha256.Sum256(src) { t.Fatal("wrong input digest") }
    if string(doc.Packages["node_modules/a"]["future"]) != "null" {
        t.Fatal("unknown/null field lost")
    }
}
```

  Add table cases for the spec's acceptance items and the five review-focus
  classes. Assert exact error categories and a zero result on rejection. Include
  v3 root/nested/link/alias records and retained dependency groups, flags, URLs,
  integrity strings, nulls, and unknown fields. Test `{}` packages successfully;
  reject missing/null/array packages and non-object entries. Reject version `2`,
  missing/string/fractional version values, trailing data, malformed input,
  invalid UTF-8, lone high/low surrogate escapes, and duplicate nested keys.
  Build valid JSON padded to exactly 64 MiB and one byte over; test total container
  depths 128 and 129. Mutate the source after success and compare retained fields.

- [ ] Run the tests and record the expected failure because the reader is absent.

- [ ] Implement in this order: check byte length; check UTF-8 and JSON syntax;
  validate escaped surrogate pairing without mistaking escaped backslashes for
  escapes; walk tokens with `UseNumber`, object-local decoded-key sets, and bounded
  recursion to enforce duplicate/depth rules. Then decode top-level raw fields,
  require integer version 3, decode non-null packages and non-null object entries,
  and compute the original-byte SHA-256. Use `encoding/json` raw-value copies, not
  slices into caller-owned input. Do not interpret versions, URLs, or paths.
  Treat missing/wrongly typed required fields as `invalid-shape`; an integer
  lockfile version other than 3 is `unsupported-version`.

- [ ] Run tests, format the two Go files, and run vet. Nushell commands:

```nu
with-env {GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: '0'} { go test ./... }
gofmt -w internal/inventory/npmlock.go internal/inventory/npmlock_test.go
with-env {GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: '0'} { go test ./... }
with-env {GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: '0'} { go vet ./... }
```

- [ ] Review the diff against every spec requirement. Recheck malformed/Unicode,
  duplicate-key, and boundary cases; confirm no dependency, target I/O, or scanner
  support claim was introduced. No independent subagent review is implied.
- [ ] Commit only `go.mod` and the two Go files with jj. Report red/green evidence,
  test/vet results, development toolchain, and remaining native/release limitations.

## Execution boundary

This plan does not authorize execution by itself. Approval may explicitly authorize
inline creation of these files and local synthetic tests, without any downloads,
runner provisioning, or changes to the existing probe. Otherwise stop for review.
