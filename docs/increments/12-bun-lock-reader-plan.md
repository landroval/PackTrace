# Bun text lockfile reader implementation plan

> Plan submitted for review together with its implementation in the same pull
> request. Executed with local synthetic tests only. No downloads, new dependencies,
> Bun execution, or native probes are authorized by this plan.

**Goal:** Deliver the in-memory `bun.lock` reader and regression tests described
in the specification.
**Architecture:** Two unexported steps inside `internal/inventory`: a
length-preserving JSONC normalizer, then the existing `jsoninput.Object`
validation followed by Bun-specific shape checks. No CLI, filesystem adapter,
tuple interpretation, or external dependencies.
**Tech stack:** Go standard library, `testing`, `go vet`.
**Spec:** [Bun text lockfile reader specification](12-bun-lock-reader.md).

## Constraints

- Go module floor 1.27.1; use the available local toolchain for development and
  record its version. Do not claim release qualification.
- No network, external dependencies, real project inputs, Bun execution, or native
  probe execution. Fixtures are synthetic byte literals only.
- Input limit 64 MiB, checked on the original bytes; maximum 128 nested
  containers, counting the root object.
- Errors carry category only; never echo raw values or package names.
- Do not change `npmlock.go`, `manifest.go`, their tests, `internal/jsoninput`,
  or the SCALIBR probe.

## Files and interface

Create only these production/test files:

- `internal/inventory/jsonc.go`: unexported JSONC normalizer.
- `internal/inventory/jsonc_test.go`: normalizer acceptance and rejection tables.
- `internal/inventory/bunlock.go`: reader and Bun shape checks.
- `internal/inventory/bunlock_test.go`: reader regression and boundary tests.

```go
// BunLockDocument contains locked, uninterpreted Bun evidence.
type BunLockDocument struct {
    SHA256     [32]byte
    Fields     map[string]json.RawMessage
    Workspaces map[string]json.RawMessage
    Packages   map[string]json.RawMessage
}

func ParseBunLock(data []byte) (BunLockDocument, error)

func normalizeJSONC(data []byte) ([]byte, bool)
```

Reuse the existing `ParseError` (`inventory: CODE`) and error codes:
`invalid-json`, `duplicate-key`, `limit-exceeded`, `unsupported-version`,
`invalid-shape`. On failure return the zero `BunLockDocument`. `normalizeJSONC`
returns a new slice of the same length, or `false` for JSONC syntax it rejects;
`ParseBunLock` maps that to `invalid-json`.

## Review focus

- Comment and comma handling must never alter bytes inside strings, including
  escaped quotes and escaped backslashes before a closing quote.
- A comma is removable only after a value and before `}` or `]`; `{,}`, `[,]`,
  `[1,,]`, and leading commas are rejected rather than repaired.
- Normalization preserves length and line breaks, so offsets remain comparable.
- The digest covers the original bytes, not the normalized bytes.
- Duplicate keys hidden between comments are still rejected by `jsoninput`.
- `lockfileVersion` accepts only the integer literals `0`–`3`.

## Task 1: JSONC normalizer

- [x] Write failing tests first in `jsonc_test.go`:
  - Accepted inputs compared byte-for-byte with expected normalized output:
    line and block comments, trailing commas in objects and arrays, a comment
    between a trailing comma and its closing bracket, CRLF line endings, and
    strings containing `//`, `/*`, `,}`, `\"`, and `\\`.
  - Output length always equals input length; every `\n` and `\r` stays in place.
  - Rejected inputs: `{,}`, `[,]`, `[1,,]`, `[,1]`, `{"a":1,,}`, `/* open`,
    a lone `/`, and `/` followed by any byte other than `/` or `*`.
- [x] Run the tests and record the expected failure because `normalizeJSONC` is
  absent.
- [x] Implement a single pass that tracks whether it is inside a string, whether
  the previous byte was an escape, the last significant byte outside comments,
  and the position of a pending comma:
  - Inside a string, copy bytes unchanged and end the string only on an
    unescaped `"`.
  - Outside a string, replace `//` comments through the end of the line and
    `/* */` comments with spaces, keeping `\n` and `\r`.
  - On `,`, reject when no value precedes it (`{`, `[`, `,`, `:`, or start of
    input); otherwise remember its position.
  - On `}` or `]` with a pending comma, replace that comma with a space. Any
    other significant byte clears the pending comma.
- [x] Run the tests until they pass.

## Task 2: Bun lockfile reader

- [x] Write failing tests first in `bunlock_test.go`, following the table style
  of `npmlock_test.go`:
  - One document per version `0`–`3` with root and non-root workspaces,
    registry, GitHub, folder, link, workspace, and root package tuples, comments,
    trailing commas, and unknown top-level fields; assert that fields,
    workspaces, and package arrays are retained exactly as normalized raw JSON.
  - Digest equals `sha256.Sum256` of the original bytes, and later mutation of the
    input does not change the returned document.
  - Rejections with exact categories: missing, string, null, `1.0`, `1e0`,
    negative, and `4` versions; missing, null, array, and scalar `workspaces` and
    `packages`; non-object workspace records; non-array package entries; `null`,
    array, and scalar roots; malformed and trailing input; invalid JSONC syntax;
    duplicate keys, including escaped aliases and duplicates separated by
    comments; invalid UTF-8 and unpaired surrogates.
  - Exact 64 MiB and 128-depth boundaries accepted; one byte and one level over
    rejected with `limit-exceeded`. Errors never contain input values.
- [x] Run the tests and record the expected failure because `ParseBunLock` is
  absent.
- [x] Implement in this order: reject input over 64 MiB; normalize JSONC; call
  `jsoninput.Object` on the normalized bytes with the same limit; require an
  integer-literal `lockfileVersion` in `0`–`3`; decode `workspaces` into non-null
  object values and `packages` into non-null array values; compute the SHA-256 of
  the original input. Reuse `integerLiteral`. Do not interpret tuples.
- [x] Run the tests until they pass.

## Task 3: Verification

- [x] Format the four Go files and run the root checks:

```sh
gofmt -l internal/inventory
GOPROXY=off GOWORK=off CGO_ENABLED=0 go test -count=1 ./...
GOPROXY=off GOWORK=off CGO_ENABLED=0 go vet ./...
```

- [x] Review the diff against every specification requirement. Confirm that no
  dependency, disk or network access, tuple interpretation, or scanner support
  claim was introduced, and that existing tests still pass unchanged.
- [x] Commit only the four Go files as one scoped commit. Report red/green
  evidence, test/vet results, the development toolchain, and remaining
  qualification limits.

## Execution boundary

This plan covers only the files listed above. It does not authorize downloads,
new dependencies, Bun execution, producer-generated fixtures, or changes to the
existing probe.

## Execution evidence

- RED: `go test` failed to build because `normalizeJSONC` did not exist, then again
  because `ParseBunLock` did not exist, before each implementation was written.
- GREEN: implementation in `38c2961` (769 root tests/subtests). Parent review then
  found that a block comment opened by `/*/` closed itself, exposing bytes that Bun
  treats as comment text. Two failing regression cases were added first; the fix
  starts the closing search after the opener. 771 tests/subtests passed.
- Independent local review (reliability lens) approved the change with advisory test
  gaps: the `escaped-duplicate` case did not use an escaped key, and no case covered
  an escaped backslash before a closing quote. Commit `9433a48` fixes both, adds an
  escaped-quote case, and aligns package fixtures with Bun's tuple shapes from its
  source. Final result: 773 root tests/subtests, `go vet`, and `gofmt -l` clean.
- Mutation checks: replacing the escape skip with a single-byte step, or detecting
  escaped quotes by the previous byte only, each fails a normalizer test.
- Remaining advisory suggestions, deferred: normalizer cases for an unterminated
  string and a trailing backslash (or a fuzz target), and exact assertions for the
  normalized `workspaces` value in `Fields`.
- Development toolchain: `go1.27.1 darwin/arm64` with `GOPROXY=off`, `GOWORK=off`,
  and `CGO_ENABLED=0`; no release qualification claimed. The SCALIBR probe was not
  modified or rerun.
