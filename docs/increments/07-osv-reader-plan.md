# Bounded OSV reader implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:executing-plans`
> for approved inline execution. User approved this plan and explicitly authorized
> the four Go files, offline synthetic verification, and scoped code/docs commits.

**Goal:** retain bounded advisory JSON evidence without qualifying it for matching.
**Architecture:** move existing strict object validation to one internal shared
package. Product readers translate category-only failures into their own existing
or new controlled errors. OSV adds only minimum-envelope checks and original hashing.
**Tech stack:** current Go module, standard library only.
**Spec:** [approved OSV-reader specification](07-osv-reader.md).

## Global constraints

- OSV input at most 4 MiB; fixed JSON depth 128; exact bytes included in digest.
- Required `id`/`modified` are nonempty strings, without trimming/date/ID interpretation.
- Preserve raw optional, invalid-looking, unknown, withdrawn, and affected data;
  successful reading is not schema/semantic/matching qualification.
- Keep all inventory APIs, limits, error types/messages and tests unchanged.
- No network, external dependencies, target access, probe changes, or native qualification.
- Use current jj workspace and file-backed ledger; inline review, scoped commits only.

## Review focus

1. Moving validation must not change duplicate-key, depth, surrogate, or error precedence.
2. Error categories cannot contain source text or raw decoder diagnostics.
3. Missing/malformed affected data cannot become an empty affected set or a no-match claim.
4. Schema versions/date text/ID spelling remain uninterpreted, even when apparently invalid.
5. Limits include whitespace; maximum-size and maximum-depth inputs must actually hit boundaries.

## Task 1: share strict decoding and add the advisory reader

**Create:** `internal/jsoninput/object.go`, `internal/intel/osv.go`,
`internal/intel/osv_test.go`.
**Modify:** `internal/inventory/npmlock.go` only.
**Consumes:** current `parseJSONFields`, `validateValue`, `validSurrogates` behavior.
**Produces:** the approved intel API and shared
`jsoninput.Object(data []byte, byteLimit int) (map[string]json.RawMessage, string)`.
The second result is empty on success, otherwise one of the four controlled JSON
categories. No typed-nil/error conversion or raw diagnostic strings are needed.

- [x] Write intel tests first. A preservation assertion starts with:

```go
src := []byte(`{"id":"TEST-1","modified":"not-a-date","schema_version":"future","affected":null,"future":9007199254740993}`)
doc, err := ParseOSVRecord(src)
if err != nil || doc.SHA256 != sha256.Sum256(src) ||
    string(doc.Fields["future"]) != "9007199254740993" ||
    string(doc.Fields["affected"]) != "null" {
    t.Fatal("raw evidence changed or semantically interpreted", err)
}
```

  Add realistic-shaped fields (ranges/events, withdrawal, aliases, references,
  extensions); verify every raw field and ownership after input mutation. Test
  escaped names, supplementary Unicode, large/exponent numbers, empty and non-object
  input, each required field missing/null/empty/wrong-type, whitespace-only strings,
  unsupported-looking schema and malformed optional data. Test malformed/trailing
  JSON, comments/commas, invalid UTF-8, nested/escaped duplicate keys and unpaired
  surrogates. Errors must be `*intel.ParseError`, exact `intel: CODE`, zero document.
- [x] Add exact size fixtures by padding a valid minimum envelope with spaces to
  `4 << 20`, then one byte beyond. Build a root object with 127 nested arrays (128
  containers total), then 128 arrays; also verify much deeper data reports the
  application limit rather than the decoder's later syntax/depth error.
- [x] Run focused tests with no implementation, observing missing symbols. Add only
  OSVDocument/ParseError types and a zero-result ParseOSVRecord stub, then rerun to
  observe behavioral RED before moving any production validation.
- [x] Move the existing object decoder and its two validation helpers into
  `internal/jsoninput/object.go`. Retain imports `bytes`, `encoding/json`, `io`,
  `strconv`, `unicode/utf8`, and the fixed private depth constant. Rename the entry
  point `Object`. Mechanically translate controlled errors to category strings:
  helper `validateValue` returns `string`; success is `""`, category failures use
  the same literal codes. Retain token traversal/UseNumber, post-validation surrogate
  checks, full EOF/object checks, and their ordering. Preserve `validSurrogates` unchanged.
- [x] Remove only moved implementation/imports/depth constant from inventory; keep
  `integerLiteral`, lockfile parsing, ParseError, and byte bound. Replace its private
  decoder body with:

```go
fields, code := jsoninput.Object(data, byteLimit)
if code != "" { return nil, &ParseError{Code: code} }
return fields, nil
```

- [x] Implement intel document/error definitions from the specification and the
  following reader; local `maxOSVRecordBytes = 4 << 20` and error prefix `intel: `:

```go
fields, code := jsoninput.Object(data, maxOSVRecordBytes)
if code != "" { return OSVDocument{}, &ParseError{Code: code} }
for _, key := range []string{"id", "modified"} {
    var value string
    if err := json.Unmarshal(fields[key], &value); err != nil || value == "" {
        return OSVDocument{}, &ParseError{Code: "invalid-shape"}
    }
}
return OSVDocument{SHA256: sha256.Sum256(data), Fields: fields}, nil
```

  No semantic fields, classification flags, or parsed timestamps are added.
- [x] Format the four files. Run focused intel tests, all root tests and vet. Inspect
  both callers of shared decoding and compare moved validation against its old body;
  check imports, error mappings, raw ownership and unchanged inventory tests. Rerun
  full tests/vet after inline review. No independent-review claim.
- [x] Commit only the four Go files; separately record results and a nested milestone
  without closing any shipping/native/matching parent. Close the task ledger.

## Commands (Nushell)

```nu
gofmt -w internal/jsoninput/object.go internal/intel/osv.go internal/intel/osv_test.go internal/inventory/npmlock.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 ./internal/intel
    go test -count=1 ./...
    go vet ./...
}
jj commit -m "feat: read bounded OSV record evidence" internal/jsoninput/object.go internal/intel/osv.go internal/intel/osv_test.go internal/inventory/npmlock.go
```

Check every verification exit before committing. Shared validation is exercised
through the real inventory/intel entry points; no duplicated validator or new test
framework is required. Go module requirements and nested probe modules stay unchanged.

## Execution evidence

- RED: missing API/types caused compile failure; with definitions plus a zero-result
  stub, all 51 new tests/subtests failed at runtime before behavior/extraction work.
- GREEN: 51 intel and 297 unchanged inventory tests/subtests pass (348 total), plus
  root `go vet`. Full root tests/vet rerun after inline review. Shared jsoninput has
  no standalone test file; validation is exercised through both domains' readers.
- Mechanical source comparison against plan base `5df5c0e8` confirmed identical
  `ParseNPMLock`, `integerLiteral`, and `validSurrogates` functions. Shared decoder
  and recursive validator differ only by approved entry-point/return-category
  translation. All old inventory test files are byte-identical to the base.
- Caller check: inventory adapter and intel reader each invoke `jsoninput.Object`;
  one recursive/depth/surrogate implementation remains. Error prefixes remain
  inventory-specific and intel-specific without leaking raw diagnostics.
- Maximum size/depth, category privacy, raw preservation, minimum-envelope rejection,
  uninterpreted optional data, and owned output tested with synthetic inputs only.
- Offline flags above; existing development toolchain `go1.27.1-X:nodwarf5 linux/amd64`.
  `go list -m all` returns only `packtrace`. Review inline, not independent.
- Code commit `4e8155f5`: exactly four approved files, including new intel reader
  (40 lines), tests (163), and shared decoder (118). No downloads, real advisory
  imports, new dependencies, target reads, native probes, or platform qualification.
