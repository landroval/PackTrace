# Issue 12: OSV header implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:executing-plans`
> for the selected inline workflow. Plan approval and explicit execution authorization
> remain pending; do not implement from this draft.

**Goal:** project exact ID/schema evidence and the bounded v1-header interpretation.
**Architecture:** one in-memory function reuses existing intel string/shape helpers.
A private canonical-core regexp avoids integer conversion; absent source evidence
is distinct from implicit v1 interpretation. No readers or shared types change.
**Tech stack:** current Go module, standard library (`regexp`, `strings`).
**Spec:** [approved header contract](issue-12-osv-header.md).

## Global constraints

- Only new `internal/intel/osv_header.go` and `internal/intel/osv_header_test.go`.
- Consume unchanged successful OSVDocument with no concurrent mutation; basic guard
  behavior is not authentication or repair of forged documents/digests.
- Preserve exact source digest, ID/schema strings/states and raw sibling fields.
- Missing schema alone defaults to implicit v1; null/empty/type/unsupported text never defaults.
- Canonical ASCII numeric core major 1 -> declared v1; other canonical major ->
  unsupported; outside profile (including valid SemVer suffixes) -> unknown.
- Header interpretation is not full schema conformance, matching eligibility, trust,
  activity, freshness, ID qualification or safe path/URL interpretation.
- Existing 4 MiB/depth-128 reader limits; no new quota or numeric conversion/RSS guarantee.
- No dependencies, network, target inputs, native/producer qualification, probes,
  source reader changes or worker/report/CLI integration.
- Current jj workspace, GitHub #12 live coordination, inline implementation review;
  an agreed second-person PR review is required before integration.

## Review focus

1. Null/empty schema must not silently inherit the absent-schema 1.0.0 default.
2. A valid SemVer suffix is outside this profile, not automatically an unsupported major.
3. Exact matching must reject a trailing newline; canonical huge digits must not overflow.
4. Explicit 1.0.0 and inferred default remain different source claims; supported state
   cannot imply eligibility or make source fields disappear.
5. Input/output snapshot and mutation checks must establish ownership, not shallow-copy equality.

## Task 1: implement the bounded header projection

**Create:** `internal/intel/osv_header.go`, `internal/intel/osv_header_test.go`.
**Consumes:** OSVDocument, OSVString, OSVFieldState, ParseError and private
`projectOSVString(fields map[string]json.RawMessage, key string) OSVString` unchanged.
**Produces:** spec-defined OSVHeaderSchemaState constants, OSVHeader and
`ProjectOSVHeader(doc OSVDocument) (OSVHeader, error)`.

- [ ] **Write reader-valid synthetic tests first.** Use ParseOSVRecord directly or
  a private test helper that builds a minimum id/modified envelope and inserts raw
  schema text only when supplied. One first assertion:

```go
doc, err := ParseOSVRecord([]byte(`{"id":"TEST","modified":"uninterpreted"}`))
if err != nil { t.Fatal(err) }
got, err := ProjectOSVHeader(doc)
want := OSVHeader{
    SourceSHA256: doc.SHA256,
    ID: OSVString{State: OSVFieldValue, Value: "TEST"},
    SchemaVersion: OSVString{State: OSVFieldAbsent},
    Schema: OSVHeaderSchemaV1Implicit,
}
if err != nil || !reflect.DeepEqual(got, want) {
    t.Fatal("implicit schema erased source absence", got, err)
}
```

  Add table cases for all spec examples and explicit 1.0.0, 1.9.1, future v1 minor/
  patch, 0/2/huge majors, null, boolean/number/object/array, empty/space, prefix/sign,
  leading-zero components, missing/extra parts, non-ASCII digits and trailing LF/CRLF.
  Include unknown suffixes for major 1 and major 2 to pin profile-before-major handling.
  Test large canonical components using strings.Repeat without exceeding the reader cap.
- [ ] **Observe compile RED, then behavioral RED.** Run focused tests; expect missing
  function/types. Add only the exact spec types/constants plus a zero-result stub,
  rerun and require runtime failures on missing state/digest/evidence before logic.
- [ ] **Add ownership/error/compatibility cases before behavior.** Verify exact decoded
  escaped ID/schema keys and values, whitespace/nonstandard ID text, preserved raw
  affected/extensions/null/uninterpreted sibling fields and original SHA-256.
  Serialize source/output before projection/input mutations; mutate raw bytes/map/digest,
  compare output snapshot, then mutate output fields and confirm source unchanged.
  Nil Fields must satisfy errors.As with intel invalid-shape and zero OSVHeader.
  Reader-rejected ID shapes remain existing reader tests, not a weaker second validator.
- [ ] **Implement minimal logic** after behavioral RED, using the spec type definitions
  already introduced. The canonical check has absolute end anchoring:

```go
var osvHeaderCorePattern = regexp.MustCompile(
    `\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z`,
)

func ProjectOSVHeader(doc OSVDocument) (OSVHeader, error) {
    if doc.Fields == nil {
        return OSVHeader{}, &ParseError{Code: "invalid-shape"}
    }
    result := OSVHeader{
        SourceSHA256: doc.SHA256,
        ID: projectOSVString(doc.Fields, "id"),
        SchemaVersion: projectOSVString(doc.Fields, "schema_version"),
    }
    schema := result.SchemaVersion
    if schema.State == OSVFieldAbsent {
        result.Schema = OSVHeaderSchemaV1Implicit
    } else if schema.State == OSVFieldValue && osvHeaderCorePattern.MatchString(schema.Value) {
        if strings.HasPrefix(schema.Value, "1.") {
            result.Schema = OSVHeaderSchemaV1Declared
        } else {
            result.Schema = OSVHeaderSchemaUnsupported
        }
    }
    return result, nil
}
```

  This does not trim, coerce, parse integers, reject unusable schema siblings or
  fabricate an effective declared schema value. Unknown is the zero interpretation.
  Add comments stating the narrow profile and unchanged-document precondition.
- [ ] **Format and run focused/root verification.** Expected focused tests pass;
  all prior readers/projections/Bun tests and root vet pass. Verify previous Go files,
  go.mod and probes byte-identical to the approved task base; no go.sum appears.
- [ ] **Review and reverify.** Inline diff/spec review checks every table branch,
  absolute anchoring, arbitrary-size digits, source/derived-state separation and
  ownership. Rerun fresh full tests/vet afterward; record actual counts/toolchain.
  Independent PR review remains a separate human gate; never claim it occurred inline.
- [ ] **Commit only the two Go files**, then record verification separately in the
  spec/plan and nested product milestone. Publish only the authorized issue bookmark
  and update the issue/draft PR in first person, using Refs #12 until complete acceptance.
  Do not clear #13/#14 blockers or mark Done until reviewed implementation integration.

## Commands (Nushell)

```nu
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 -run TestProjectOSVHeader ./internal/intel
}
```

Run this during RED expecting the missing API, then behavioral failures; do not commit
production logic until that behavioral gate is observed. GREEN verification:

```nu
gofmt -w internal/intel/osv_header.go internal/intel/osv_header_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go version
    go test -count=1 ./...
    if $env.LAST_EXIT_CODE != 0 { error make { msg: "Root tests failed" } }
    go vet ./...
    if $env.LAST_EXIT_CODE != 0 { error make { msg: "go vet failed" } }
}
jj commit -m "feat: project OSV header evidence" internal/intel/osv_header.go internal/intel/osv_header_test.go
```

Only commit after verification succeeds. Downloads, new dependencies, target access,
publication beyond the approved task and native/producer qualification remain excluded.
