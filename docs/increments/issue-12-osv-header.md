# Issue 12: OSV header evidence and bounded v1 interpretation

Status: written specification approved, including the bounded v1-header profile.
[Implementation-plan](issue-12-osv-header-plan.md) approval and explicit production
execution authorization remain pending. Tracking: [issue #12](https://github.com/landroval/PackTrace/issues/12).
Authority: [design decisions](../design-decisions.md).

## Goal and current boundary

Provide a small in-memory header projection that downstream identity and event
qualification can consume without mistaking reader success or a schema declaration
for a valid, authentic, active or matchable advisory.

The [existing reader](07-osv-reader.md) establishes strict JSON and nonempty string
`id`/`modified`, not full OSV conformance. Existing temporal and affected projections
remain unchanged. This task records `id` and `schema_version` and interprets only
an explicitly bounded schema-header profile; it does not qualify matching.

## Source and interpretation policy

Reviewed upstream reference: [OSV schema 1.9.1, pinned commit
8e3305dedc0786c4869c7bb0b14564e03ec277b3](https://github.com/ossf/osv-schema/blob/8e3305dedc0786c4869c7bb0b14564e03ec277b3/docs/schema.md#schema_version-field).
The reference says `schema_version` follows SemVer 2.0.0 without a leading `v`,
that an unspecified version defaults to `1.0.0`, and that new minor/patch versions
add fields without changing old field meanings. `id` has a database-specific
identifier format, which is **not** validated in this task.

PackTrace deliberately supports a narrower header interpretation than full SemVer:

- A missing `schema_version` yields a separately identified implicit v1 header.
  Do not fabricate a declared string or replace the absent source state.
- An explicit canonical numeric core `MAJOR.MINOR.PATCH` is inspectable under this
  profile. Each component is ASCII `0` or starts with `1`–`9` followed by zero or
  more ASCII digits. No leading zeros, whitespace, signs, prefixes or omitted parts.
- Major exactly `1` yields a declared v1-header interpretation. Minor/patch values
  are not capped at the reviewed document version; this follows the additive-field
  rule for **this narrow header**, not qualification of future field semantics.
- Any other canonical numeric major yields an unsupported header major. That is
  a PackTrace support boundary, not a claim that the document is invalid OSV.
- Null, wrong type, empty string and every string outside the profile yield unknown
  header interpretation. Preserve their source states/content independently.
  Prerelease/build suffixes can be valid SemVer but are **uninterpreted here**,
  not automatically invalid or an unsupported major.
- Only **absence** defaults. Null, empty or malformed values never inherit v1.

Do not parse components into fixed-width integers. Arbitrarily long canonical
components within the existing reader bound remain representable without overflow.
This is a bounded lexical header check, not package-version parsing or comparison.

## Internal interface

Reuse the existing `OSVString`, `OSVFieldState`, `projectOSVString` and `ParseError`
without changing their signatures or moving them. New types and function:

```go
type OSVHeaderSchemaState uint8

const (
    OSVHeaderSchemaUnknown OSVHeaderSchemaState = iota
    OSVHeaderSchemaV1Implicit
    OSVHeaderSchemaV1Declared
    OSVHeaderSchemaUnsupported
)

type OSVHeader struct {
    SourceSHA256 [32]byte
    ID, SchemaVersion OSVString
    Schema OSVHeaderSchemaState
}

func ProjectOSVHeader(doc OSVDocument) (OSVHeader, error)
```

These are internal evidence types, not public report/IPC fields. `Schema` describes
only this header profile; none of its values establish full advisory conformance.

## Projection, ownership and errors

- Consume an unchanged successful `ParseOSVRecord` result with no concurrent
  mutation. Do not authenticate/revalidate forged documents or supplied digests.
- Copy `doc.SHA256` into `SourceSHA256`. Project exact decoded `id` and
  `schema_version` strings using existing field-state behavior. String content,
  including empty/whitespace values, is not normalized or trimmed by the helper.
- On inspected fields, missing/null/nonstring/string produce absent/null/invalid-type/
  value. Only value retains string content. No absent field is replaced by a value.
- Classify the schema as above independently of the ID text. Nonempty but
  unfamiliar/whitespace-only ID text accepted by the reader stays exact evidence,
  not an authenticated identifier, filename, URL or database classification.
- Missing/null/empty/wrong-type ID cannot enter through a successful reader. Keep
  the existing reader rejection unchanged; do not weaken it or add a second full
  envelope validator. Basic guard behavior is not a forged-input security guarantee.
- Nil `doc.Fields` returns existing `ParseError{Code: "invalid-shape"}` with exact
  message `intel: invalid-shape` and a zero `OSVHeader`. Do not expose raw input or
  standard decoder diagnostics. Unusable schema values are states, not fatal errors.
- The projection never modifies the raw document. Its returned values must remain
  unchanged after later input mutation; output changes must not affect source data.
- Source locators are source digest plus exact top-level field name (`id` or
  `schema_version`). No normalized ID or cross-record deduplication is introduced.

## Work bounds and scope

Only two scalar fields and one lexical check are projected. Work scales with those
field bytes under the reader's existing **4 MiB / depth-128** document contract.
There is no new collection quota, integer parser, regex backtracking requirement,
external dependency or hard RSS guarantee. Large canonical components must be
handled without integer overflow, silent truncation or relaxed input syntax.

Planned production scope is only new `internal/intel/osv_header.go` and
`internal/intel/osv_header_test.go`. Existing Go files/readers/projections, Bun work,
shared JSON validation, root module and probe modules remain unchanged. If interface
review discovers a required shared change, revise scope before implementation.

## Examples and acceptance

Every example is accompanied by a reader-valid synthetic envelope with nonempty
`id` and `modified`; source strings remain distinct from derived interpretation.

| `schema_version` source | Field state | Header interpretation |
| --- | --- | --- |
| missing | absent | v1 implicit; source still absent |
| `"1.0.0"`, `"1.9.1"`, `"1.999.123"` | value, exact string | v1 declared |
| `"0.0.0"`, `"2.0.0"`, canonical huge major other than `1` | value, exact string | unsupported major |
| `null` | null | unknown |
| boolean/number/object/array | invalid-type | unknown |
| `""`, `" "`, `"v1.0.0"`, `"01.0.0"`, `"1.01.0"`, `"1.0.00"` | value, exact string | unknown |
| `"1.0"`, `"1.0.0 "`, `"1.0.0\n"`, signed or non-ASCII digits | value, exact string | unknown |
| `"1.0.0-rc.1"`, `"1.0.0+build"`, `"2.0.0-rc.1"` | value, exact string | unknown; outside the bounded profile |

Synthetic RED/GREEN tests must verify:

1. Every schema source state and the complete classification table, including
   exact matching (no trailing-newline acceptance), huge components and malformed
   component/prefix/suffix forms without numeric overflow.
2. Missing schema versus explicit `"1.0.0"` remain different source claims;
   supported header state never fabricates fields or erases raw extensions.
3. Exact escaped strings/keys, decoded ID whitespace/nonstandard spelling, original
   byte digest and raw unknown/null/conflicting sibling fields retained unchanged.
4. An unknown/unsupported schema does not lose the usable ID or turn the result into
   an error, negative matching claim, active advisory, freshness or trust decision.
5. Input/output independence via snapshots and subsequent raw/digest/output mutation;
   nil Fields yields controlled error/zero result. Existing ID-envelope rejections
   remain covered by unchanged reader regressions.
6. Fresh offline root tests and vet across all packages before/after review. Record
   toolchain and synthetic-only limitations. No producer/native/release claim follows.

## Coordination and completion

Remain **Preparation** while written specification, plan and explicit execution
approval are pending. Use an issue-specific branch/bookmark and draft PR; request
an agreed second-person review before integration. A specification PR uses
`Refs #12`, not `Closes #12`; documentation alone does not deliver the projection.

Do not clear #13/#14 dependency links merely because this draft is written or
approved. The header implementation and its acceptance need integration first;
those tasks retain their own approvals and must not treat header interpretation
as identity/range qualification.

## Exclusions

No full OSV or ID syntax validation, database namespace allowlist, publisher trust,
matching eligibility, origin confirmation, package-version SemVer, range evaluation,
withdrawal/freshness inference, aliases/classification, matching engine, network,
corpus/target access, dependencies/toolchains, native probes, storage publication,
CLI/reporting or release qualification. Plan approval and explicit production
execution authorization remain separate from approving this specification.
