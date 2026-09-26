# Increment 7: bounded OSV record reader

Status: specification and [implementation plan](07-osv-reader-plan.md) approved;
inline execution explicitly authorized and completed. Code `4e8155f5`; 348 root
tests/subtests and `go vet` pass. Reading does not qualify advisories for matching. Authority: [design decisions](../design-decisions.md).

## Deliverable

Introduce `internal/intel` with an in-memory reader for advisory JSON. Reuse the
existing strict JSON object decoder through a small shared `internal/jsoninput`
package; do not make intelligence depend on inventory or duplicate the validator.

```go
// Package intel — internal evidence, not a validated advisory or matching input.
type OSVDocument struct {
    SHA256 [32]byte
    Fields map[string]json.RawMessage
}
type ParseError struct { Code string }
func ParseOSVRecord(data []byte) (OSVDocument, error)
```

Successful reading establishes only strict JSON and the minimum envelope below.
It does not establish full OSV conformance, supported schema version, applicability,
trusted publisher, withdrawal status, freshness, or eligibility for matching.

## Input and evidence contract

- One JSON object, at most **4 MiB (4 << 20 bytes)**, with the existing maximum
  **128 nested containers**. Count all input bytes, including surrounding whitespace;
  reject excess before decoding. This is not a hard process-memory guarantee.
- Require `id` and `modified` to be non-empty JSON strings. Missing, null, empty,
  or wrong-type values return `invalid-shape`. Do not trim strings or impose ID
  spelling/date syntax: whitespace-only or malformed date text remains raw evidence
  for later semantic validation, never a valid timestamp/freshness assertion.
- No other required fields in this increment. `schema_version`, `published`,
  `withdrawn`, `affected`, ranges/events, aliases, references, severity, and publisher
  extensions remain raw and uninterpreted, including unknown/null/wrong-type values.
  Missing or malformed `affected` is **not** evidence that no versions are affected.
- Apply current strict validation: UTF-8, single JSON value, no comments/trailing
  commas, decoded-key uniqueness at every object depth, preserved numeric precision,
  valid surrogate pairs, and depth checked before the decoder's larger internal cap.
- Preserve every top-level raw field and unknown nested content without rewriting
  values; hash the exact original input bytes. Return storage independent of later
  caller-byte mutation. No concurrent caller mutation during the call is supported.
- IDs and references are untrusted strings, not paths, URLs to fetch, or trust anchors.
  No filename-based identity, namespace classification, normalization, or merging.

## Shared decoder and error compatibility

Move the existing token/depth/duplicate/surrogate validation from
`internal/inventory/npmlock.go` into `internal/jsoninput`, retaining one implementation
and the same validation ordering. Keep byte limits caller-supplied and depth 128
fixed. The shared helper returns fields plus a controlled category, not input-bearing
standard-library diagnostics. No hashing, format semantics, or I/O belongs in it.

Keep inventory's existing `ParseError` type, `inventory: CODE` messages, APIs, limits,
raw results, and projections unchanged. The existing private `parseJSONFields`
becomes a thin adapter. Inventory tests remain unchanged and must all pass.

Intelligence gets its own `ParseError`, whose message is exactly `intel: CODE`.
Codes: `invalid-json`, `duplicate-key`, `limit-exceeded`, `invalid-shape`. Every error
returns a zero `OSVDocument`: no partial fields/digest or source contents in messages.
Unknown schema versions are retained, not silently qualified or treated as supported.

## Acceptance

Use only synthetic, in-memory inputs:

- Minimum envelope plus realistic-shaped affected/withdrawn/alias/extension fields;
  retain conflicting-looking data without deciding which is authoritative.
- Original-byte digest, raw values/numeric spellings, escaped keys, Unicode and
  valid surrogate pairs; independence after caller mutation.
- Every missing/null/empty/wrong-type required field; accepted nonempty uninterpreted
  strings; non-object/empty object inputs; unknown schema and malformed optional
  fields retained without compatibility or matching claims.
- Malformed/trailing JSON, invalid UTF-8, comments/trailing commas, nested and
  escape-equivalent duplicate keys, unpaired surrogates, and excessive depth.
- Exactly 4 MiB versus one byte over; 128 versus 129 containers. Errors have exact
  controlled codes/messages and zero results.
- Fresh offline root tests/vet across all packages, including all unchanged inventory
  regressions, before and after inline review.

## Exclusions

No advisory downloads, real corpus import, schema/range/date interpretation,
classification, matching, synchronization, storage publication, CLI/reporting,
new dependencies/toolchains, target access, native probes, SCALIBR work, or platform
qualification. Subsequent semantic validation must not treat this reader's success
as permission to match or publish a record.
