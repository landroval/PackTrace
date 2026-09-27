# Increment 9: OSV affected package identities

Status: scope selected; written specification awaiting approval. Plan and execution
approval remain separate. Authority: [design decisions](../design-decisions.md).

## Deliverable

Add a positional projection of `affected` and `package.ecosystem/name/purl` in
`internal/intel`. Consume an unchanged successful [OSVDocument](07-osv-reader.md),
retaining its digest and raw document. Reader and [temporal projection](08-osv-times.md)
remain unchanged. This is typed evidence, not validated identity or matching input.

```go
type OSVFieldState uint8
const (
    OSVFieldUnavailable OSVFieldState = iota
    OSVFieldAbsent
    OSVFieldNull
    OSVFieldInvalidType
    OSVFieldValue
)
type OSVString struct {
    State OSVFieldState
    Value string
}
type OSVAffectedEntry struct {
    Index int
    State, PackageState OSVFieldState
    Ecosystem, Name, PURL OSVString
}
type OSVAffectedProjection struct {
    SourceSHA256 [32]byte
    State OSVFieldState
    Entries []OSVAffectedEntry
}
func ProjectOSVAffected(doc OSVDocument) (OSVAffectedProjection, error)
```

Use intel-local states; do not import inventory or move its existing types. The
unavailable state is necessary for children whose parent cannot be inspected;
it is not evidence that the child is absent.

## Shape and uncertainty contract

- At the root, missing `affected` -> absent; null -> null; non-array -> invalid-type;
  array -> value. Non-value roots have nil Entries. A valid empty array has non-nil
  empty Entries; it does not establish a negative affectedness or complete coverage.
- Produce one entry per array position, preserving order and duplicates, with its
  exact zero-based Index. No filtering by ecosystem, package name, or usability.
- Each element: null -> null; non-object -> invalid-type; object -> value. For an
  unusable element, PackageState and all three strings remain unavailable.
- Within an object element, package missing/null/non-object/object yields
  absent/null/invalid-type/value. If package is not an object, all three strings
  remain unavailable, not absent. An empty package object instead establishes
  that its three named fields are absent.
- In a package object, string fields missing/null/non-string/string yield
  absent/null/invalid-type/value. Only value fields retain string content; an empty
  string is still a typed value. Bad fields do not erase usable siblings.
- Copy exact decoded string values. Do not trim, normalize, parse PURLs, infer missing
  fields, resolve discrepancies, or cross-check PURL against ecosystem/name. Keep
  contradictory-looking claims and non-npm ecosystems without reinterpretation.
- Versions, ranges, affected-level ecosystem/database metadata, and unknown package
  fields stay unchanged in the raw document. No typed range/version output yet.
- Source locator: digest + `affected` index + package field. Output mutation does not
  affect another entry or the input, and later input mutation does not affect output.

## Bounds and failure behavior

Add **20,000 affected entries per document**, counting every position, including
null/invalid elements and repeated identities. This is independent of inventory
limits; it is not an installed-instance limit or evidence-deduplication budget.

Decode the array under the reader's existing 4 MiB/depth-128 bounds, then check count
before allocating output entries or projecting children. Over the limit returns
existing intel `limit-exceeded` and a zero projection, never truncation. This does
not prevent allocations during JSON decoding or promise a hard RSS limit. Raw
reader acceptance and the original document remain unchanged.

Nil Fields returns existing intel `invalid-shape` and a zero projection. Other
unusable field/element shapes yield explicit states with nil error. Controlled
messages use `intel: CODE`, without source contents. Preconditions exclude concurrent
input mutation and forged/modified documents; basic guards do not authenticate them.

## Acceptance and exclusions

Synthetic tests cover all root/element/package/string states, unavailable versus
absent children, mixed valid/invalid siblings, duplicate identities, original order,
exact strings, unknown/non-npm/conflicting PURL claims, raw versions/ranges preserved,
digest/ownership, nil input, and exact 20,000/20,001 limits counting null/invalid and
repeated entries. All previous 420 tests/subtests and vet must continue to pass.

No schema/name/ecosystem/PURL qualification, range/version interpretation, matching,
active-advisory eligibility, snapshot indexing, new dependencies, network/target
access, native probes, SCALIBR work, CLI/reporting, or platform qualification.
