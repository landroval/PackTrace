# Increment 3: typed npm locked records

Status: specification, record bound, and [implementation plan](03-npm-locked-records-plan.md)
approved; inline execution explicitly authorized and completed. Implementation
commit `8ef999fe`; 139 passing root tests/subtests and `go vet`.
No producer/native or full-scanner qualification is implied. Global constraints are in
[design decisions](../design-decisions.md).

## Deliverable

Add an internal, in-memory projection of the [v2/v3 reader's](02-npm-v2-reader.md)
`Document`. It exposes explicitly recorded scalar fields for later analysis,
without changing the reader, reconciling legacy data, or claiming installed state.
No new dependency, network access, or filesystem operation is needed.

## Interface and field states

```go
type FieldState uint8

const (
    FieldAbsent FieldState = iota
    FieldNull
    FieldValue
    FieldInvalidType
)

type LockField[T string | bool] struct {
    State FieldState
    Value T
}

type LockedRecord struct {
    Location  string
    Name      LockField[string]
    Version   LockField[string]
    Resolved  LockField[string]
    Integrity LockField[string]
    Link      LockField[bool]
}

type NPMLockProjection struct {
    SourceSHA256 [32]byte
    Records      []LockedRecord
}

func ProjectNPMLock(doc Document) (NPMLockProjection, error)
```

These are internal types, not a public report/IPC schema. `FieldValue` means only
that the JSON value has the expected scalar type: empty strings and `false` are
values, not absence. No coercion from numbers, booleans, strings, arrays, or objects
to another type. All non-value states carry the zero value of `T`.

## Projection contract

- Consume an unchanged successful `ParseNPMLock` result. The caller must not mutate
  it before or during projection. This internal helper does not authenticate or
  revalidate a caller-forged/mutated document or its digest.
- Produce one record per `Document.Packages` entry, including root (`""`), workspace,
  and link entries. These are lockfile locations, not verified physical locations.
  Preserve each decoded key exactly; no path normalization, deduplication, or
  following links. Sort records by Go string lexicographic order of `Location`.
- Read only explicit `name`, `version`, `resolved`, `integrity`, and `link` fields.
  Do not infer names from location keys, alias targets, versions from constraints,
  link-target identities, origin classes, digest algorithms, or authenticity.
  Unsupported semantic values remain uninterpreted strings, not validated identities.
- Treat missing, null, correct-type, and wrong-type fields distinctly. A wrong-type
  field does not discard its record or usable sibling fields; its state records
  the problem. Do not invent findings, coverage completion, or enforcement decisions.
- Copy the document SHA-256 into the projection. Field evidence is located by that
  source digest, the exact record location, and the known field name. Keep all raw
  values, unknown fields, and legacy conflicts in the original `Document`, unchanged;
  no second parser or copy of the entire raw document belongs in the projection.
- Later mutation of the input document must not alter returned scalar values or
  locations. The projection must not mutate the input. An empty parsed `packages`
  object returns an empty, non-nil `Records` slice, not a clean/safe conclusion.
- Reject nil `Fields`, nil `Packages`, or a nil package record with the existing
  `ParseError{Code: "invalid-shape"}` and a zero projection. These basic guards are
  not full validation of a forged `Document`.

## Additional work bound

Limit this projection to **20,000 lockfile records**, including root, workspace,
and link entries. Check `len(doc.Packages)` before sorting or allocating records.
Above the bound, return `ParseError{Code: "limit-exceeded"}` and a zero projection;
never truncate silently. The original raw document remains available unchanged.
This is a new projection bound, not a redefinition of the installed-instance budget
or a hard RSS/duration guarantee. It does not change what `ParseNPMLock` accepts.

## Acceptance and exclusions

Synthetic tests must cover v2/v3 inputs; deterministic ordering; root/workspace/link
and repeated-name records; aliases and odd location keys retained without inference;
all four states for string/bool fields; empty string and false; wrong-type fields
with valid siblings; raw unknown/legacy conflicts unchanged; original digest and
non-aliasing after source mutation; empty/nil inputs; exact 20,000/20,001 boundaries.

Require RED/GREEN, passing root tests/vet with the existing offline development
environment, inline review, and scoped jj commits after separate authorization.

No manifest or installed inventory, dependency-edge resolution, SemVer/URL/digest
validation, origin classification, report/redaction implementation, CLI, native
probe, SCALIBR changes, or producer/native qualification. Future matching must
validate identity/version/origin applicability before treating these claims as
confirmed matches; field typing alone cannot supply that validation.
