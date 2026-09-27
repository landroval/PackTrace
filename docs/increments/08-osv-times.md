# Increment 8: OSV timestamps and withdrawal claims

Status: written specification approved. The [implementation plan](08-osv-times-plan.md)
and execution authorization remain to be approved. Authority: [design decisions](../design-decisions.md).

## Deliverable

Add an in-memory temporal projection to `internal/intel`, consuming an unchanged
successful [OSVDocument](07-osv-reader.md). Preserve its source digest and project
only `modified`, `published`, and `withdrawn`. Do not change the raw reader.

```go
type TimestampState uint8
const (
    TimestampAbsent TimestampState = iota
    TimestampNull
    TimestampInvalidType
    TimestampUninterpretable
    TimestampValue
)
type OSVTimestamp struct {
    State TimestampState
    Text string
    Value time.Time
}
type WithdrawalState uint8
const (
    WithdrawalUnknown WithdrawalState = iota
    WithdrawalNotDeclared
    WithdrawalReported
)
type OSVTimes struct {
    SourceSHA256 [32]byte
    Modified, Published, Withdrawn OSVTimestamp
    Withdrawal WithdrawalState
}
func ProjectOSVTimes(doc OSVDocument) (OSVTimes, error)
```

These are internal evidence types, not public report/IPC schemas or a fully
validated advisory. Digest + field name identifies the original evidence.

## Explicit timestamp profile

Accept only `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)` with ASCII digits,
uppercase `T`/`Z`, required timezone, and **1–9 fractional digits** when present.
Numeric offsets permit hours 00–23 and minutes 00–59; retain `-00:00` as original
text while interpreting its UTC instant. Require a valid Gregorian date/time via
Go's standard time parser. Leap-second spellings (`:60`), excess fractional digits,
commas, lowercase separators, whitespace, abbreviations, and omitted zones are
outside this profile, not silently normalized or precision-truncated.

Use `time.ParseInLocation(time.RFC3339Nano, text, time.UTC)` after lexical checks,
not `time.Parse`/`time.Local`: numeric offsets must not consult the process's local
timezone. Normalize accepted values to UTC. Both the four-digit input year and
normalized UTC year must be within **0000–9999**; offset conversions leaving that
range are uninterpretable. This is an explicit supported subset, not a claim to
recognize every RFC3339/OSV-permitted representation.

## States and withdrawal behavior

- Missing field -> `TimestampAbsent`; JSON null -> `TimestampNull`; non-string ->
  `TimestampInvalidType`. Their text is empty and value is zero.
- Strings retain their exact decoded text, including empty strings. A calendar/
  lexical/profile failure -> `TimestampUninterpretable` with zero value; accepted
  text -> `TimestampValue` with its UTC instant. Do not return parser diagnostics.
- A zero `time.Time` can itself be a valid represented instant (year 0001). **State,
  not `Value.IsZero()`, determines validity.** Do not lose fractional trailing zeros
  or original offsets from `Text`, even though the interpreted value is normalized.
- Withdrawal classification depends only on the `withdrawn` field:
  absent -> `WithdrawalNotDeclared`; supported timestamp -> `WithdrawalReported`;
  null/wrong-type/uninterpretable -> `WithdrawalUnknown`.
- `WithdrawalNotDeclared` does **not** mean active, valid, authentic, or matchable.
  `WithdrawalReported` is a retained source claim, not confirmation by a publisher.
  A future-looking supported withdrawal still reports that claim; no clock or
  effective-date scheduling is introduced.
- Keep each field independently: an unusable `modified`/`published` does not erase
  a usable withdrawal or vice versa. Do not infer ordering constraints, compare to
  now, repair dates, or use advisory timestamps as acquisition freshness.

## Preconditions, bounds, and errors

Input must remain an unchanged successful reader result with no concurrent mutation;
this function does not reauthenticate hashes, revalidate forged documents, or qualify
schema/identity/corrections. Nil `Fields` returns existing intel `invalid-shape` and
zero `OSVTimes` (whose withdrawal default is unknown). Temporal problems instead
remain explicit field states with nil error; no raw strings leak through errors.

Only three scalar fields are projected under the reader's existing 4 MiB/depth bounds.
No new collection or adjustable budget is introduced. Results own their mutable
structure and are unaffected by subsequent input-byte/map/digest mutation. Original
raw fields, unrelated data, and digest remain unchanged during projection.

## Acceptance and exclusions

Synthetic tests must cover all states/classifications, original text and digest,
valid UTC/numeric offsets/negative-zero offset, nanosecond precision and trailing
zeros, valid zero time, calendar and lexical failures, excessive precision, leap
seconds, UTC year boundaries, future withdrawal without clock inference, independent
invalid siblings, ownership and nil input. Existing 348 tests/subtests and vet must
continue passing, with reader/decoder behavior unchanged.

No full OSV validation, timeline consistency, freshness, active-advisory eligibility,
affected/range interpretation, matching, classification of threat categories,
network, new dependencies, target access, native probes, SCALIBR work or qualification.
