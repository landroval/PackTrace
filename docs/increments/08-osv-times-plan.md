# OSV temporal projection implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:executing-plans`
> for approved inline execution. Await plan review and execution authorization.

**Goal:** expose temporal evidence and withdrawal claims without inferring activity/freshness.
**Architecture:** three fixed scalar projections from a successful OSVDocument;
lexical profile plus standard calendar parsing, independent field states, and a
withdrawal classification derived only from the withdrawn field's state.
**Tech stack:** Go standard library (`bytes`, `encoding/json`, `regexp`, `time`).
**Spec:** [approved temporal contract and type definitions](08-osv-times.md).

## Global constraints

- Keep existing OSV reader, shared decoder, inventory code/tests and module unchanged.
- Preserve text/source hash; distinguish missing/null/wrong type/uninterpretable/value.
- Accepted strings have explicit timezone, uppercase T/Z, at most nine fractional
  digits, valid calendar values, numeric offsets <=23:59, and UTC years 0000–9999.
- `TimestampValue`, not IsZero, marks validity. Retain -00:00 and fractional spelling
  in Text; Value is normalized to UTC.
- Unknown withdrawal is the zero default; no active/eligible or freshness inference.
- No ambient clock/local timezone, I/O, external dependencies, probes or qualification.
- Current jj workspace/file-backed ledger; inline review and scoped commits only.

## Review focus

1. Go accepts some timestamp forms or precision truncation outside this explicit profile.
2. Go time.Parse can consult Local for numeric offsets; use ParseInLocation with UTC.
3. Year 0001 zero time is valid; UTC normalization can cross the allowed year boundaries.
4. Bad modified/published data must not erase a readable withdrawal; absence is not active.
5. Unusable timestamp text remains evidence, but must not leak into error diagnostics.

## Task 1: implement timestamp fields and withdrawal claims

**Create:** `internal/intel/osv_times.go` and `internal/intel/osv_times_test.go`.
**Consumes:** `OSVDocument`, intel `ParseError`, the approved timestamp profile.
**Produces:** `TimestampState`, `OSVTimestamp`, `WithdrawalState`, `OSVTimes` and
`ProjectOSVTimes(doc OSVDocument) (OSVTimes, error)` exactly as specified.

- [ ] Write tests through `ParseOSVRecord`, then the new projection. Start with
  an advisory whose modified value is `not-a-date` and whose withdrawn value is
  `0001-01-01T00:00:00Z`:

```go
got, err := ProjectOSVTimes(doc)
if err != nil || got.Modified.State != TimestampUninterpretable ||
    got.Withdrawn.State != TimestampValue || !got.Withdrawn.Value.IsZero() ||
    got.Withdrawal != WithdrawalReported {
    t.Fatal("invalid sibling or zero instant erased withdrawal", err)
}
```

  Cover absent/null/wrong-type/empty/unsupported/valid optional fields, supported
  modified values and future withdrawals, UTC and positive/negative/-00:00 offsets,
  fractional trailing zeros/nanoseconds, leap dates, all rejected grammar variants,
  and years at/beyond UTC boundaries. Assert exact Text, states, normalized UTC
  values (using Time.Equal, not UnixNano outside its useful range), and zero values
  for non-value states. Check independent fields and source digest/raw ownership.
  Nil Fields must return exact intel invalid-shape and zero OSVTimes.
- [ ] Observe missing-symbol compile RED; add only approved types/constants and a
  zero-result ProjectOSVTimes stub, then observe behavioral RED before implementation.
- [ ] Add a private compiled lexical pattern, before calling the time parser:

```go
var osvTimestampPattern = regexp.MustCompile(
    `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}` +
    `(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$`)
```

  Implement private `projectOSVTimestamp(fields map[string]json.RawMessage, key string)`:
  absent -> zero timestamp; trimmed null -> TimestampNull; failed string decoding ->
  TimestampInvalidType with empty Text/Value. Otherwise initialize TimestampUninterpretable
  with the decoded Text. If lexical check passes, apply:

```go
value, err := time.ParseInLocation(time.RFC3339Nano, result.Text, time.UTC)
if err != nil { return result }
value = value.UTC()
if value.Year() < 0 || value.Year() > 9999 { return result }
result.State, result.Value = TimestampValue, value
return result
```

  No raw parser error is returned. No trimming or truncation of Text. No fallback
  to a permissive parser after lexical rejection.
- [ ] Implement ProjectOSVTimes: nil Fields -> zero result/controlled invalid-shape;
  copy digest, independently project modified/published/withdrawn, then:

```go
switch result.Withdrawn.State {
case TimestampAbsent:
    result.Withdrawal = WithdrawalNotDeclared
case TimestampValue:
    result.Withdrawal = WithdrawalReported
}
return result, nil
```

  Other states retain WithdrawalUnknown. Do not compare fields to each other or to now.
- [ ] Format both files, run focused/new and all root tests/vet, inspect all profile
  branches and callers, and verify no old files changed. Rerun full verification
  after inline review; do not claim independent review or native qualification.
- [ ] Commit only the two Go files. Record actual results and a nested milestone
  in a separate docs commit without closing matching/freshness/withdrawal shipping
  parents. Close the task ledger.

## Verification and commit (Nushell)

```nu
gofmt -w internal/intel/osv_times.go internal/intel/osv_times_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 -run TestProjectOSVTimes ./internal/intel
    go test -count=1 ./...
    go vet ./...
}
jj commit -m "feat: project OSV timestamps and withdrawal" internal/intel/osv_times.go internal/intel/osv_times_test.go
```

Each verification command must succeed before committing. Unknown schema versions,
invalid identities, publisher trust, corrections, and matching eligibility remain
outside this temporal projection even when all three timestamps are interpretable.
