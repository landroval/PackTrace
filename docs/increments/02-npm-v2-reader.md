# Increment 2: npm v2/v3 lockfile reader

Status: written specification approved. The
[implementation plan](02-npm-v2-reader-plan.md) still requires review and explicit
execution authorization.
Global constraints remain in [design decisions](../design-decisions.md).

## Deliverable and API change

Extend the existing in-memory reader to accept npm lockfile versions 2 and 3,
without adding another parser, package, dependency, or filesystem operation.
This builds on [increment 1](01-npm-v3-reader.md), not on the SCALIBR probe.

Rename the internal entry point to:

```go
func ParseNPMLock(data []byte) (Document, error)
```

Keep `Document` and `ParseError.Code` unchanged. Replace the error-text prefix
`npm v3: ` with `npm lockfile: `, followed only by the controlled category.
The existing callers are tests in `internal/inventory/npmlock_test.go`; migrate
them rather than adding a compatibility wrapper for an internal-only API.
These name, accepted-version, and error-prefix changes explicitly supersede the
corresponding increment-1 contracts. Other guarantees remain unchanged.

## Reading contract

- Accept one JSON object with an integer-literal `lockfileVersion` equal to 2 or 3.
  Other integers, including 1, 4, negative and oversized values, produce
  `unsupported-version`. Missing/non-integer versions produce `invalid-shape`;
  decimal/exponent spellings such as `2.0` and `2e0` are not integer literals.
- Both versions require `packages` to be an object of objects. Empty `packages`
  and its empty-string root key remain allowed. Never reconstruct a missing or
  invalid `packages` from the legacy `dependencies` tree.
- Preserve every top-level and package field as raw JSON. For v2, keep the legacy
  tree in `Document.Fields["dependencies"]`; do not duplicate it into another
  model, flatten it, merge it with `Packages`, or use it to overwrite any entry.
- Retain disagreements between the two representations, including differing
  versions, source strings, digests, or entries present in only one. This reader
  does not reconcile them or emit semantic-conflict diagnostics.
- `dependencies` is optional raw evidence, not a validated npm graph. Preserve
  absence versus null and non-object values without interpreting them. Generic
  JSON validation still visits its entire value, rejecting duplicates, malformed
  Unicode, or excessive nesting just as for all other fields. Retention must not
  be presented as evidence of valid dependency semantics.
- Keep the existing original-byte SHA-256, caller-input independence, exact
  decoded package keys, number precision, null/unknown-field preservation,
  duplicate-key/Unicode checks, single-document rule, 64 MiB size limit, and
  128-container nesting limit. These are not hard RSS or duration guarantees.
- Every failure returns a zero `Document` and the existing controlled categories,
  without input contents in the error. No partial success or version fallback.

## Acceptance

1. Run the existing preservation and input-rejection cases against both accepted
   versions where applicable; retain v3 regression coverage after the API rename.
2. Add a v2 fixture containing nested legacy dependencies and deliberate conflicts
   with `packages`. Assert independent raw retention, no invented locations or
   records, original digest, and independence from subsequent input mutation.
3. Cover absent/null/non-object legacy data, missing/invalid `packages` despite a
   legacy tree, and duplicate keys or invalid Unicode inside nested legacy data.
4. Verify exact size/depth boundaries, unsupported versions 1 and 4, wrong version
   types/spellings, zero results on rejection, and content-free error messages.
5. After separate authorization, demonstrate RED/GREEN tests and passing root
   `go test ./...` and `go vet ./...`, using the existing local development
   toolchain with `GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0`.

## Exclusions and completion boundary

No CLI, disk access, discovery or shrinkwrap selection, installed inventory,
relationship resolution, producer-version inference, matching, integrity checks,
Bun/v1 parsing, dependencies/downloads, native probe, or SCALIBR modifications.
Synthetic parser tests do not qualify npm 8 or any other producer/native target;
macOS runner availability does not block this in-memory increment. Only the two
existing inventory Go files need production/test changes. Record completion with
a scoped jj commit after implementation is explicitly authorized and verified.
