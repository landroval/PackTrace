# Increment 1: npm v3 lockfile reader

Status: written specification approved. Implementation still requires approval of
the [implementation plan](01-npm-v3-reader-plan.md) and explicit execution
authorization. Global constraints remain in
[design decisions](../design-decisions.md).

## Deliverable

A reusable internal Go reader with runnable regression tests, not a scanner CLI.
It accepts an in-memory byte slice containing one npm lockfile-version-3 JSON
document and returns its locked records without discarding their fields.

This increment does not depend on a macOS runner. Native filesystem safeguards
and the five-platform release qualification remain required for later increments
that access investigated trees; this reader makes no such access or support claim.

## Contract

- Use the Go standard library only; no new external dependencies.
- Accept exactly one JSON object with integer `lockfileVersion: 3` and an object
  `packages`. The empty-string root package key is allowed. Each package value
  must be an object. Empty `packages` is representable, not evidence of safety.
- Return the SHA-256 digest of the original input bytes and a field-preserving
  document: retain top-level fields and each package record as raw JSON values,
  including unknown fields and absent-versus-null distinctions. Preserve package
  keys exactly after valid JSON string decoding; do not normalize filesystem paths.
- Preserve fields such as `name`, `version`, `resolved`, `integrity`, dependency
  groups, `link`, and installation flags without inventing values. Interpreting
  their manager semantics is outside this increment; retained values are evidence,
  not validated resolutions, URLs, provenance, or installed-package identities.
- Reject malformed JSON, trailing documents/data, duplicate keys at any object
  level, invalid UTF-8, and unpaired Unicode surrogate escapes. Do not silently
  replace ambiguous input or accept last-key-wins decoding.
- Enforce the existing 64 MiB lockfile-size and 128-container nesting limits.
  These are work bounds, not a hard RSS or runtime guarantee.
- A rejected document produces a controlled error category and no successful or
  partial parsed document. Categories distinguish syntax/encoding, duplicate keys,
  limits, unsupported version, and invalid shape. Do not include raw input values
  or package names in error messages.
- The caller must not modify the input concurrently with parsing. Returned raw
  values must not alias the caller's byte slice; later input mutation cannot
  change the accepted result.

## Explicit exclusions

No disk reads/writes by the reader, directory discovery, package-manager execution,
networking, CLI, public report schema, SARIF, Bun/npm-v1/v2 adapters, policy engine,
matching, integrity comparison, worker process, or native probe. Do not infer
that a parsed lockfile is effective, supported for every npm producer, installed,
clean, or safe. No automatic promotion of existing probe implementation code.

## Acceptance

Run standard Go tests with synthetic byte literals covering:

1. A v3 document with root, nested/duplicate-name instances, aliases, links,
   dependency groups, flags, digests, and unknown/null fields retained.
2. Original-byte digest correctness and independence from later input mutation.
3. Missing/wrong version, missing/wrong `packages`, null/non-object package
   records, malformed/trailing JSON, and duplicate keys including escaped aliases.
4. Invalid UTF-8 and unpaired surrogate rejection; valid Unicode retained.
5. Exact size/depth boundaries and limit failures without content-bearing errors.

The implementation must show a failing-then-passing test cycle and passing tests
and `go vet` for the new production module. Record the development toolchain;
local development checks do not replace official-toolchain release qualification.
Keep the existing SCALIBR probe isolated and report its known build blocker
separately; do not modify or rerun it as part of this increment.
