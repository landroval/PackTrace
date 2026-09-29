# Increment 12: Bun text lockfile reader

Status: specification and [implementation plan](12-bun-lock-reader-plan.md) submitted
for review in the pull request for [issue #1](https://github.com/landroval/PackTrace/issues/1).
Implemented in `internal/inventory/jsonc.go` and `bunlock.go`, with regression tests
alongside them (code `38c2961`, tests `9433a48`). Development checks passed: 773 root
tests/subtests and `go vet`. This is not producer-generated, native, or release
qualification. The increment number is provisional. Global constraints remain in
[design decisions](../design-decisions.md).

## Deliverable

A reusable internal Go reader with runnable regression tests, not a scanner CLI.
It accepts an in-memory byte slice containing one text `bun.lock` document and
returns its top-level fields, workspace records, and package entries as retained
evidence, without interpreting package tuples.

This closes a gap recorded by the [SCALIBR probe](../inventory-evaluation-results.md):
its Bun extractor panicked on a literal `null` lockfile, accepted unsupported
versions such as `-1` and `999`, and did not enforce reader byte budgets. The
recorded recommendation is a narrowly owned JSONC projection; this increment
provides its bounded reading step only.

## Format evidence

Bun's own source (`oven-sh/bun`, `src/install/lockfile/bun.lock.rs` and
`src/parsers/json.rs`, reviewed on the `main` branch) shows:

- `bun.lock` is parsed with Bun's `package.json` dialect: comments and trailing
  commas are allowed; duplicate keys produce a warning, not an error.
- `lockfileVersion` must be a non-negative integral number; versions 0–3 are
  known. Version 1 changed workspace package rows; version 2 added stricter
  integrity and git-tag checks; version 3 allows scoped override objects.
- A `workspaces` object is required. A missing `packages` object is parsed as
  empty, but the writer always emits it.
- Each `packages` value is an array whose shape depends on the resolution kind
  (registry, git, GitHub, tarball, folder, link, workspace, root).

This is source inspection, not producer-generated fixture evidence. Actual
Bun 1.3.2/1.4.2 output compatibility remains separate qualification work.

## Contract

- Use the Go standard library only; no new external dependencies. In particular,
  do not add `github.com/tidwall/jsonc`.
- Normalize JSONC before validation with a PackTrace-owned normalizer:
  - Remove `//` line comments and `/* */` block comments outside strings.
  - Remove a trailing comma that follows a value and precedes `}` or `]`,
    ignoring intervening whitespace and comments.
  - Replace each removed byte with a space, keeping line breaks, so normalized
    output has the same length and byte offsets as the original.
  - Leave string contents unchanged, including `//`, `/*`, and `,}` inside strings
    and escaped quotes.
  - Reject unterminated block comments, a lone `/` outside strings, and commas that
    do not follow a value, such as `{,}`, `[,]`, `[1,,]`, or a leading comma.
  - Perform no other syntax repair; all remaining validation belongs to
    `internal/jsoninput`.
- Enforce the 64 MiB lockfile-size limit on the original bytes and the existing
  128-container nesting limit. These are work bounds, not an RSS guarantee.
- Validate the normalized bytes with `jsoninput.Object`, preserving its rejection of
  malformed JSON, trailing data, duplicate keys at any level, invalid UTF-8, and
  unpaired surrogate escapes. Rejecting duplicate keys is deliberately stricter
  than Bun, which only warns; last-key-wins ambiguity is not accepted as evidence.
- Accept only an integer-literal `lockfileVersion` of `0`, `1`, `2`, or `3`.
  Reject other integers as unsupported, and non-integer or non-number values such
  as `"1"`, `null`, `1.0`, or `1e0` as invalid shape. Rejecting `1.0` is
  deliberately stricter than Bun and consistent with the npm reader.
- Require `workspaces` as an object whose values are objects, and `packages` as an
  object whose values are arrays. Preserve keys exactly after valid JSON string
  decoding. Empty objects are representable, not evidence of safety.
- Return the SHA-256 digest of the original input bytes, not the normalized bytes.
  Retain all top-level fields, including unknown ones such as `configVersion`,
  `overrides`, `catalogs`, `trustedDependencies`, and `patchedDependencies`, as raw
  JSON. Retain each workspace record and package array as raw JSON.
- Retained raw values come from the normalized document. Because normalization is
  length-preserving, their positions still correspond to the original bytes.
- Do not interpret package tuples, identities, versions, resolution kinds,
  integrity values, workspace semantics, overrides, or `configVersion`.
- A rejected document produces a controlled error category and no successful or
  partial document. Reuse the existing categories: `invalid-json` (including JSONC
  syntax), `duplicate-key`, `limit-exceeded`, `unsupported-version`, and
  `invalid-shape`. Do not include raw input values or package names in errors.
- The caller must not modify the input concurrently with parsing. Returned raw
  values must not alias the caller's byte slice.

## Explicit exclusions

No typed projection of package tuples, workspace or override semantics,
`configVersion` interpretation, binary `bun.lockb` support, installed-layout or
`.bun` store observation, effective-input selection between npm and Bun
lockfiles, disk reads/writes, directory discovery, package-manager execution,
networking, CLI, report schema, matching, or integrity comparison. The npm reader
and `internal/jsoninput` behavior remain unchanged. Do not infer that a parsed
lockfile is effective, installed, supported for every Bun producer, clean, or safe.

## Acceptance

Run standard Go tests with synthetic byte literals covering:

1. Normalizer: line and block comments, trailing commas in objects and arrays,
   comments between a trailing comma and its closing bracket, and strings
   containing `//`, `/*`, `,}`, and escaped quotes left unchanged.
2. Normalizer rejection: `{,}`, `[,]`, double and leading commas, unterminated
   block comments, and a lone `/`.
3. Normalizer length and offset preservation, including retained line breaks.
4. A document for each version 0–3 with root and non-root workspaces, several
   package tuple shapes, and unknown top-level fields retained unchanged.
5. Original-byte digest correctness and independence from later input mutation.
6. Missing, non-integer, negative, and unknown versions; missing or non-object
   `workspaces`/`packages`; non-object workspace records; non-array package
   entries; and literal `null`, array, and scalar roots.
7. Duplicate keys, including escaped aliases and duplicates hidden by comments;
   invalid UTF-8 and unpaired surrogates; malformed and trailing input.
8. Exact size and depth boundaries and limit failures without content-bearing errors.

The implementation must show a failing-then-passing test cycle and passing
`go test ./...` and `go vet ./...` for the root module. Record the development
toolchain; local checks do not replace official-toolchain release qualification.
Keep the SCALIBR probe isolated; do not modify or rerun it.

## Open question

Bun parses a lockfile without `packages` as empty, although its writer always
emits the field. This specification rejects a missing `packages` object as invalid
shape, as proposed in the issue. The alternative is to accept it and record its
absence as distinct evidence from an empty object.
