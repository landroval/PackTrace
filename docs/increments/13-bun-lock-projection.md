# Increment 13: typed Bun locked records

Status: specification and [implementation plan](13-bun-lock-projection-plan.md)
drafted for [issue #3](https://github.com/landroval/PackTrace/issues/3). The
increment number is provisional. Global constraints remain in
[design decisions](../design-decisions.md).

## Deliverable

Add an internal, in-memory projection of the [Bun reader's](12-bun-lock-reader.md)
`BunLockDocument`. It interprets each retained `packages` tuple into typed,
state-carrying fields for later analysis, the way the
[npm projection](03-npm-locked-records.md) does for `package-lock.json`, without
changing the reader or claiming installed state. No new dependency, network
access, or filesystem operation is needed.

## Format evidence

Bun's text-lockfile parser (`oven-sh/bun`, `main` branch:
`src/install/lockfile/bun.lock.rs`, `src/install/dependency.rs`, and
`src/install/resolution.rs`) reads each `packages` value as an array whose first
element is `"<name>@<resolution>"`:

| Kind | Resolution form written by Bun | Remaining elements |
|------|-------------------------------|--------------------|
| npm registry | bare `x.y.z` version | registry string (empty means default), INFO, integrity string |
| git | `git+<url>#<ref>` | INFO, bun-tag string, optional integrity |
| GitHub | `github:<owner>/<repo>#<ref>` | INFO, bun-tag string, optional integrity |
| tarball | `http://` or `https://` URL, or a path ending in `.tgz`, `.tar.gz`, or `.tar` | INFO, optional integrity |
| folder | `file:<path>` | INFO |
| link | `link:<path>` | INFO |
| workspace | `workspace:<path>` | none (INFO in version 0) |
| root | written as `@root:` with an empty name | object with `bin` or `binDir` |

Findings that shape this contract:

- Bun splits `name@resolution` at the first `@` after index 0
  (`split_name_and_maybe_version`), so scoped names keep their scope and git URLs
  such as `git+ssh://git@host/repo` keep their own `@`. `@root:` is a special
  case with an empty name.
- Bun checks `root:`, `link:`, `workspace:`, and `file:` prefixes first, then
  infers the kind from the remaining string. `file:` is always a folder, even when
  it ends in `.tgz`.
- The integrity element is required for npm rows and optional for git, GitHub,
  and tarball rows. The git bun-tag is a commit tag, not a digest.
- Bun rejects a missing or wrong-type registry, INFO, npm integrity, git tag, or
  root object as invalid package info.

This is source inspection, not producer-generated fixture evidence.

## Interface

```go
type BunResolutionKind uint8

const (
    BunKindUnknown BunResolutionKind = iota
    BunKindNPM
    BunKindGit
    BunKindGitHub
    BunKindTarball
    BunKindFolder
    BunKindLink
    BunKindWorkspace
    BunKindRoot
)

type BunLockedRecord struct {
    Key        string
    Kind       BunResolutionKind
    Name       LockField[string]
    Resolution LockField[string]
    Registry   LockField[string]
    Integrity  LockField[string]
    GitTag     LockField[string]
    Info       json.RawMessage
}

type BunLockProjection struct {
    SourceSHA256 [32]byte
    Records      []BunLockedRecord
}

func ProjectBunLock(doc BunLockDocument) (BunLockProjection, error)
```

These are internal types, not a public report or IPC schema. `FieldState` and
`LockField[T]` are reused unchanged. `LockedRecord` is not reused: its fields
describe npm JSON members, while Bun's name and resolution come from a positional
string and the meaning of each later element depends on the kind. A common
npm/Bun model for matching is designed with matching, not here.

## Projection contract

- Consume an unchanged successful `ParseBunLock` result. The caller must not
  mutate it before or during projection. This helper does not authenticate or
  revalidate a forged or mutated document.
- Produce one record per `Packages` entry. `Key` is the decoded `packages` key,
  kept as opaque evidence: no path normalization, deduplication, or name
  inference from it. Sort records by Go string order of `Key`.
- **Split.** For a first element of exactly `@root:`, `Name` is the empty string
  and `Resolution` is `root:`. Otherwise split at the first `@` after index 0.
  A first element that is not a string gives `Name` and `Resolution` the state of
  that element (`FieldNull` or `FieldInvalidType`); an empty tuple gives
  `FieldAbsent`. A string without such an `@`, or with nothing after it, gives
  both `FieldInvalidType`. Names are not validated as safe folder names.
- **Kind.** Classify from the resolution in this order, and only when the tuple
  shape below also matches; otherwise the kind is `BunKindUnknown`:

  | Resolution test | Kind | Required shape after the first element |
  |-----------------|------|----------------------------------------|
  | equals `root:` | root | one object |
  | prefix `link:` | link | one object (INFO) |
  | prefix `workspace:` | workspace | nothing, or one object (INFO) |
  | prefix `file:` | folder | one object (INFO) |
  | prefix `github:` | GitHub | object, string, then an optional string |
  | prefix `git+` | git | object, string, then an optional string |
  | prefix `http://` or `https://`, or suffix `.tgz`, `.tar.gz`, `.tar` (ASCII case-insensitive) | tarball | object, then an optional string |
  | anything else | npm | string, object, string |

  PackTrace does not reimplement Bun's hosted-git URL inference or SemVer checks:
  it recognizes the forms Bun writes. A non-canonical form, or any shape mismatch,
  is kept as a `BunKindUnknown` record with its raw evidence still in the
  document, never dropped or rejected.
- **Fields by kind.** `Registry` is filled only for npm. `Integrity` is filled for
  npm, git, GitHub, and tarball (absent when the optional element is missing).
  `GitTag` is filled only for git and GitHub. Every other combination, and every
  field of a `BunKindUnknown` record except `Name` and `Resolution`, is
  `FieldAbsent`. `Resolution` is an uninterpreted string: a version only for npm,
  never validated as SemVer, URL, or path.
- `Info` is a copy of the INFO object for kinds that have one, or of the root
  object for root; otherwise nil. Its dependency groups, platform constraints,
  and binaries are not interpreted here.
- Empty strings are values, not absence. Copy the document SHA-256 into the
  projection. Returned strings and `Info` must not alias the input document;
  later mutation of the document must not alter them. The projection must not
  mutate the input.
- An empty `packages` object returns an empty, non-nil `Records` slice, not a
  clean or safe conclusion.
- Reject nil `Fields`, nil `Packages`, or a nil or non-array package entry with
  `ParseError{Code: "invalid-shape"}` and a zero projection. These basic guards
  are not full validation of a forged document.

## Additional work bound

Limit this projection to **20,000 records**, the same bound as the npm
projection. Check `len(doc.Packages)` before sorting or allocating. Above the
bound, return `ParseError{Code: "limit-exceeded"}` and a zero projection; never
truncate silently. This does not change what `ParseBunLock` accepts.

## Explicit exclusions

No workspace, override, catalog, or `configVersion` semantics; no interpretation
of `INFO` contents or dependency edges; no lockfile-version-specific rules such as
Bun's version 2 integrity and git-tag checks; no SemVer, URL, safe-name,
digest-algorithm, or integrity validation; no hosted-git URL inference; no
tarball download or git fetch; no `node_modules` or `.bun` store observation; no
binary `bun.lockb`; no common npm/Bun model; no matching, report schema, CLI, disk
access, or networking. The npm projection and the Bun reader remain unchanged.
Do not infer that a projected record is installed, authentic, clean, or safe.

## Acceptance

Run standard Go tests with synthetic byte literals parsed by `ParseBunLock`,
covering:

1. One record per kind (npm, git, GitHub, remote and local tarball, folder, link,
   workspace with and without INFO, root) with the expected `Kind` and fields.
2. Scoped names, git resolutions containing `@`, and `@root:` split correctly.
3. Optional integrity present and missing for git, GitHub, and tarball.
4. `BunKindUnknown` for shape mismatches (missing or wrong-type registry, INFO,
   integrity, or tag; extra elements), unrecognized forms, and `file:x.tgz` staying
   a folder.
5. Split failures: empty tuple, null and non-string first element, no `@`, and an
   empty resolution, each kept as a record with the specified states.
6. Empty strings as values; deterministic ordering by `Key`, including repeated
   names under different keys.
7. `Info` copied unchanged and non-aliasing; digest copied; no effect from later
   document mutation.
8. Empty `packages`, nil and non-array guards, and exact 20,000/20,001 record
   boundaries.

The implementation must show a failing-then-passing test cycle and passing
`go test ./...` and `go vet ./...` for the root module.

## Resolved questions

- The issue proposed splitting at the last `@`; Bun splits at the first `@` after
  index 0, and this specification follows Bun.
- Tarballs have no dedicated prefix. Bun treats `http(s)://` URLs without a git
  host and paths ending in `.tgz`, `.tar.gz`, or `.tar` as tarballs; this
  specification recognizes those forms and leaves others unknown.
