# pnpm lockfile v9: first operational scan increment

## Goal and approval

I am implementing the owner's request to expand pnpm support with a short robust
plan, parallel agents and fast operational results. This increment reaches the
existing `scan` command; it is not a separate parser demo or full pnpm support.

The owner approved a maintained YAML dependency and up to 64 MiB of official
acquisitions, 24 pnpm invocations, five minutes of owned fixture generation and
512 MiB scratch, with scripts disabled and producer networking limited to an
owned loopback registry. This is historical scope for this increment, not a
standing grant. No system installation, VM, real target scan, advisory refresh,
native CI, publication, merge or persisted-policy repinning is included.

## Deliverable and non-goals

- Parse original `pnpm-lock.yaml` FORMAT **9.0** bytes and retain their SHA-256.
- Collect manifest declarations and distinct locked package/snapshot claims through
  the supervised scan, terminal, JSON and SARIF pipeline.
- Preserve peer-qualified snapshot contexts and aliases without turning them into
  filesystem paths or authenticated registry origins.
- Always expose pnpm installed/reconciliation coverage as incomplete, with **zero
  installed observations**. Do not traverse `.pnpm` contents as installed evidence.
- Do not perform pnpm advisory lookups or issue pnpm enforcement/integrity bindings
  in this first slice. Such checks remain incomplete, not silently successful.
- Preserve npm/Bun behavior, authority, privacy, original handles, aggregate bounds
  and exit precedence: interruption > operation/output failure > incomplete
  coverage > enforced finding > completion.

Full workspaces, `pnpm-workspace.yaml` interpretation, catalogs, patches, external
stores, generic hardlink admission, installed graph reconciliation, pnpm hooks,
`.npmrc` and executable configuration are out of scope. Non-root importers or
unsupported semantics must produce explicit gaps, not an exhaustive-scope claim.

The format profile is **`pnpm@lockfile-9`**, with `--manager pnpm` as a family
request. A format is not a producer version. Canonical stable pnpm 9/10 hints may
identify the family; other producer versions/prereleases do not automatically
qualify it. Actual producer evidence is pinned to **9.15.9 and 10.34.9** only.
The `packageManager` field must never contain the format-profile alias as a
concrete producer identity. Existing explicit-policy/hint conflict rules remain
conservative; mixed npm/Bun/pnpm inputs in automatic mode must abstain.

## Parser contract and limits

The sole runtime dependency is vendored `go.yaml.in/yaml/v3` **v3.0.6**, verified
with Go's signed checksum database. Its MIT and Apache-2.0 portions and original
NOTICE remain separate and retained. No pnpm runtime is required by PackTrace.

Pure-memory APIs in `internal/inventory`:

```go
func ParsePNPMLock(data []byte) (PNPMLockDocument, error)
func ProjectPNPMLock(doc PNPMLockDocument) (PNPMLockProjection, error)

type PNPMDependencyReference struct {
    Group, InstallationName string
    Specifier, Reference LockField[string]
}
type PNPMImporterRecord struct {
    Location string
    Requirements []DependencyGroup // locked claims, never manifest declarations
    References []PNPMDependencyReference
    Unsupported bool
    Problem string // fixed code for unsupported importer semantics
}
type PNPMLockedRecord struct {
    PackageKey, SnapshotKey string
    Name, Version, Integrity, Tarball LockField[string]
    Requirements []DependencyGroup
    Kind string // package for registry-shaped claims, unknown otherwise; no authority
    Unsupported bool
    Problem string // fixed privacy-safe code, never raw input
}
type PNPMLockProjection struct {
    SourceSHA256 [32]byte
    Importers []PNPMImporterRecord
    Records []PNPMLockedRecord
    Unsupported bool // root features outside this first subset
}
```

`PNPMLockDocument` exposes its SHA256 but keeps retained original YAML nodes and
valid-parse state private. It owns parsed storage; no YAML-library type leaks into
collector/wire/report types. Existing `LockField`, `DependencyGroup` and
`ParseError` are reused. The original manifest remains the only source of declared
observations; importer specifiers are only locked claims.

New parser ceilings are **1 MiB raw bytes, depth 64, 100,000 nodes, 64 KiB per
scalar, 20,000 total importer/package/snapshot records and 20,000 aggregate
requirements/references**, plus **8 MiB of aggregate projected string bytes**
including metadata repeated across snapshot contexts, without increasing the
collector's existing limits.
The raw-byte ceiling is checked before the maintained decoder runs. Node decode
must not expand aliases; its own recursion/alias protections are reviewed, and
untrusted production parsing remains inside the existing supervised worker.

Require one mapping document and format text exactly `9.0` (quoted string or the
plain canonical float-tagged scalar only; no numeric conversion/equivalents).
Reject invalid UTF-8, duplicates at every depth, non-string/complex keys, anchors,
aliases, merge keys, explicit/custom tags, additional documents and exceeded
limits. Do not leak upstream parser diagnostics or target strings.

Known sections are typed strictly. A null/wrong-type section is not an empty
mapping. An empty project may have no packages/snapshots; importers must still be
well formed. Preserve unknown fields as uninterpreted source evidence, not
qualified semantics. Unsafe/unsupported identity or resolution forms remain
explicit unsupported records. Snapshot/package joins require validated bounded
keys; unmatched snapshots and metadata-only package records stay visible.
Records are deterministic and snapshot contexts remain distinct. Unsupported
importer references, explicit source IDs and root patch/unknown feature claims
produce explicit unsupported signals and coverage gaps; they are not silently
converted into ordinary registry claims. Parent validation requires all three
mandatory installed/reconciliation/workspace limitations. No locked key can
authorize native access or stand in for an installed location.

## Implementation order and ownership

1. **Owner/integrator:** dependency/license pinning, this contract, actual producer
   fixture receipts/corpus and generation tooling. Preserve original checkout
   changes; use an isolated jj workspace based on current development.
2. **Parser agent:** exclusively `internal/inventory/pnpmlock*.go` and parser tests.
   Start with failing acceptance/adversarial tests; implement the API above.
3. **Integration agent:** manager profile, CLI/policy gates, project selection and
   collection, wire/frozen-authority validators, integrity/report consumers and
   actual CLI tests. No parser-file edits; use the agreed API. Do not weaken an
   implicit npm-versus-Bun assumption into an unconditional third-manager grant.
4. **Owner/integrator:** combine isolated changes, resolve seams and update English
   and Spanish current documentation. Canonically regenerate vendor after the
   actual import exists. Current alpha.1 release artifacts remain unchanged and do
   not gain pnpm support retroactively.
5. **Independent review agents:** inspect parser attacks and end-to-end evidence,
   privacy, coverage and regression behavior. Fix blockers before the final tests.

Agents use disjoint isolated workspaces/ownership, not concurrent edits to shared
files. Acquisition and producer execution are performed only by the owner agent;
subagents receive no authority to renew those budgets or read real projects.

## Acceptance checks

- RED/GREEN parser tests for original digests/ownership, real producer locks,
  aliases, scoped names, distinct peer contexts, malformed keys/shapes, nulls,
  duplicate unknown fields, tags/anchors/aliases/multi-document attacks and bounds.
- Selection tests for sole/mixed locks, uncertain/unsafe presence, explicit family,
  format policy, concrete hint conflicts and unsupported formats. No fallback.
- Actual owned CLI scans in terminal/JSON/SARIF with physically disjoint temporary
  configuration/source parents; zero installed observations, explicit missing
  coverage, safe output, no target mutation and confirmed cleanup/exit 3.
- Forgery tests for pnpm installed observations, false completion, profile/file
  mismatches, switched source digests, invented correspondences and accidental
  integrity/advisory authority. Parent validation must fail closed.
- Full offline root tests and vet; affected parser/collector/policy/execution race
  tests and bounded parser fuzzing where practical. Windows cross-compilation is
  compile-only, not Windows execution or release qualification.
- Real producer captures preserve original YAML and distinguish generated cases
  from supported cases. Workspace captures are negative coverage evidence, not
  workspace support. Record failures, consumed reservations and reaps honestly.
- Final diff excludes unrelated `.pi/` changes, workflows, user setup and product
  release assets. Commit locally; do not publish or replace the installed binary.

## Progress evidence

Implementation receipts and budgets remain outside the source tree. This plan is
not a successful-test record; final executed results and remaining gaps must be
recorded separately after integration.
