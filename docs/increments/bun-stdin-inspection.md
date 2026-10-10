# Bun stdin inspection: compact design and execution outline

Status: **proposed; execution/publication not yet authorized**. The owner selected
Bun stdin as the next direction. This single compact brief follows the agreed
low-ceremony increment process; no Go change, issue or PR is included in preparation.
Base: development `c4919e02b706615fdd9c51f1057359f24da49a63`.

## Usable deliverable

`packtrace inspect-bun [--format terminal|json]` consumes exactly one stdin envelope:
`{"lockfile_text":"<original text bun.lock>","advisory":{...}}`.
Default terminal; attached/separated format argument; no duplicate/unknown flags,
positionals or identity-profile flags. Help and invalid arguments never read stdin.
One supplied advisory is deliberate: Bun batch support is deferred, not implied.

Reuse ParseBunLock, ProjectBunLock, concrete SemVer and the existing OSV matching
pipeline. No Bun execution, downloads, new dependency/agent, filesystem access,
project discovery, binary bun.lockb, producer fixtures or hosted CI.

## Interpretation and source boundary

- Preserve the original decoded lock text, including JSONC comments/commas, for
  reader validation and its original-byte digest. Never synthesize npm JSON or
  replace the Bun source binding with a converted-lockfile hash.
- The existing reader accepts text versions 0–3. This remains an experimental
  interpretation subset, not a compatibility/producer qualification declaration.
- Keep projected package-key ordering, distinct records with equal tuple names,
  original source digest/index/key internally and copied field states. Package keys
  are opaque: no name inference, path access, hoist or alias-target resolution.
- Only recognized npm tuple shape plus a qualified concrete SemVer resolution
  permits version evaluation. Its split tuple name is the comparison claim, not
  its map key. Preserve exact case/spelling; never lowercase or infer absent names.
- Recognized root tuples are excluded from dependency observations by kind, not
  by empty key. An unknown/malformed array tuple stays an explicit unknown record;
  it is not silently dropped, treated as npm or mistaken for root.
- Git/GitHub, tarball, file, link, workspace and unknown records retain kind/state
  observations and explicit non-evaluated gaps. A lexical SemVer inside an
  unsupported tuple does not establish an npm/version claim. No workspace graph
  expansion; malformed source containers/entries rejected by the reader are fatal.
- Candidate requires same affected-slot qualified npm advisory identity equal to
  the tuple name, version match and withdrawal not-declared. Unknown withdrawal
  blocks; unknown version siblings preserve incompleteness. Registry/integrity
  strings are recorded metadata, never network-origin authentication or byte checks.
- Positive kind `bun-tuple-name-version-only`; source `bun-tuple`, qualification
  `tuple-claim`. No canonical correspondence, applicability, installation,
  integrity, freshness, category or enforcement proof; findings empty.

## Bounded input and portable report

Strict outer JSON: exact keys/types, nested duplicates, UTF-8/surrogates/trailing
data rejected by jsoninput.Object. Validate inner text with the existing JSONC
reader, including inner duplicates/Unicode errors. No errors echo caller content.

Wire at most 1,048,576 bytes, read at most +1. At most 64 raw package records
including roots/unknowns, 64 raw workspace entries, 64 affected slots and 4,096
comparisons. Check source counts before projection/matching; retain upstream
nested limits. Reject overflow, never truncate or let unsupported tuples evade
budgets. These bounds are not stdin deadlines, RSS limits or a network sandbox.

`packtrace.inspect.bun.v1`, experimental, supplied-metadata, portable, fixed profile
`bun-npm-tuples`; positional `package-N`/`advisory-0`. Both formats expose tuple kind,
field/query qualification, provenance, comparisons, support/problem positions,
candidates, findings and coverage. Tuple comparisons use `tuple-claim-equal` /
`tuple-claim-different`, or indeterminate when not qualified.

Do not export names, versions, keys/paths, resolution/registry/git URLs, integrity,
INFO/declarations, advisory IDs, hashes, source text or caller diagnostics.
Usable reports exit 3 even for empty/unsupported scopes; private fatal input,
metadata, budget/read/report failures exit 2. No vacuous completed record/version
coverage; recognized and unknown siblings remain independently observable.

## Compact execution proposal (requires approval)

1. Record authorization in this brief before Go. Create an issue under CLI #8 and
   link Bun inventory #3; do not close/move parent capabilities or touch #40/ledgers.
2. TDD missing API then compiling-stub behavioral RED for Bun adapter, portable
   boundary and CLI. Extract shared advisory/version matching inside internal/demo;
   keep existing public entry points and npm normalization/profile behavior.
   No public generic framework/interface or options for speculative future formats.
3. Add EvaluateBunMetadata plus inspect.ReadBun and portable rendering using the
   existing allowlist where compatible. Source-kind fields are omitted from old
   schemas/results; no default inspect/demo/batch byte changes except root help
   advertising the command. Candidate-kind selection must retain explicit/derived
   npm distinctions as well as Bun tuple provenance.
4. GREEN root test/vet/build/gofmt with GOTOOLCHAIN=local GOPROXY=off GOWORK=off
   CGO_ENABLED=0. Detect and restore compiling mutants for unknown-as-npm,
   key-derived identity, cross-slot mixing and lost source provenance. Run owned
   compiled examples in both formats and compare legacy stdout/stderr/exits with
   the integrated prerequisite executable.
5. Scope expected: cmd main/test, demo normalization/matcher/test, inspect Bun
   adapter/test (only minimal shared allowlist extraction if required), this brief.
   Existing inventory/intel readers/projections, modules and workflows unchanged.
6. Author review and final-head checks, scoped jj commit/bookmark/push; ready PR to
   development. Integrate only under the owner's ongoing own-approved-increment
   waiver after fresh combined-tree checks, no conflicts/failing checks/unresolved
   threads and exact merged-tree verification. No self-approval event; record the
   waiver, not independent approval. Keep bypass until owner orders restoration.

## Discriminating acceptance

- Ordinary/scoped npm tuples, mismatched map key vs tuple name, duplicate names
  under distinct keys, deterministic original bindings, exact-list/range/fixed edge.
- Each non-npm kind, unknown arrays including bad registry/INFO/integrity shapes,
  null/empty/wrong-type tuple head, invalid SemVer; recognized root excluded but
  empty-key npm retained. Valid siblings survive without unsupported promotion.
- Same-name/version different affected slots cannot combine; reported and unknown
  withdrawal block; match plus unknown sibling preserves gaps; empty records/slots
  never imply clear/completed applicability.
- Malformed outer/inner JSON, JSONC valid comments/trailing commas, duplicate keys,
  inner and outer invalid Unicode, read/output failure, exact/+1 wire/packages/
  workspaces/affected bounds; rejected flags/help perform no input reads.
- Both portable formats omit planted private markers in every input field/error;
  kind/provenance and all expected semantic states remain visible. Old commands,
  both npm profiles, batches and six demos retain their byte/exit contracts.

Implementation evidence is pending. Checks use the modified local Go toolchain;
synthetic/runtime-owned evidence does not qualify actual Bun/npm producers,
platforms, native acquisition, CI or a release.
