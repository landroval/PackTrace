# Bun stdin inspection: compact design and execution outline

Status: **design, compact execution, publication and integration approved**. The
owner selected Bun stdin and then explicitly chose “Ejecutar ciclo completo”,
waiving additional document handoffs, not verification. Inline execution; issue
#52, CLI parent #8, related Bun capability #3. No new agents or target access.
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
original resolution field state independently of query qualification, provenance,
comparisons, support/problem positions,
candidates, findings and coverage. Tuple comparisons use `tuple-claim-equal` /
`tuple-claim-different`, or indeterminate when not qualified.

Do not export names, versions, keys/paths, resolution/registry/git URLs, integrity,
INFO/declarations, advisory IDs, hashes, source text or caller diagnostics.
Usable reports exit 3 even for empty/unsupported scopes; private fatal input,
metadata, budget/read/report failures exit 2. No vacuous completed record/version
coverage; recognized and unknown siblings remain independently observable.

## Approved compact execution

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

## Execution ledger

- Authorization recorded before Go; shared normalization/matching interfaces reviewed.
- Ruling: this approved brief is spec, plan and ledger; no redundant documents or
  new agents. Author review and the integration waiver are not independent approval.
  Preserve all source workspaces and unrelated ledger deletions.
- GitHub rejected historical issue_id with required sub_issue_id; verified no parent
  before corrected POST, then verified parent #8. No duplicate issue was created.
- Missing-API RED, then compiling-stub behavioral RED: 34 failing tests/subtests,
  no compiler stderr. Focused GREEN; final root **3,068**, including **37 new**
  above 3,031; vet/build/gofmt clean. Acquisition disabled, local modified toolchain.
- Four compiling mutants independently failed: unknown-as-npm, key-derived identity,
  cross-slot mixing and original-source binding loss. Exact source bytes restored.
- Author review found resolution states flattened behind query qualification.
  TestBunResolutionFieldStates failed RED; original resolution state added to the
  private/portable allowlist with old-schema omission; GREEN and root rechecked.
- Nineteen owned compiled cases ran in terminal/JSON: npm/scoped/empty-key/root,
  duplicate names, non-npm and unknown siblings, invalid query, fixed/withdrawn/
  unknown-withdrawal/cross-slot, empty inventory, exactly 4,096 pairs and fatal
  package/workspace/affected/inner-input errors. Usable exit 3, fatal 2; no leaks.
- Legacy stdout/stderr/exits are byte-identical against integrated prerequisite:
  72 inspect invocations, 40 batch invocations, twelve demos. Root help alone
  advertises Bun; old identity/profile/schema behavior is preserved.
- Final review: author review (new agents explicitly excluded), not independent
  approval. No known remaining in-scope important/critical issue. Native/producer,
  project acquisition, stdin deadlines/RSS and Bun batches deliberately excluded.
- Scoped publication and exact final-head/combined/merged-tree checks pending.

## Owned example (Bash)

```bash
bin="$(mktemp -d)/packtrace"
GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0 go build -o "$bin" ./cmd/packtrace
cat <<'JSON' | "$bin" inspect-bun --format json
{"lockfile_text":"{\"lockfileVersion\":1,\"workspaces\":{},\"packages\":{\"alias-key\":[\"example-package@1.2.3\",\"\",{},\"synthetic-integrity-claim\"]}}","advisory":{"id":"EXAMPLE-OSV-001","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example-package"},"versions":["1.2.3"]}]}}
JSON
# Exit 3: one tuple-name/version-only candidate, zero confirmed findings.
```

Checks use the modified local Go toolchain;
synthetic/runtime-owned evidence does not qualify actual Bun/npm producers,
platforms, native acquisition, CI or a release.
