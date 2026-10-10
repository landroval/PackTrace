# Opt-in npm lockfile installation-name profile

## Goal and authority

Make experimental `inspect` useful with ordinary npm v2/v3 records lacking `name`,
without turning an installation locator into authenticated canonical identity.
The owner selected identity npm as the next direction and authorized preparation.
**Approved:** the owner selected “Ejecutar y publicar apilado (recomendado)”,
authorizing this written specification/plan, inline TDD, owned checks, scoped jj
commits, issue #48 and dependent draft publication; no merge or queue cleanup.
One compact brief accompanies code; no separate documentation PR.

Workspace `npm-lock-names` starts at #47 head
`53b5c598ea87267ab8e5b03c80c1e790aac25450`. Preserve #45/#47 heads, reviews,
other workspaces and unrelated original task deletions. #47 is still draft;
publication and integration are not independent review or product completion.

## Observable command

Add `--identity-profile explicit-only|npm-lock-v2-v3` to `packtrace inspect`.
Default is `explicit-only`, preserving #47's current conservative behavior.
Both separated and attached values work; repeated/unknown flags or invalid values
return private exit 2 before consuming stdin. Keep help free of stdin reads.
The operator explicitly selects an interpretation, not producer proof, public
origin, network permission or authority from packageManager/project metadata.

The existing envelope, npm v2/v3 parser, 1 MiB wire/read ceiling, 64 records,
64 affected slots, 4,096 pairs and upstream guards remain unchanged. Still one OSV
record, portable only, offline, no input/output paths or target access.

## Name evidence and selection

A narrow inventory projection preserves three separate concepts internally:
**installation name**, **explicit record name**, and **selected comparison name**.
Bind selections to the original projection digest and record index/locator;
never mutate, canonicalize or reserialize source evidence to add a missing name.

- Explicit nonempty record names remain exact declared claims, preferred over any
  locator interpretation. A different installation name is not automatically a
  conflict: aliases can legitimately differ. This is not canonical-name proof.
- Null, empty or wrong-type explicit name blocks fallback; do not hide contradictory
  explicit evidence by taking a nicer inferred name. Missing is not the same state.
- Only an **absent** name under the explicitly selected profile can fall back.
  Known links, null/wrong-type link flags and ambiguous declaration evidence block
  fallback. Empty-key project root remains excluded from dependency analysis.
- Decode locators as metadata strings, never use filepath.Base, URL-decoding,
  filesystem traversal or opening. Supported grammar is exactly a sequence of
  `node_modules/<name>` components, with `<name>` optionally `@scope/package`.
  Support direct, scoped and nested node_modules entries. Reject absolute, drive,
  UNC, backslash, repeated/trailing separator, dot/dot-dot, percent-encoded,
  workspace-prefixed and other non-profile shapes with an explicit gap.
- This deliberately narrow name grammar is lowercase ASCII: components start with
  a-z or 0-9, then a-z/0-9/dot/underscore/hyphen; scoped names use one slash and an
  `@` prefix. Full decoded name is at most 214 bytes. This is the installation-name
  profile, not a new general canonical npm identity normalizer or producer claim.
- Scan the existing projected dependency groups across the whole lock document.
  A requirement whose trimmed string begins `npm:` marks its exact local key as an
  alias blocker, including malformed alias suffixes. Null/wrong-type requirements
  block that key. Uninspectable non-absent groups block all fallback, conservatively.
  Do not parse a requirement into a concrete version or invent resolved edges.
- If an installation name has an alias blocker anywhere in the document, preserve
  it but do not select it as canonical/comparison fallback. Whole-document blocking
  can over-block unrelated contexts; nearest-owner/hoisting resolution is deferred,
  not silently approximated. Preserve explicit record names independently.
- No declaration-based alias target resolution, workspace resolution, source URL
  identity inference or producer execution in this slice.

## Correlation, presentation and uncertainty

Reuse the current same-affected-slot matcher, concrete SemVer evaluation and
withdrawal gates. Never combine another package/slot's name, version or evidence.

For explicit record names, keep existing `identity-version-only` candidates.
For locator-derived comparison names, emit a separate
`installation-name-version-only` candidate **only** when the same qualified OSV npm
slot and concrete version match and withdrawal is not declared. This is a visible
hypothesis, not canonical package correspondence, authenticity or affectedness.
Never make either kind enforcement eligible or a confirmed finding.

For the selected profile, expose constant profile/provenance/qualification labels
and opaque relationships in both formats, including a gap that canonical name
correspondence is unqualified for installation-name hypotheses. Do not label an
installation-name comparison as proven canonical identity equality.
All raw names (including inferred/alias names), paths, requirement strings, URLs,
IDs and hashes remain hidden in portable output and diagnostics. Redaction occurs
after matching through the existing allowlisted view, never by altering evidence.
Default-mode usable reports and the six original demo outputs remain unchanged;
help is updated truthfully to advertise the additional opt-in flag.

Usable partial reports still exit 3, including no candidates; fatal input/argument,
limit or output failure exits 2 without a success report. Applicability stays
incomplete; installation/integrity not run; findings empty; no clean/safe claims.

## Files, execution plan and acceptance

Permitted: new `internal/inventory/npmlock_names.go` and its test; existing
`internal/demo/demo.go`/test, `internal/inspect/inspect.go`/test,
`cmd/packtrace/main.go`/test; this brief renamed with a real issue number.
No intel API, existing raw readers/projections, modules, workflows or task ledgers
changed. Reuse projected dependency evidence, not a second lockfile parser.

1. Record explicit approval here before code; if authorized, create an owner-assigned
   child issue under #5, blocked by #46, and use its actual number/bookmark.
2. Observe literal projection/CLI behavioral RED before implementation. Add no
   speculative engine/configuration or new dependencies.
3. Implement narrow projection, explicit profile selection, shared matching and
   portable provenance/hypothesis view. Preserve default/source bytes and callers.
4. Run focused/root tests, vet/gofmt and compiled owned stdin examples in both formats.
   Mutation checks must discriminate deriving through an alias blocker and silently
   promoting a locator hypothesis to canonical/enforcement evidence. Restore exact
   bytes and repeat checks; author review is not independent review.
5. Scoped jj commits and a dependent draft PR only with publication authority.
   Never merge into a dependency branch; retarget/sync/ready/review/integration need
   their relevant later authority. No agents, native probes or actual third-party
   packages/producers/feeds executed or acquired. Do not close issues or mark Done.

Literal cases: absent direct/scoped/nested name gives a labeled hypothesis only
under opt-in; default still no candidate. Explicit same/different name is preserved;
null/empty/invalid name and link block fallback. Alias requirement valid/malformed,
null/invalid requirement and uninspectable group block derivation; unrelated context
with the same key over-blocks conservatively. Non-profile locators and case/length
boundaries yield gaps. Fixed/unsupported/withdrawn/unknown-withdrawal/cross-slot
cases retain their outcomes; record/digest bindings and source bytes unchanged.
Private markers/digests absent from both formats/errors; references coherent;
invalid/repeated profile flags never read stdin; root/default/demo regressions pass.

## Bash example after implementation (not executed during preparation)

```bash
bin="$(mktemp -d)/packtrace"
GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0 go build -o "$bin" ./cmd/packtrace
cat <<'JSON' | "$bin" inspect --identity-profile npm-lock-v2-v3 --format json
{"lockfile":{"lockfileVersion":3,"packages":{"node_modules/example-package":{"version":"1.2.3"}}},"advisory":{"id":"EXAMPLE-OSV-001","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example-package"},"versions":["1.2.3"]}]}}
JSON
# Expected 3, one installation-name hypothesis, zero confirmed findings.
```

This is synthetic development evidence on the existing modified local Go toolchain
with acquisition disabled, not named npm producer/platform qualification. Public
examples use Bash; local instructions for the operator use Nushell.

## Execution ledger

- Owner approval recorded before code; issue #48 read back with landroval,
  parent #5 and native blocked-by #46. No independent approval claimed.
- API compilation RED and compiling-stub behavioral RED observed: 30 failing
  tests/subtests; implementation GREEN retained all dependency suites.
- Root GREEN: **3,013 passing tests/subtests** (2,977 dependency + 36 new);
  focused four-package run: 1,544. Vet/gofmt clean on the modified local toolchain.
- Twelve compiled owned stdin cases ran in terminal/JSON: direct/scoped/nested
  installation hypotheses and explicit alias claim produce one limited candidate;
  alias/link/null/non-profile/fixed/withdrawal/unknown/cross-slot cases produce none.
  All usable cases exit 3, findings empty, candidates not enforcement eligible.
- For these twelve inputs, default-mode stdout/stderr/exits remain byte-identical
  to #47's executable in both formats. All six original demo scenarios likewise.
- Compiling alias-blocker bypass and canonical-kind promotion mutations failed
  their intended behavioral tests; restored exact production bytes and root checks.
- Author review found a qualification-label issue: fallback had made the existing
  explicit-record coverage completed. Added a literal failing test, observed RED,
  retained the explicit-claim gap and repeated root/vet/build checks. No evidence
  was normalized or promoted to actual canonical correspondence.
- Author review covered grammar/bounds, source/index/record binding, whole-document
  blockers, raw evidence preservation, same-slot/withdrawal gates, hypothesis kind,
  portable labels/no raw or hashes, and original/default behavior. No remaining
  in-scope important/critical issue identified; independent review remains pending.
- Publication pending at ledger write. Only the new bookmark may be pushed; keep
  the PR draft and do not merge into the dependency branch or close issues/Done.
