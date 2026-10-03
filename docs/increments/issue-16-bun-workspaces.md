# Issue #16: bounded Bun workspace declaration evidence

## Status and intent

I record this **approved written specification** for [#16](https://github.com/landroval/PackTrace/issues/16)
from integrated `development` commit `63b5873d747419e494432b2d1b80e10a611875d3`.
The owner explicitly approved the reviewed local draft
`ffe68e285bf10630c01a9e7adff845de0dc73af1` and separately authorized publishing only
this document/bookmark in a draft PR. I preserve its technical contract unchanged:
minimum typed evidence, independent20,000-workspace/20,000-cumulative-declaration
bounds and unchanged shared helpers. That original one-document publication did
not authorize an implementation plan or Go execution. The owner subsequently
approved the [written plan](issue-16-bun-workspaces-plan.md) and explicitly authorized
inline execution/pre-code/code/evidence publication; I record that later stage below.
No dependency/native/producer/consumer/ready/reviewer/merge authority is included.
I originally reserved #16 for landroval in Preparation under
[separate preparation-only coordination authority](https://github.com/landroval/PackTrace/issues/16#issuecomment-5971191443).
I do not base it on unreviewed PR #32/#33 or change their heads/status. After the
later authorized execution I keep #16 OPEN/In progress and PR34 draft.

I need to retain declarations recorded in each Bun lockfile workspace object,
without mistaking them for current manifest declarations, resolved package edges,
workspace discovery, installed attribution or producer compatibility. Success means
bounded, ordered, owned typed claims with source provenance and explicit unusable
states; missing or invalid evidence is not a negative finding or complete coverage.
[Design decisions](../design-decisions.md#3-evidence-and-coverage-model) remain authoritative.

## Scope and existing evidence

I add one proposed in-memory projection of the existing
[Bun reader](12-bun-lock-reader.md)'s `BunLockDocument.Workspaces`. I leave the
[package-tuple projection](13-bun-lock-projection.md), JSONC normalizer, strict JSON
reader, npm readers/projections and common types/helpers unchanged. No new parser,
resolver, framework or dependency is needed.

The current reader already requires an object of object-valued workspaces, preserves
decoded keys/raw normalized JSON and original-byte SHA-256, and accepts integer
lockfile versions 0–3. It bounds original input to 64 MiB and nesting to128 containers.
This projection consumes that reader profile; it neither widens acceptance nor
establishes actual Bun1.3.2/1.4.2 output compatibility or version-specific semantics.
I use the same name/version JSON scalar states and four group rules as the owned
[manifest projection](04-manifest-declarations.md) and cumulative allowance pattern
from [locked requirements](05-locked-requirements.md).

I choose minimum typed evidence rather than another raw-object projection or a
second raw copy in every row. All unknown fields, unsupported raw values, workspace
objects and top-level configuration remain in the original unchanged document.
Consumers needing those bytes must retain that document with its digest. The new
projection is not a self-contained raw evidence bundle, public ABI or report schema.

## Proposed exact internal interface

```go
type BunWorkspaceRecord struct {
    Location      string
    Name, Version LockField[string]
    Requirements  []DependencyGroup
}

type BunWorkspaceProjection struct {
    SourceSHA256 [32]byte
    Records      []BunWorkspaceRecord
}

func ProjectBunWorkspaces(doc BunLockDocument) (BunWorkspaceProjection, error)
```

I reuse unchanged `LockField[string]`, `FieldState`, `DependencyGroup` and
`DeclaredDependency`; I add no `Fields`, root flag, generic adapter, unavailable
state, path object or derived identity. Proposed source/test files are only
`internal/inventory/bunlock_workspaces.go` and `bunlock_workspaces_test.go`, after
written-spec/plan approval and explicit execution authorization. They do not exist
in this preparation. Code in this document is an interface proposal, not a compiled
or tested declaration.

## Input qualification and fatal guards

1. Require an unchanged successful `ParseBunLock` result; the caller must not mutate
   it before/during projection. The copied digest binds the original read bytes,
   not a reconstructed workspace JSON object. Do not recompute, authenticate or
   reconcile a forged/mutated document, or treat an all-zero digest as an absence
   sentinel. Basic guards are defensive, not input requalification.
2. Nil `doc.Fields` or nil `doc.Workspaces` returns an entire zero projection and
   exact existing `*ParseError{Code: "invalid-shape"}`. Check these before counts.
   Do not add guards on unused `Packages` or infer package presence from workspaces.
3. More than20,000 workspace members returns entire zero and `limit-exceeded`,
   before sorting keys or allocating output records. Count every key, including
   `""`, unusable field claims and repeated names under different locations.
4. Process locations in Go string order. Decode each raw workspace as a required
   non-null JSON object using existing `rawObjectMembers`. Nil/malformed/null/
   array/scalar raw values in a defensive synthetic document return entire zero
   and `invalid-shape`, not a raw decoder error or a usable prefix. These values
   cannot arise from an unchanged successful reader.
5. Project that workspace's four groups with the shared remaining declaration
   allowance. A limit failure in a later workspace/group discards every output
   row; the original document remains untouched. Earlier scalar type problems
   are retained states, not fatal errors that mask the cumulative allowance.

Only `invalid-shape` and `limit-exceeded` are fatal projection codes here; their
exact texts are `inventory: invalid-shape` and `inventory: limit-exceeded`.
Never wrap/disclose JSON, a key, name, value, path, decoder detail or partial result.
Envelope/version/duplicate-key failures belong to the existing reader, before this
projection is called; it must not duplicate or weaken that validator.

## Locations, scalar claims and provenance

- Emit exactly one row per workspace key, sorted by Go string order of the exact
  decoded `Location`. Preserve case, whitespace, Unicode, NUL/control characters,
  slashes, backslashes, absolute/traversal/URL-looking strings and overlaps as data.
  No cleaning, joining, safe-path/name qualification, root containment or following.
- Only the exact key `""` locates a recorded root workspace. Preserve it as an
  ordinary row; do not fabricate it when missing or equate `"."`, `"./"` or another
  spelling with it. Its presence does not prove discovery of a physical root.
- `Name` projects only explicit `name`; `Version` projects only explicit `version`.
  Missing => `FieldAbsent`; JSON null => `FieldNull`; string including empty =>
  `FieldValue` with exact decoded text; any other type => `FieldInvalidType` with
  empty Value. No inference from location, package tuples or another workspace.
- Unusable name/version does not suppress requirements or other usable rows. The
  same name/version under two locations yields two rows. No identity merging,
  validation, case folding, SemVer/range interpretation or package registration.
- Copy `doc.SHA256` to `SourceSHA256`; evidence locator is source digest + exact
  workspace location + scalar/group/declaration key. These are lockfile-recorded
  declarations, not independently observed current `package.json` intent. Reusing
  manifest value shapes does not merge those evidence classes.

## Dependency groups and independent allowance

For every row return exactly four `Requirements`, in this fixed order:
`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`.
Use unchanged `projectDependencyGroups` and `projectField[string]` behavior:

| Recorded group | Group state | Entries |
| --- | --- | --- |
| Missing | `FieldAbsent` | nil |
| JSON null | `FieldNull` | nil |
| Object | `FieldValue` | non-nil, possibly empty |
| Other JSON type | `FieldInvalidType` | nil |

For an object group, retain one entry per exact decoded key, sorted by Go string
order, with the existing `DeclaredDependency{Name, Requirement, State}` value shape.
String requirements, including empty strings, have `FieldValue`; null has
`FieldNull`; other types have `FieldInvalidType`. Non-value requirements have an
empty Requirement; a recorded entry is never `FieldAbsent`.

Keep each repeated membership independently across groups/workspaces, including
conflicting texts. No optional/dev/peer precedence, deduplication or repair. An
unusable group does not erase a usable sibling. Requirements such as `npm:alias`,
`workspace:*`, `catalog:`, ranges, file/Git/URL strings and private credential-looking
values stay opaque. Do not expand `catalogs`, `overrides`, peer metadata, patches,
trustedDependencies, top-level fields or package INFO into missing memberships.

The independent cumulative bound is **20,000 memberships across all four groups
of all workspaces**, not per row/group, and not merged with the workspace-row bound.
Count every member of each object group, including null/wrong-type requirements
and repeated names. Missing/null/nonobject groups have no enumerable memberships;
that is not proof that they contain no intended dependencies. Pass one remaining
allowance across successive rows; never reset it, deduplicate or count only usable
values. Decode under the existing reader byte bound, then check that group's count
before sorting/allocating its output entries. This permits intermediate decoding
allocations and does not promise hard RSS, native confinement or scanner coverage.

## Ownership, empty output and sensitive success

- On success, `Records` is non-nil, including for an empty parsed Workspaces map.
  An empty map creates no invented root row. Every emitted row has four owned
  groups; object groups have non-nil Entries, others nil. Source order in maps is
  not semantic, but source locations/names/text remain exact.
- Do not mutate the document. Returned typed strings/groups/entries must be
  independent of later raw-document mutation and other rows/groups. Mutating one
  output group's entries must not change another row or repeated membership.
  Sharing immutable Go strings is not mutable raw-byte aliasing.
- Unknown/unsupported raw bytes remain in BunLockDocument, not in the result;
  their continued retention requires the caller to preserve that document. An
  invalid-type state does not reproduce its raw value or confer a coverage result.
- Successful locations/name/version/requirements can be sensitive/hostile input,
  not trusted policy or public-log/terminal/report/IPC-safe output. No formatting,
  printing, path use, source lookup or other consumer action belongs here.

## Literal reference expectations for future owned tests

I author the following **48 documentary expectations**, not executed test counts.
Unless stated otherwise, B is the literal input
`{"lockfileVersion":1,"workspaces":{},"packages":{}}`; replace its Workspaces with W.
For a successful projection, retain the original-byte source SHA and exact rows,
scalar/group states, nil-versus-empty distinctions and whole-input nonmutation.
Locations/entries are always sorted as specified, not by a production-derived oracle.
Boundary expansions below are deterministic owned synthetic objects under64 MiB;
no target files, fixture imports or package-manager producer execution are needed.

| ID | Literal evidence/variation | Required expectation |
| --- | --- | --- |
| C01 | B unchanged | Non-nil empty Records; source SHA; no root invented |
| C02 | W=`{"":{}}` | One Location `""`; name/version absent; four absent groups |
| C03 | W=`{"apps/a":{"name":"a","version":"1.2.3","dependencies":{"x":"^1"}}}` | One exact row, value scalars and x membership; other groups absent |
| C04 | W=`{"z":{"name":"same"},"":{"name":"same"},"a":{"name":"same"}}` | Three independent rows ordered `""`, `"a"`, `"z"`; no name merge |
| C05 | W=`{".":{},"./":{},"":{}}` | Three distinct rows ordered `""`, `"."`, `"./"`; no path normalization |
| C06 | W=`{"apps/a":{}}` | No root fabricated; absent scalar/group claims preserved |
| C07 | Locations `"../private"`, `"/abs"`, `"C:\\private"`, `"file:///x"`, `"nul\u0000\n"` | Exact opaque rows; no open/join/containment or output-safety inference |
| C08 | W=`{"": {"name":"","version":""}}` | Both FieldValue with empty text, not absent |
| C09 | W=`{"": {"name":null,"version":null}}` | Both FieldNull with empty Value |
| C10 | W=`{"": {"name":42,"version":false,"dependencies":{"x":"1"}}}` | Both FieldInvalidType; usable x retained |
| C11 | W=`{"": {"name":[],"version":{},"devDependencies":{"x":"2"}}}` | Invalid scalar types; usable dev x retained |
| C12 | Name `" Ω/@synthetic\n"`, version `"v1 /not-semver"` | Exact value claims; no name/version qualification |
| C13 | W=`{"": {"dependencies":{},"devDependencies":{},"optionalDependencies":{},"peerDependencies":{}}}` | Four FieldValue groups in fixed order, all non-nil empty Entries |
| C14 | W=`{"": {"dependencies":null,"devDependencies":null,"optionalDependencies":null,"peerDependencies":null}}` | Four FieldNull groups, all nil Entries |
| C15 | W=`{"": {"dependencies":[],"devDependencies":false,"optionalDependencies":1,"peerDependencies":"x"}}` | Four FieldInvalidType groups, all nil Entries |
| C16 | W=`{"": {"dependencies":false,"devDependencies":{"x":"2"},"peerDependencies":null}}` | Preserve malformed/null/absent groups and usable dev x independently |
| C17 | W=`{"": {"dependencies":{"z":"last","A":"first","a":"middle"}}}` | Entries ordered A,a,z with exact texts |
| C18 | W=`{"": {"dependencies":{"x":""}}}` | Present FieldValue requirement with empty text |
| C19 | W=`{"": {"dependencies":{"x":null}}}` | Present FieldNull x; not absent |
| C20 | W=`{"": {"dependencies":{"a":false,"b":[],"c":{},"d":7,"ok":"1"}}}` | Four invalid-type members plus usable ok; count all five |
| C21 | W=`{"": {"dependencies":{"x":"1"},"optionalDependencies":{"x":"2"},"peerDependencies":{"x":"3"}}}` | Three separate x memberships; no precedence or resolution |
| C22 | W=`{"a":{"dependencies":{"x":"1"}},"b":{"dependencies":{"x":"2"}}}` | Two source-located x memberships; no cross-workspace merge |
| C23 | Requirements `"npm:other@^1"`, `"workspace:*"`, `"catalog:"`, `"file:../x"`, `"git+ssh://synthetic.invalid/r"` | Exact FieldValue claims; no expansion/lookup/resolution |
| C24 | W=`{"": {"peerDependencies":{"x":"1"},"peerDependenciesMeta":{"x":{"optional":true}}}}` | x retained as written; metadata only raw in document, no semantics |
| C25 | B plus top-level overrides/catalogs/trustedDependencies/patch fields and workspace unknown precise number `18446744073709551616000` | Original raw evidence unchanged; no added/filled/rewritten projected claims |
| C26 | W=`{"x":{}}`, Packages contains a tuple claiming name/version for x | Workspace Name/Version still absent; no package fallback/attribution |
| C27 | Same W parsed in separate literal v0,v1,v2,v3 documents | Same workspace claims/groups; each result carries its own original digest; no producer qualification |
| C28 | Equivalent W with JSONC comments/trailing comma and different original byte layout | Same typed evidence, each original-byte SHA; not normalized/canonical digest |
| C29 | Workspace/name/requirement duplicate keys including escaped-equivalent spelling in input | Existing reader duplicate-key failure; projection not called; no last-key-wins |
| C30 | After successful projection clear input document's raw workspace bytes | Typed rows, scalars, groups and source SHA remain unchanged |
| C31 | After projection replace/delete doc.Workspaces entry and clear doc.Fields raw data | Earlier typed projection unchanged; it does not claim to preserve raw document bytes |
| C32 | Same x in two groups/rows; mutate one returned Entries element/slice | Other membership/row unchanged; fresh second projection unaffected |
| C33 | Synthetic doc.Fields=nil and Workspaces of20,001 members | Whole-zero invalid-shape precedes row-count failure |
| C34 | Synthetic doc.Workspaces=nil, non-nil Fields | Whole-zero invalid-shape |
| C35 | Synthetic workspace raw nil/null/array/string/number/bool/malformed JSON | Whole-zero invalid-shape for each; no decoder/value disclosure |
| C36 | Keys `"a"` valid and `"z"` raw null in defensive doc | Late invalid-shape, whole-zero; no usable a prefix |
| C37 | Exactly20,000 object workspaces including `""`, all `{}` | Success20,000 rows, each four absent groups; row limit independent |
| C38 | Exactly20,001 members, with an invalid later raw entry | Whole-zero limit-exceeded before sorting/per-row shape checks |
| C39 | One workspace/group with20,000 distinct x00000..x19999 names, string `"1"` | Success at declaration limit; deterministic entry order |
| C40 | Same group with20,001 members | Whole-zero limit-exceeded |
| C41 | Two groups in one row, each10,000 memberships; repeated names across groups | Success20,000 memberships; no deduplication |
| C42 | C41 plus one member in the second group | Whole-zero limit-exceeded; no prefix |
| C43 | Two workspaces, each10,000 memberships | Success; allowance global, independent of location/name usability |
| C44 | C43 plus one member in the second workspace | Whole-zero limit-exceeded; no per-row allowance reset |
| C45 |10,000 null plus10,000 invalid-type memberships, spread over groups/rows | Success20,000 entries; all consume allowance despite unusable values |
| C46 | C45 plus one invalid membership | Whole-zero limit-exceeded; no usable-only counting |
| C47 |20,000 empty workspaces and20,000 memberships in one row | Success at both independent bounds; do not combine counters |
| C48 | Sensitive locator/name/requirement text in earlier valid row, then one extra membership over20k in later row | Whole-zero exact private limit-exceeded; no secret/path/value/partial disclosure |

These rows do not replace broader table variants. The future tests must independently
pin all scalar/group states, root/non-root locations, control/private text, invalid
siblings, exact boundaries and ownership; expected values must not come from the
production projector or generated Markdown at runtime. Reader-regression examples
such as C29 do not redefine this projection's two fatal codes. Defensive fabricated
documents exercise basic guards, not successful-reader authenticity.

## Local preparation evidence

I self-reviewed the interface and full contract against the current reader,
scalar/group helpers and previous approved evidence contracts. I checked five focus
classes below, fatal precedence versus retained bad fields, both independent
allowances, source classification, ownership, nil/empty and privacy. I found no
remaining placeholder or in-scope contradiction in this draft.

I checked48 unique ordered documentary case IDs and7 link targets/anchors, and
syntax/formatted one proposed Go API fragment with gofmt only. This does **not**
compile that API, execute fixtures or add a new root test count. All preexisting
tracked bytes/module/checklist remain identical to the integrated base. The eight
unrelated deletions are preserved in a separate local-only jj checkpoint, not this
issue bookmark. At that local draft record I changed one specification document
only: no Go source/test, plan, dependency, workspace probe, push/PR or execution.
The later written approval and one-document draft-publication authority are
recorded above; neither turns documentary expectations into executed tests.

## Review focus, exclusions and next gates

I request future review of five concrete classes:
1. Source class and opaque locators versus installed/root/workspace attribution.
2. All four group/scalar states, raw retention in the document and usable siblings.
3. Independent row count and cumulative membership allowance including repetitions,
   null/invalid requirements and late failures, without resetting/deduplicating.
4. Input/result/sibling ownership, nil versus empty and original-byte digest linkage.
5. Private whole-zero fatal errors versus sensitive internal success and inert data.

No workspace discovery/glob expansion, path containment, filesystem or package-manager
execution, producer fixtures/corpus, common effective inventory, package tuple INFO
projection, configVersion/overrides/catalogs/patch semantics, identity/origin/SemVer
qualification, dependency resolution/graphs, installed observation, matching, policy,
report/redaction/IPC/CLI, HTTP/acquisition, native/CI/fuzz/race work or release belongs
here. No shared API/helper/source/module change or probe rerun is proposed. Raw/typed
success is not complete coverage, safety, authenticity or an effective dependency tree.

I preserve the PR #32/#33 review gates and all capability/shipping parents. The
original specification-publication handoff authorized no implementation plan or
Go execution; its documentary checks were not compiled/executed evidence. The owner
subsequently approved the written plan and explicit execution described below.
Peer handoff, integration and closure still require their separately recorded gates.

## Bounded implementation evidence

I received written-plan approval and explicit **“Aprobar y ejecutar aquí”** for the
two new Go files, inline owned offline tests/vet/restored mutations, scoped commits
and pre-code/code/evidence publication in draft PR34, with #16 OPEN/In progress.
I published/read back authority `fb7fdca6f95be92025f3820b6e40fa4d20c258a8` before
creating any Go. The preceding approved plan is
`ae77c923808d8891f004345ff1f73b264de70040`; the specification/API/technical contract
is unchanged. I retained direct integrated base63b5873d and the separate local-only
eight-deletion checkpoint; no sibling merge or shared-source/module change.

I implemented only `internal/inventory/bunlock_workspaces.go` and
`internal/inventory/bunlock_workspaces_test.go` in scoped code commit
`05807188aeeabcaa5df1684804531b5bf7dc7a6c`. The production module is the approved
minimum GREEN listing with two structs and one function, reusing unchanged
rawObjectMembers/projectField/projectDependencyGroups and existing20k constants.

I observed API compilation RED (undefined ProjectBunWorkspaces and
BunWorkspaceProjection, JSON build-output), then behavioral zero/nil-stub RED:
**126 fail/5 pass tests/subtests**; all47 projection reference IDs failed. C29's
reader-only duplicate regressions and the AST purity subtest correctly passed.
I corrected one explicit-map test fixture compilation error before behavioral RED;
that failed build was not counted as behavioral evidence. Expectations use literals,
not a production oracle or runtime Markdown.

Fresh actual-tree offline root tests pass **2,350 tests/subtests**, **131 new** across
eight TestProjectBunWorkspaces suites, including all48 reference IDs and state/
ownership/privacy/boundary variants; baseline was2,219. Counts use JSON Action=pass
with nonempty Test, not packages or summed runs. Offline root vet exits0. Toolchain
is **go1.27.1-X:nodwarf5 linux/amd64**, not official/native release qualification.

I observed and restored eight mutations with original-source SHA verification:
per-row reset(6 failures), combined counters(8), usable-only consumption(4),
location-derived name(94), reversed sorting(14), late partial result(18),
private error disclosure(18), and middle boundary attribution(3). The final middle
check strengthened C37/C47 to pin every expanded row position and C39/C47 every entry
position independently. Production remained identical to approved GREEN; no mutation
is active. The final whole suite/vet was rerun after restoration/strengthening.

I author-reviewed all five focus classes against full source/tests and unchanged
helpers, with no remaining in-scope blocker or deferred minor. This is **self-review,
not independent approval**. Native containment/producer/platforms, actual resource use,
workspace discovery/effective/installed inventory, INFO/config/overrides, consumers,
public output safety, scanner coverage and all shipping/pilot/release claims remain
unqualified. I update only this evidence, the plan and one nested milestone; all85
top-level shipping items remain unchanged. #16 stays OPEN/In progress and PR34 draft;
no reviewer/ready, merge or closure is implied.
