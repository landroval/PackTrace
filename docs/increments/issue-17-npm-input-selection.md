# Issue 17 — pure npm root-input selection

## Status and authority

- Issue: [#17](https://github.com/landroval/PackTrace/issues/17); owner: landroval.
- Design agreed: separate presence/usability, a concrete npm interpretation profile, only the two root lockfile inputs, and a fixed pure decision with preflight guards.
- Written specification: **approved by the user for documentary publication in a draft PR**; independent peer review is pending.
- Base: integrated development `235347cc0be03e3cc5019db40a1e3b710920be9b`, independently of open PR #29/#30.
- Separate authorization permits this written specification's documentary draft publication and coordination. No implementation plan/execution, acquisition/native/CI, ready/reviewer or merge permission follows.

## Purpose and binding references

I propose a pure decision over caller-qualified states for `npm-shrinkwrap.json` and root `package-lock.json`, within a caller-selected supported npm interpretation. I preserve the distinction between missing input, unverified presence, unusable evidence and a usable selection. I do not open/read/discover paths, parse bytes, run managers, infer versions/producers or choose a scan exit.

- [Effective-input selection](../design-decisions.md#19-effective-input-selection-and-scope) and [manager syntax/authority](../design-decisions.md#28-core-scan-command-and-argument-validation) govern this slice.
- [Inventory compatibility](../inventory-compatibility.md) records pinned producer/source evidence and deferred qualification, including npm12's different shrinkwrap behavior; it is not a completed compatibility claim.
- Existing [reader](../../internal/inventory/npmlock.go), [typed projection](../../internal/inventory/npmlock_projection.go) and [manifest reader](../../internal/inventory/manifest.go) remain unchanged.
- [Collaboration](../github-collaboration.md) preserves separate specification, plan/execution, publication and second-person review gates.

The existing `FieldState` describes JSON fields, not availability of filesystem inputs. I introduce a dedicated scalar state pair instead of changing/reusing that meaning. The existing `ParseError` supplies the fixed fatal `inventory: invalid-shape`; no shared error change is required.

## Scope and caller obligations

This is internal analysis data, not an operational scanner, public report/IPC schema or complete inventory. Only an eventual new `internal/inventory/npm_input_selection.go` and its `_test.go` are intended, after later approvals.

The caller supplies two records from the same qualified explicit-root interpretation/view. Availability and usability are observations/classifications, not instructions or authentication. A successful `ParseNPMLock` result validates recorded JSON structure only; it does not prove input selection, producer, native safety or physical presence at the root. This helper does not turn parser success into any of those claims.

Manifest declarations, hidden `node_modules/.package-lock.json`, installed observations, other manager inputs, bytes/digests/locators/conflicts and all underlying failures remain independently retained by the caller. They are not arguments to this function and cannot rescue an absent/unusable/indeterminate root lock. The hidden lock is auxiliary, never a fallback/effective root lock or installed-instance proof. A lower-priority root record is copied even when it does not govern selection; ignored-for-precedence is not discarded evidence or global coverage completion.

Root scoping, safe handle acquisition, source associations, stale/change checks, npm/Bun coexistence, unique auto/family interpretation and operational coverage remain outside. No ancestor/nested discovery, cache-content-as-active inference, conversion, repair, downloads, directory/environment access or package-manager execution is authorized.

## Proposed API and exact types

Entry point: `SelectNPMInput(profile string, shrinkwrap, packageLock NPMInputState) (NPMInputSelection, error)`.

| Type | Members/constants |
| --- | --- |
| `NPMInputPresence uint8` | `NPMInputPresenceUnknown = 0`, `NPMInputPresenceAbsent = 1`, `NPMInputPresencePresent = 2` |
| `NPMInputUsability uint8` | `NPMInputUsabilityUnqualified = 0`, `NPMInputUsabilityUsable = 1`, `NPMInputUsabilityUnreadable = 2`, `NPMInputUsabilityUnsafe = 3`, `NPMInputUsabilityUnsupported = 4`, `NPMInputUsabilityInvalid = 5` |
| `NPMInputState` | `Presence NPMInputPresence`; `Usability NPMInputUsability` |
| `NPMInputCandidate uint8` | `NPMInputCandidateNone = 0`, `NPMInputCandidateShrinkwrap = 1`, `NPMInputCandidatePackageLock = 2` |
| `NPMInputSelectionState uint8` | `NPMInputSelectionUnknown = 0`, `NPMInputSelectionUsable = 1`, `NPMInputSelectionUnusable = 2`, `NPMInputSelectionIndeterminate = 3`, `NPMInputSelectionAbsent = 4` |
| `NPMInputDiagnostic uint8` | `NPMInputDiagnosticUnknown = 0`, `NPMInputDiagnosticNone = 1`, `NPMInputDiagnosticProfileUnqualified = 2`, `NPMInputDiagnosticShrinkwrapPresenceUnknown = 3`, `NPMInputDiagnosticPackageLockPresenceUnknown = 4`, `NPMInputDiagnosticUsabilityUnqualified = 5`, `NPMInputDiagnosticCandidateUnusable = 6`, `NPMInputDiagnosticNoRootLock = 7` |
| `NPMInputSelection` | `Profile string`; `ProfileQualified bool`; `Shrinkwrap`, `PackageLock` of type `NPMInputState`; `Candidate NPMInputCandidate`; `State NPMInputSelectionState`; `Diagnostic NPMInputDiagnostic` |

`Candidate` records the input imposed by known precedence, not a successful read, an effective usable dependency tree or permission to access it. Present-unusable shrinkwrap therefore still records the shrinkwrap candidate. None means no governing candidate could be established or both qualified root inputs are absent; consult State/Diagnostic, never the zero candidate alone.

I copy profile text and both scalar state pairs exactly; no caller container is mutated. No slices/maps, raw paths, parser documents, derived versions, source-hash fabrication or general candidate registry is introduced. Ordinary Go string immutability applies; unsafe/concurrent mutation is unsupported. Profile text may be untrusted/private and is not a public diagnostic to echo.

A successful return has nil error and one explicit nonzero selection State/Diagnostic. Fatal return is whole-zero `NPMInputSelection` with exactly `*ParseError{Code:"invalid-shape"}` and `Error()=="inventory: invalid-shape"`. Guards do not authenticate fabricated evidence. Unknown zero selection/diagnostic are never emitted successful classifications.

## Presence, usability and coherent input guards

PresenceAbsent is an explicit qualified absence observation for that root slot, not a failed open, parse error, missing cache object or unperformed check. PresencePresent is qualified presence in the supplied view, not freshness, stable native identity, readability or compatibility proof by itself. PresenceUnknown means neither can be established.

UsabilityUsable means the caller qualified the input for this selected interpretation, not merely nonempty bytes or successful JSON parsing. Unqualified means usability has not been established. Unreadable/Unsafe describe a failed or refused access classification; neither necessarily proves existence. Unsupported/Invalid describe content/interpretation classifications for a present source. If multiple causes exist, retain them outside this one decision-primary state; do not discard source diagnostics.

Permitted pairs are exactly:

| Presence | Permitted usability | Meaning |
| --- | --- | --- |
| Unknown (0) | Unqualified (0), Unreadable (2), Unsafe (3) | No qualified presence; preserve inability/refusal to inspect |
| Absent (1) | Unqualified (0) only | No present-content/access claim in the same view |
| Present (2) | Any defined value0..5 | Presence is known; usability remains independent |

Both input pairs are checked before profile qualification/selection. Any out-of-domain enum or inconsistent pair fails the whole call, including an unusable/unsupported profile or a non-governing lower-priority record. Thus present-usable shrinkwrap does not suppress a fabricated package-lock shape.

A cached content verdict with unverified current association must not be repackaged as current present root evidence; retain that source elsewhere. The coherent-pair guard defines this API's input contract, not a native observation mechanism or source-trust proof.

## Profile qualification

Only exact `npm@8.19.4`, `npm@10.9.4`, `npm@11.6.2` qualify the bounded interpretation profile. This may be an explicit operator choice or a separately qualified unique caller interpretation; it is not producer proof or a requirement that every invocation use an explicit flag.

Empty/unknown, `auto`, family-only `npm`, different versions, whitespace/case variants, npm12, Bun/Yarn/pnpm and other text are copied but unqualified. After valid state preflight, return CandidateNone, SelectionIndeterminate, DiagnosticProfileUnqualified and ProfileQualified=false. Do not apply npm<=11 precedence to them, select a newest anchor, parse/version-normalize the text or label every outside profile invalid npm syntax.

Known-profile selection sets ProfileQualified=true; this flag qualifies only this rule, not real producer/native/inventory support. CLI types from pending PR #30 are neither imported nor changed.

## Deterministic selection and diagnostics

After both state guards and profile qualification:

1. If shrinkwrap presence is Unknown, return CandidateNone/Indeterminate/ShrinkwrapPresenceUnknown. Retain its Unqualified/Unreadable/Unsafe and the lower-priority record. No fallback, including usable package-lock.
2. If shrinkwrap is Present, it is the governing CandidateShrinkwrap. Ignore package-lock for the choice but retain its states. UsabilityUsable returns Usable/None; Unqualified returns Indeterminate/UsabilityUnqualified; the four failure categories return Unusable/CandidateUnusable. No fallback.
3. Only if shrinkwrap is explicitly Absent, consider package-lock. Unknown presence returns CandidateNone/Indeterminate/PackageLockPresenceUnknown. Present returns CandidatePackageLock and the same usability outcomes as above.
4. Both explicitly Absent return CandidateNone/Absent/NoRootLock. This is scoped observed absence of the two supplied slots, not no dependencies/findings or completed checks. Manifests/installed/auxiliary evidence survives independently.

One primary fixed diagnostic describes why this selection is unavailable/indeterminate, not every source failure. Candidate plus copied states locates usability problems. No diagnostic string includes the raw profile/target/content and no coverage/findings/exit field is returned.

A usable shrinkwrap may coexist with a present-invalid or unknown-unreadable package-lock and still govern the rule. This is not permission to erase/report the latter as complete or safe. If a selected input later changes/becomes unusable, the caller must qualify a new consistent snapshot; this function does not monitor or silently substitute it.

## Literal reference cases — documentary only

Notation: input `s`/`p` are literal `[presence,usability]` pairs. Output `q`, `c`, `state`, `d` are literal ProfileQualified, candidate, selection State and diagnostic values. Every successful row also copies its profile and both state pairs exactly; every error has the whole-zero result. This compact notation is not a report/API JSON schema.

| ID | Literal input | Literal outcome |
| --- | --- | --- |
| C01 | `{"profile":"npm@8.19.4","s":[2,1],"p":[2,1]}` | `{"q":true,"c":1,"state":1,"d":1}` |
| C02 | `{"profile":"npm@10.9.4","s":[2,1],"p":[2,1]}` | `{"q":true,"c":1,"state":1,"d":1}` |
| C03 | `{"profile":"npm@11.6.2","s":[2,1],"p":[2,1]}` | `{"q":true,"c":1,"state":1,"d":1}` |
| C04 | `{"profile":"npm@11.6.2","s":[1,0],"p":[2,1]}` | `{"q":true,"c":2,"state":1,"d":1}` |
| C05 | `{"profile":"npm@11.6.2","s":[1,0],"p":[1,0]}` | `{"q":true,"c":0,"state":4,"d":7}` |
| C06 | `{"profile":"npm@11.6.2","s":[0,0],"p":[2,1]}` | `{"q":true,"c":0,"state":3,"d":3}` |
| C07 | `{"profile":"npm@11.6.2","s":[0,2],"p":[2,1]}` | `{"q":true,"c":0,"state":3,"d":3}` |
| C08 | `{"profile":"npm@11.6.2","s":[0,3],"p":[2,1]}` | `{"q":true,"c":0,"state":3,"d":3}` |
| C09 | `{"profile":"npm@11.6.2","s":[2,0],"p":[2,1]}` | `{"q":true,"c":1,"state":3,"d":5}` |
| C10 | `{"profile":"npm@11.6.2","s":[2,2],"p":[2,1]}` | `{"q":true,"c":1,"state":2,"d":6}` |
| C11 | `{"profile":"npm@11.6.2","s":[2,3],"p":[2,1]}` | `{"q":true,"c":1,"state":2,"d":6}` |
| C12 | `{"profile":"npm@11.6.2","s":[2,4],"p":[2,1]}` | `{"q":true,"c":1,"state":2,"d":6}` |
| C13 | `{"profile":"npm@11.6.2","s":[2,5],"p":[2,1]}` | `{"q":true,"c":1,"state":2,"d":6}` |
| C14 | `{"profile":"npm@11.6.2","s":[1,0],"p":[0,0]}` | `{"q":true,"c":0,"state":3,"d":4}` |
| C15 | `{"profile":"npm@11.6.2","s":[1,0],"p":[0,2]}` | `{"q":true,"c":0,"state":3,"d":4}` |
| C16 | `{"profile":"npm@11.6.2","s":[1,0],"p":[0,3]}` | `{"q":true,"c":0,"state":3,"d":4}` |
| C17 | `{"profile":"npm@11.6.2","s":[1,0],"p":[2,0]}` | `{"q":true,"c":2,"state":3,"d":5}` |
| C18 | `{"profile":"npm@11.6.2","s":[1,0],"p":[2,2]}` | `{"q":true,"c":2,"state":2,"d":6}` |
| C19 | `{"profile":"npm@11.6.2","s":[1,0],"p":[2,3]}` | `{"q":true,"c":2,"state":2,"d":6}` |
| C20 | `{"profile":"npm@11.6.2","s":[1,0],"p":[2,4]}` | `{"q":true,"c":2,"state":2,"d":6}` |
| C21 | `{"profile":"npm@11.6.2","s":[1,0],"p":[2,5]}` | `{"q":true,"c":2,"state":2,"d":6}` |
| C22 | `{"profile":"npm@11.6.2","s":[2,1],"p":[0,2]}` | `{"q":true,"c":1,"state":1,"d":1}` |
| C23 | `{"profile":"npm@11.6.2","s":[2,1],"p":[2,5]}` | `{"q":true,"c":1,"state":1,"d":1}` |
| C24 | `{"profile":"","s":[0,0],"p":[0,0]}` | `{"q":false,"c":0,"state":3,"d":2}` |
| C25 | `{"profile":"npm","s":[2,1],"p":[2,1]}` | `{"q":false,"c":0,"state":3,"d":2}` |
| C26 | `{"profile":"auto","s":[1,0],"p":[2,1]}` | `{"q":false,"c":0,"state":3,"d":2}` |
| C27 | `{"profile":"npm@12.1.0","s":[2,1],"p":[2,1]}` | `{"q":false,"c":0,"state":3,"d":2}` |
| C28 | `{"profile":"npm@11.6.3","s":[2,1],"p":[2,1]}` | `{"q":false,"c":0,"state":3,"d":2}` |
| C29 | `{"profile":"NPM@11.6.2","s":[2,1],"p":[2,1]}` | `{"q":false,"c":0,"state":3,"d":2}` |
| C30 | `{"profile":" npm@11.6.2","s":[2,1],"p":[2,1]}` | `{"q":false,"c":0,"state":3,"d":2}` |
| C31 | `{"profile":"bun@1.4.2","s":[1,0],"p":[2,1]}` | `{"q":false,"c":0,"state":3,"d":2}` |
| G01 | `{"profile":"npm@11.6.2","s":[255,0],"p":[2,1]}` | `{"error":"inventory: invalid-shape"}` |
| G02 | `{"profile":"npm@11.6.2","s":[2,255],"p":[2,1]}` | `{"error":"inventory: invalid-shape"}` |
| G03 | `{"profile":"npm@11.6.2","s":[1,1],"p":[2,1]}` | `{"error":"inventory: invalid-shape"}` |
| G04 | `{"profile":"npm@11.6.2","s":[1,2],"p":[2,1]}` | `{"error":"inventory: invalid-shape"}` |
| G05 | `{"profile":"npm@11.6.2","s":[0,1],"p":[2,1]}` | `{"error":"inventory: invalid-shape"}` |
| G06 | `{"profile":"npm@11.6.2","s":[0,4],"p":[2,1]}` | `{"error":"inventory: invalid-shape"}` |
| G07 | `{"profile":"npm@11.6.2","s":[0,5],"p":[2,1]}` | `{"error":"inventory: invalid-shape"}` |
| G08 | `{"profile":"npm@11.6.2","s":[2,1],"p":[1,5]}` | `{"error":"inventory: invalid-shape"}` |
| G09 | `{"profile":"npm@12.1.0","s":[255,0],"p":[1,0]}` | `{"error":"inventory: invalid-shape"}` |
| G10 | `{"profile":"","s":[1,0],"p":[255,0]}` | `{"error":"inventory: invalid-shape"}` |

These41 authored reference rows are documentary expectations, not executed tests or native/producer qualification. Future tests must expand coherent-state combinations, guard both slots under every profile gate, preserve copied input/status/provenance, assert no fallback from all unknown/unusable shrinkwrap states, and prove whole-zero privacy/ownership. Fixtures/observations outside the supported profile are retained, not normalized into an eligible selection.

## Resource and completion boundaries

Two scalar input pairs and one output give constant-space decision work; exact profile comparison is bounded to the three fixed names while arbitrary outside text is retained as an immutable string. No list quota, path budget, raw-byte copying, hard-RSS claim, native observation or in-memory filesystem scaffold is added.

I self-reviewed tuple coherence, profile abstention, candidate versus usability, all41 literal expectations, caller-retained auxiliary evidence and preflight despite abstention; I identified no critical/important documentary issue. I checked unique IDs/JSON, seven local links/anchors and unchanged existing tracked bytes. The user then approved this written specification and its documentary publication. These are author/documentary checks, not independent review, selector execution, Go test results or native/producer qualification.

After written-specification approval, a separate plan must name the two Go files, independent literal RED/GREEN, fallback/profile/preflight mutations, actual-tree fresh offline tests/vet, scoped evidence and independent review. Native/source acquisition, ready/reviewer/publication/integration and global inventory/coverage/shipping acceptance remain separately gated.
