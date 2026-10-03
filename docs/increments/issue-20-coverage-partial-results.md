# Issue 20 — coverage and coherent partial results

## Status, scope and authority

- Tracking: [#20](https://github.com/landroval/PackTrace/issues/20); owner: landroval; **Preparation**, not Ready.
- Design agreed: four outcomes, attempt yes/no/unknown, evidence-qualified non-applicability satisfying a required scope, minimal closure/retention and a consumer map.
- Written contract: **approved by the user for documentary publication in a draft PR**. No implementation of this contract's consumers or independent peer review has occurred.
- Base: integrated development `235347cc0be03e3cc5019db40a1e3b710920be9b`, independently of open PR #29/#30/#31. Their branch-local tests are not cumulative evidence for this document.
- Separate authorization permits this approved written contract's documentary draft publication and coordination. No shared Go/public/wire schema, consumer/worker/target/native/CI execution, acquisition, ready/reviewer or merge permission follows.

## Goal and binding sources

I specify how to represent coverage without confusing findings with completion, and when independently valid partial work survives abnormal execution. This is a documentary contract for later, individually approved consumer increments. It does not collect evidence or implement a coverage evaluator, scanner, IPC decoder, reporter or policy engine.

Binding approved directions:

- [Evidence and coverage](../design-decisions.md#3-evidence-and-coverage-model): distinct evidence, four per-scope outcomes, explicit incompleteness and unknown totals.
- [Defaults/exits](../design-decisions.md#5-scan-defaults-and-exit-codes) and [policy authority](../design-decisions.md#6-configuration-policy-authority-and-output): required obligations, exclusions, report-first behavior and independent exit conditions.
- [Freshness](../design-decisions.md#9-intelligence-freshness-policy) and [integrity references](../design-decisions.md#12-integrity-references-and-assurance): missing/unknown/stale data, source qualification and minimum assurance.
- [Reports](../design-decisions.md#13-report-contract), [privacy](../design-decisions.md#14-report-privacy-profiles) and [exceptions](../design-decisions.md#15-evidence-bound-exceptions): one result model, redacted output and no coverage waivers.
- [Execution architecture](../design-decisions.md#16-execution-architecture) and [wire boundaries](../design-decisions.md#26-supervisorworker-wire-contract): supervisor authority, minimal coherent closures, independent partial retention and abnormal EOF.
- [Effective-input scope](../design-decisions.md#19-effective-input-selection-and-scope) and [collaboration](../github-collaboration.md): qualified selection/root boundaries and separate shared-consumer review/execution gates.

No complete per-message lifecycle, serialized field names, protocol-version change, JSON/SARIF schema or Go API is defined here. Literal fixtures below are conceptual reference data, not a public or wire format.

## Conceptual record and authority

For each check and explicit scope, retain independently:

- Check identity and scope, the selected interpretation and source/evidence references; do not merge physical instances or silently broaden a scope.
- Whether effective trusted policy/invocation requires that scope, and whether it was selected/excluded. Inventory is a prerequisite, not an optional category flag. Default detection categories remain malicious, vulnerability and integrity; a permitted narrower selection is visible, not a complete three-category claim.
- Attempt knowledge: `yes`, `no`, `unknown`. Yes requires a qualified attempt observation; no requires a qualified decision/scheduling observation of no attempt. Missing start/traffic is not proof of no work. Neither means target package code executed.
- One qualified terminal coverage outcome, supporting reasons/evidence and relevant limitations. Until it can be qualified, an open record is not completed by default.
- Known observed/processed counts and whether a total can be qualified. A zero observed count or finished known subset does not establish zero total/complete discovery.
- Supporting-evidence validity and independently retained findings/candidates/diagnostics. Those collections are not a coverage status or completion certificate.

The supervisor establishes required/selected scope, validates records/evidence and derives report/exit conditions. Worker messages or target metadata cannot waive obligations, select public exits, accept exceptions, redact output, enable downloads or mutate/delete target/state data. Basic source/closure validation is not binary authentication, a sandbox or native access qualification.

## Four coverage outcomes and attempt knowledge

| Outcome | Qualification | Attempt knowledge |
| --- | --- | --- |
| `completed` | Defined scope known and accounted for; required applicable work finished, minimum supporting evidence valid, closure coherent, no relevant unresolved gap | `yes` |
| `incomplete` | Work attempted with unresolved scope/evidence/operation gaps, or execution/attempt cannot be qualified after abnormal/truncated information | `yes` or `unknown` |
| `not-run` | A qualified reason establishes no check evaluation: unavailable, unsupported, blocked, or explicitly excluded | `no` |
| `not-applicable` | Valid evidence establishes non-applicability for the whole stated scope; not a missing-input/unsupported shortcut | `yes` or `no`, established independently |

`incomplete` with attempt `unknown` asserts a gap, not a fabricated attempt. A lost start/closure cannot be converted into `not-run` merely because no successful attempt was observed. Deliberately blocked work with a qualified no-attempt decision is `not-run`; an attempt stopped by a limit/access failure is `incomplete`.

Unknown attempt cannot coexist with a qualified completed/not-applicable/not-run outcome. Contradictory records or attempted-completed claims without qualified closures remain unqualified/incomplete, with controlled diagnostics. Never silently coerce them to success or accept a worker's unsupported assertion of non-applicability.

### Obligation satisfaction

For a required check/scope, **completed or evidence-qualified not-applicable** satisfies that obligation. Not-applicable is not relabeled completed or recorded as an attempt if none occurred. Both must retain a qualified full scope, valid supporting evidence and coherent relevant closure.

Incomplete, not-run, exclusion, unknown scope/total required to establish scope, unqualified attempt, invalidated support and unresolved required execution all leave required coverage incomplete. Optional exclusions/gaps remain visible even if they do not set the required-coverage exit condition. Trusted policy must first validate whether an exclusion is allowed; an attempt to weaken a mandatory check is an invocation/policy error, not an allowed exclusion.

A policy exception accepts a finding only; it never changes coverage, supplies an input/reference, justifies non-applicability or makes unattempted work complete.

### Scope and aggregation

A completed known child scope remains that child's completion, not completion of unknown siblings/parent discovery. Parent completion requires qualified scope closure, all relevant obligations accounted for and every applicable child completed or validly not-applicable. No child finding count, worker exit or cached count supplies that proof.

Unknown total means **no completion percentage**. Known processed/observed counts may be shown with explicit unknown total and scope; do not divide by known subset, invent a denominator or treat a budget-truncated enumeration as closed. If all known package checks finish but discovery is unreadable/truncated/changing, discovery stays incomplete and the required aggregate has a gap.

No applicable instances after fully qualified discovery can support non-applicability for an explicitly installed-instance check scope. Missing installed evidence, absent root lock, only lockfile records, unsupported manager/platform or no known matches cannot. The full scope/evidence reason must be inspectable, not a generic `no packages found` claim.

## Inputs, snapshots and reference gaps

- Missing/corrupt snapshots before evaluation make matching unavailable: qualified no-attempt gives not-run. If evaluation began but support/scope becomes unusable, mark incomplete. Neither is a successfully empty advisory set or no-match conclusion. No implicit download.
- Stale/unknown/future-dated source freshness or overdue reconciliation prevents complete required intelligence coverage while preserving findings independently supported by usable local data. Freshness gap is not automatically byte invalidation; copy/import/failure does not refresh provenance.
- Unreadable/unsafe/changing/unqualified effective input produces explicit gaps, not silent package-lock/hidden-lock fallback or synthetic installed observations. A parser's success does not establish physical source presence, safe access, producer support or a complete effective tree.
- Missing/unverified/wrong/weak reference or unmet independent assurance is not non-applicability. Qualified no attempt gives not-run; a partial comparison gives incomplete. Valid differences already obtained remain with their own qualified references; integrity equality is not benignness and drift is not automatic malware.
- Unsupported matching/profile/ownership/workspace/native behavior stays limited/unavailable, never negative or complete. An explicit manager/profile choice cannot make unsupported behavior compatible.

Reasons are controlled classifications plus qualified references, not raw stderr/parser fragments/secrets/absolute paths. Logical examples `missing-snapshot`, `unknown-freshness`, `unreadable-scope`, `missing-reference`, `unsupported-access`, `unqualified-attempt`, `invalid-closure`, `execution-incomplete` are illustrative reason categories, **not newly frozen Go/wire enum values**.

## Minimal closure and abnormal execution

A check's completion requires a coherent closure for its stated scope and supporting records; a finding, elapsed work, no alerts, EOF or process exit0 alone is insufficient. A closure whose scope/reference/count claims cannot be verified is not completed. This contract sets the acceptance conditions, not allowed envelope ordering or exact message fields.

Global successful execution additionally requires coherent applicable check closures, valid run completion, expected EOF and normal termination with no contradictory/extra protocol traffic. Handshake/sequence/reference/limit validation remains mandatory under section26. A run-completion claim followed by panic, unexpected traffic or failed termination does not qualify successful execution.

On interruption, panic, timeout, protocol failure, truncated/partial line, unexpected EOF or limit exhaustion:

1. Preserve independently validated observations and findings while their supporting evidence remains valid, with their original scope/provenance and relevant execution limitations.
2. Preserve independently completed/validly not-applicable scopes; do not change them merely because unrelated later execution failed. Unclosed, invalidly closed or invalidated affected scopes are incomplete. Known scheduled-but-blocked no-attempt scopes are not-run; absent trustworthy attempt evidence stays unknown/incomplete.
3. Record a required **execution gap** when successful global execution cannot be qualified, even if previously closed check scopes remain completed. This is an execution condition, not a fourth detection category, invented target finding or permission to erase source facts.
4. User-established interruption remains distinct from timeout/worker death. Preserve a partial requested report where possible; no guarantee of report availability or write safety is introduced.

Late scope/evidence invalidation affects only facts that depend on it, but must affect all dependents. A finding whose necessary support is invalid/contradictory cannot remain confirmed/enforceable simply because it arrived earlier. Retain the independently valid source observation/candidate and controlled invalidation diagnostics if representable; do not retain an unvalidated raw worker claim as confirmed data. Missing an unrelated snapshot/reference does not erase an otherwise valid finding. Freshness limitations can coexist with a supported historical-version finding without pretending current complete coverage.

A supervisor-qualified contradiction in the same check's accepted closure/support set invalidates that closure's completion; it does not automatically invalidate every supporting finding. Rejected untrusted traffic is not by itself authority to erase/reclassify independently valid records; the supervisor must qualify dependency impact, otherwise retain those facts and the global execution gap. Conversely, a valid closure does not rescue an invalid finding reference. Never describe an abnormal run as globally successful because some scopes were independently completed.

## Existing exit-selector integration boundary

The current [pure exit selector](../../internal/cli/exits.go), with its [written contract](issue-19-cli-exits.md), consumes four qualified caller conditions. This document changes none of its code/API and executes no tests. A future supervisor adapter must establish:

| Condition | Required qualification |
| --- | --- |
| `Interrupted` | User interruption; not guessed from timeout, EOF or worker death |
| `ReportPreventingError` | Invalid invocation/policy or an operational failure prevents the requested report; representable check/execution gaps are not automatically this flag |
| `RequiredCoverageIncomplete` | A required obligation is not satisfied as above, or required global execution cannot be qualified; false requires positive qualification, not a default empty result |
| `EnforcedUnacceptedFindings` | Independently valid, enforcement-eligible unaccepted findings under effective policy; candidates, invalidated support, accepted findings or disabled enforcement do not set it |

Keep all four facts separately even when one code dominates. Existing precedence remains interruption130, otherwise2>3>1>0. A usable partial report with required gap gives3; failed requested report gives2 unless user interruption takes precedence. No code asserts target safety, and an empty/filtered alert UI does not establish coverage.

The CLI request parser in PR #30 supplies requests/default origins only, not effective policy or these qualified conditions. A future adapter must not treat omitted defaults, explicit exclusion, worker-provided booleans or zero Go structs as permission to weaken policy/claim coverage.

## Literal fixtures — conceptual, not executed

Unless a row names a global execution failure, its facts explicitly posit coherent normal execution and a usable requested report. `yes/no/unknown` below are qualified attempt facts, not defaults inferred from missing fields. `F1` and `F2` denote synthetic findings with independent valid support unless the row invalidates that support; they are not advisory IDs, real observations or evaluator output. Scope labels `R`/`C1`/`C2` are conceptual identifiers, not paths. `I/E/C/F` are literal qualified exit-condition booleans, in that order; numbers0/1 are false/true.

| ID | Literal supplied facts | Expected coverage/retention | Required gap; literal I/E/C/F; exit |
| --- | --- | --- | --- |
| C01 | R required; attempt=yes; full known scope finished; support valid; no findings | R completed; no findings | no; 0/0/0/0; 0 |
| C02 | C01 scope/support; F1 valid; enforcement disabled | R completed; retain F1 | no; 0/0/0/0; 0 |
| C03 | C01 scope/support; F1 valid/unaccepted/enforced | R completed; retain F1 | no; 0/0/0/1; 1 |
| C04 | R required; attempt=yes; unreadable subdirectory; known F1 valid/enforced | R incomplete; retain F1 with scope gap | yes; 0/0/1/1; 3 |
| C05 | R required; attempt=no; missing snapshot; evaluation blocked | R not-run; no manufactured no-match/finding | yes; 0/0/1/0; 3 |
| C06 | R required; attempt=no; corrupt snapshot; no usable evaluation | R not-run; no empty-feed claim | yes; 0/0/1/0; 3 |
| C07 | R required; attempt=yes; usable local data, stale freshness; F1 valid/enforced | R incomplete; retain F1 and freshness gap | yes; 0/0/1/1; 3 |
| C08 | C07 but source freshness unknown | R incomplete; retain F1 | yes; 0/0/1/1; 3 |
| C09 | C07 but future-dated source check metadata | R incomplete; retain F1; no fresh inference | yes; 0/0/1/1; 3 |
| C10 | C07 but successful source check within24h, reconciliation overdue beyond7days | R incomplete; retain F1 | yes; 0/0/1/1; 3 |
| C11 | R required integrity; attempt=no; missing reference | R not-run; missing-reference, not non-applicability | yes; 0/0/1/0; 3 |
| C12 | R required integrity; attempt=yes; C1 valid drift F1, C2 attempted comparison then reference became unusable | C1 completed; C2/R incomplete; retain F1 as drift | yes; 0/0/1/0; 3 |
| C13 | R required integrity; attempt=yes; only weak reference or unmet independent assurance | R incomplete; no verified equality/safety claim | yes; 0/0/1/0; 3 |
| C14 | R optional/unselected; policy permits exclusion; attempt=no | R not-run/excluded, visible limitation | no; 0/0/0/0; 0 |
| C15 | Invocation excludes mandatory R; effective validation rejects it before checks; attempt=no | R not-run; invalid-policy/invocation retained | yes; 0/1/1/0; 2 |
| C16 | R required; attempt=no; valid full-scope non-applicability proof; coherent closure | R not-applicable, no fabricated attempt | no; 0/0/0/0; 0 |
| C17 | R required; attempt=yes; valid full-scope non-applicability proof obtained, coherent closure | R not-applicable, attempt retained yes | no; 0/0/0/0; 0 |
| C18 | R required; attempt=no; missing source claimed as non-applicability, claim rejected; actual blocker qualified | R not-run with blocker; no accepted non-applicability | yes; 0/0/1/0; 3 |
| C19 | R required; attempt=no; platform access unsupported, explicitly blocked | R not-run; unsupported is not not-applicable | yes; 0/0/1/0; 3 |
| C20 | R required; attempt=yes; observed2/processed2 known instances finish; discovery total unknown/unreadable | Known instance scopes completed; discovery/R incomplete; no percentage | yes; 0/0/1/0; 3 |
| C21 | R required; attempt=yes; observed2/processed2/total2, all relevant scope fully closed; F1 valid/enforced | R completed; retain F1 with qualified count | no; 0/0/0/1; 1 |
| C22 | R required; attempt=yes; budget truncates enumeration; no findings | R incomplete; observed count only, not zero total/no-match | yes; 0/0/1/0; 3 |
| C23 | R required; attempt=yes; input changes/unreadable after valid F1 from independent unchanged support | R incomplete; retain F1, no input substitution | yes; 0/0/1/0; 3 |
| C24 | R required; attempt=yes; partial matching and F1 valid; user interrupt, usable partial report | R incomplete; retain F1 | yes; 1/0/1/0; 130 |
| C25 | R required; attempt=unknown; unexpected EOF without qualified attempt/closure | R incomplete/unqualified-attempt; no invented no-work | yes; 0/0/1/0; 3 |
| C26 | R required; attempt=yes; valid F1 before unclosed check EOF | R incomplete; retain F1 | yes; 0/0/1/0; 3 |
| C27 | C1 completed/closed, F1 valid/enforced; unrelated open C2 panics | C1 completed retained; C2 incomplete; global execution gap | yes; 0/0/1/1; 3 |
| C28 | All R check scopes independently completed, F1 valid/enforced; run-complete claim followed by panic | Completed scopes/F1 retained; global execution not successful | yes; 0/0/1/1; 3 |
| C29 | All R scopes completed; exit0 but missing valid run-completion/expected EOF | Completed scopes retained; global execution gap | yes; 0/0/1/0; 3 |
| C30 | R attempt=yes; supervisor qualifies contradictory accepted same-check closure/support set; F1 support independently valid | R incomplete; retain F1, reject closure success | yes; 0/0/1/0; 3 |
| C31 | R attempt=yes; supervisor qualifies direct invalidation of F1 support/reference; F2 independent valid/enforced | R incomplete; F1 not confirmed/enforceable; retain F2 | yes; 0/0/1/1; 3 |
| C32 | C31 but F2 accepted; F1 was only unaccepted enforced claim | R incomplete; retain accepted F2; no valid enforced F1 | yes; 0/0/1/0; 3 |
| C33 | R complete; F1 accepted under valid exception; evidence remains valid | R completed; retain F1/acceptance | no; 0/0/0/0; 0 |
| C34 | R incomplete; F1 accepted under valid exception; evidence remains valid | R incomplete; retain F1/acceptance; no coverage waiver | yes; 0/0/1/0; 3 |
| C35 | Valid retained F1 enforced and required gap; requested report cannot be produced | Coverage/findings still distinct internal facts; no claimed output file | yes; 0/1/1/1; 2 |
| C36 | C35 plus qualified user interruption | Retain facts where possible; no guaranteed partial-file success | yes; 1/1/1/1; 130 |
| C37 | R attempt=yes; no findings; unclosed check and worker exit0 | R incomplete; exit0/no alerts not completion | yes; 0/0/1/0; 3 |
| C38 | R optional; attempt=yes; partial work/gap; all required scopes and execution qualified; F1 valid unenforced | R incomplete remains visible; retain F1; required aggregate satisfied | no; 0/0/0/0; 0 |
| C39 | R required; prior valid not-applicable proof later invalidated; applicability/attempt now unknown | R incomplete, attempt unknown; withdraw non-applicability satisfaction | yes; 0/0/1/0; 3 |
| C40 | R required parent; full scope known; C1 completed/C2 validly not-applicable; support/closure coherent | R completed; preserve distinct C1/C2 outcomes and attempt facts | no; 0/0/0/0; 0 |
| C41 | R required; unqualified completed/no-attempt claims conflict; no qualified closure or attempt proof | R incomplete with attempt unknown; controlled inconsistency diagnostic | yes; 0/0/1/0; 3 |
| C42 | R required matching; attempt=no; no lock but manifest/installed evidence separately retained; work blocked | R not-run; preserve evidence, no fabricated zero-dependency inventory | yes; 0/0/1/0; 3 |
| C43 | R required integrity; attempt=no; fully qualified discovery proves zero installed instances in explicit scope; coherent closure | R not-applicable; no safety/no-declared-dependencies claim | no; 0/0/0/0; 0 |
| C44 | R required integrity; attempt=no; zero observed installed count but discovery incomplete | R not-run/blocked; prerequisite discovery incomplete; no non-applicability | yes; 0/0/1/0; 3 |
| C45 | C1 completed with F1 independent valid; C2 attempted work hits timeout/partial line/traffic cap before closure | C1/F1 retained; C2 incomplete and required execution gap | yes; 0/0/1/0; 3 |
| C46 | R scope completed with F1 valid; consumer hides execution metadata/SARIF notifications | Underlying completed scope unchanged; no inferred whole-target safety from UI | no; 0/0/0/0; 0 |
| C47 | C04 gap/F1 valid, portable redaction or local rendering applied | Coverage/findings/enforcement facts unchanged; only presentation differs | yes; 0/0/1/1; 3 |
| C48 | R required; copied/imported stale snapshot usable; F1 valid; failed refresh attempt did not renew age | R incomplete; retain F1/provenance, no download/age reset | yes; 0/0/1/0; 3 |

These48 authored scenarios are literal review expectations, not executed Go/matching/worker/native/report tests. Exit numbers restate the existing independently tested selector contract; this document does not execute that selector or calculate expected fixtures from it. Reason labels/profiles/count examples do not introduce corpus/target acquisition or runtime permission.

## Consumer coordination and implementation gates

| Consumer | Current reference | Contract obligation / separate next gate |
| --- | --- | --- |
| CLI exit selection | `internal/cli/exits.go`, issue19 contract above | Qualified four conditions, no default-completion inference; future adapter needs independent specification/plan/execution |
| CLI invocation requests | [#18](https://github.com/landroval/PackTrace/issues/18), PR #30 under review | Requests/provenance are not effective policy/required coverage; no dependency on its unmerged Go types |
| Inventory/scope and input decision | [#17](https://github.com/landroval/PackTrace/issues/17), PR #31 under review; design section19 | Caller-qualified states/candidate do not prove physical discovery, native safety or scope completeness |
| Intel matching/freshness and storage | Design sections9/10/25; [#15](https://github.com/landroval/PackTrace/issues/15), [#21](https://github.com/landroval/PackTrace/issues/21) | Supported source/version/origin/evidence/freshness gates independent; no matching/storage implementation adopted here |
| Supervisor and worker IPC | Design sections16/26, no operational consumer implemented in this tree | Semantic scope/evidence/closure acceptance plus existing transport limits; exact per-type lifecycle/wire implementation needs its own reviewed contract |
| Reports/privacy/SARIF | Design sections13/14, no report consumer implemented | One model, four coverage outcomes/attempt uncertainty and retained-valid findings, controlled diagnostics and no false-clean UI; public schema/renderers remain separate |

Before **any shared Go model or consumer implementation**, agree exact input/output ownership and invalidation semantics with those consumers/reviewer; approve a bounded written implementation plan and explicit execution. Document publication, approved design, issue ownership, linkage or absence of a dependency does not grant that permission. No field in this conceptual record freezes a public ABI.

## Documentary review and completion boundary

The deliverable for #20 is a reviewed contract ready to inform separate increments, not operational coverage/scanning. Author/user documentary review can establish local intent and table consistency; second-person review/integration remains separate before claiming the issue's reviewed delivery. Parents/shipping gates remain open.

I self-reviewed all four states, required/excluded/non-applicable authority, tri-state attempt, total/scope qualification, validity-dependent retention, minimal closure/global execution, consumer links and all48 rows. I clarified that only supervisor-qualified dependency invalidation affects prior valid facts, and made partial comparison/unknown-total examples explicit. I found no critical/important documentary issue or placeholder. I checked unique IDs,48 authored exit-condition rows against an independent literal16-case matrix,14 local links/anchors and unchanged existing tracked bytes. The user then approved this written contract and its separate documentary draft publication. Those checks/approvals do not execute producer/worker/matching/report semantics or Go tests and are not independent peer approval. No new root test count or toolchain qualification follows from this document-only preparation.
