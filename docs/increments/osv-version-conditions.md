# OSV version-condition evaluation

## Status, intent and authority

**Written specification/plan approved; local implementation verified; peer review pending.**
The owner selected evaluation of OSV version conditions as the next product increment,
reviewed and approved this complete specification and its separate
[implementation plan](osv-version-conditions-plan.md), then explicitly authorized
inline local execution, synthetic offline checks, restored mutations, evidence in
these two documents and scoped local jj commits. The new workspace starts from
integrated `development` `2c1cad8653e801a1395c2e372a76979dd54c8067`. No GitHub
issue number is reserved by this filename. Agents, acquisition, probes, CI, GitHub
coordination/publication and independent review/integration remain separate.

The goal is to turn existing evidence into executable version-condition decisions,
not add another raw reader. Success is passing the 64 remaining R/A/U reference
cases and preserving uncertainty, original evidence and valid positive alternatives.
This is one step toward an offline investigation, **not a runnable scanner or a
confirmed advisory finding**. It introduces a derived internal evaluation surface;
existing readers, projections and CLI interfaces stay unchanged.

Sources: [matching decisions](../design-decisions.md#10-advisory-matching-semantics),
[#15 fixture contract](issue-15-osv-version-fixtures.md),
[#14 structure contract](issue-14-osv-range-structure.md),
[#35 strict SemVer](issue-35-strict-semver-primitives.md),
[#20 coverage contract](issue-20-coverage-partial-results.md) and
[collaboration](../github-collaboration.md).
Their original queue-status paragraphs are historical: the cited deliveries are
integrated in this base. Their integration does not authorize this increment.

## Smallest delivery and exclusions

Later implementation, if approved, owns only:

- `internal/intel/osv_version_conditions.go`
- `internal/intel/osv_version_conditions_test.go`

It reuses `ParseSemVer`, `CompareSemVer`, `CheckOSVRangeStructure`, existing
projection types and private `ParseError` categories. There is no dependency,
reader rewrite, generic evaluator framework or new shared/public/wire schema.
Specification and the later plan remain under `docs/increments/`.

Excluded: package identity/origin correspondence, malicious/vulnerability source
classification, advisory activity/withdrawal/corrections, confidence/enforcement,
full matching, installed observations, discovery, filesystem/state access,
freshness, snapshots on disk, HTTP/feed acquisition, target/package-manager
execution, report rendering, worker IPC, CI, fuzzing, native probes and releases.
`ECOSYSTEM`, GIT and unknown range types remain unevaluated; SemVer ordering is
not substituted for npm ecosystem or dependency-selection semantics.

## Proposed concrete internal API

```go
type OSVVersionOutcome uint8

const (
    OSVVersionIndeterminate OSVVersionOutcome = iota
    OSVVersionNoMatch
    OSVVersionMatch
)

type OSVVersionProblemKind string

type OSVVersionProblem struct {
    Kind OSVVersionProblemKind
    VersionIndex, RangeIndex, EventIndex int
}

type OSVVersionSupport struct {
    VersionIndex, RangeIndex int
}

type OSVVersionEntryDecision struct {
    Index int
    State OSVFieldState
    Outcome OSVVersionOutcome
    FullyEvaluated bool
    Support []OSVVersionSupport
    Problems []OSVVersionProblem
}

type OSVVersionConditions struct {
    SourceSHA256 [32]byte
    HeaderSchema OSVHeaderSchemaState
    Query SemVer
    State OSVFieldState
    Entries []OSVVersionEntryDecision
    Problems []OSVVersionProblem
}

func EvaluateOSVVersionConditions(
    header OSVHeader,
    affected OSVAffectedProjection,
    query SemVer,
) (OSVVersionConditions, error)
```

The function consumes unchanged successful header/affected projections from the
same unchanged successful document, without concurrent mutation. Basic guards do
not authenticate fabricated representations or digests. Query is a successful
strict parser value or an unqualified zero value; missing or rejected query evidence
must not be rescued by inventing a version. Same-package fabrication of private
SemVer fields and unsafe mutation remain outside its preconditions.

- Preserve source digest, header profile, query exact text through immutable
  `SemVer`, affected-list state and each source slot/index. Do not aggregate
  different affected package entries into one package/advisory match.
- A usable affected list has nonnil `Entries`, including an empty list. Otherwise
  `Entries` is nil and a root `affected-uninspectable` problem records the gap.
  An empty affected list produces no synthetic entry or global no-match assertion.
- An unsupported/uninterpretable header or unqualified query blocks all positive
  and negative decisions. Preserve slot shapes/indices, use indeterminate with
  `FullyEvaluated=false`, and record the applicable root problem(s). Do not pretend
  an unqualified query has the concrete string `"null"` or `"0.0.0"`.
- Unusable affected slots remain indeterminate with their original state/index;
  they do not disappear. Their entry problem is `affected-uninspectable`.
- `FullyEvaluated` refers only to that slot's version-condition alternatives,
  never inventory, advisory applicability, scan coverage or safety.
- Successful `Support`/`Problems` slices are owned, nonnil empty slices when
  inspected and empty. Blocked/uninspectable decisions have nil support. Output
  mutation cannot change inputs or another output; no source arrays are sorted in
  place. Successful query text is potentially sensitive, not public-output-safe.

Support references either an exact-list member `(VersionIndex>=0, RangeIndex=-1)`
or a winning range `(VersionIndex=-1, RangeIndex>=0)`. Preserve every qualifying
positive member/range, including repeated source slots, in versions-then-ranges
source order. Supporting event evidence remains available through that range's
unchanged original indices/document; it is not duplicated or normalized here.

## Enumerated versions

A value list is inspectable, including empty. Every member is independently
qualified with strict SemVer; absent/null/invalid members, rejected text and
per-text limits remain problems, not silently discarded negative alternatives.
Membership uses **exact original text equality**, not equal SemVer precedence.
`1.0.0+one` and `1.0.0+two` compare with equal precedence but are different members.

A qualified matching member supports a positive despite an unusable sibling,
with `FullyEvaluated=false`. Without a positive, an unusable member prevents
no-match. Absent or empty optional lists remove that alternative; null/type-invalid
lists create an unevaluated alternative. Neither absence nor an empty list alone
establishes a usable version condition.

## SEMVER ranges

Reuse the existing supported v1 structure checker. A range must have a satisfied
structure result and exact type `SEMVER` before semantic evaluation. Unsupported
types and unsatisfied structures stay indeterminate with locators; a structurally
satisfied ECOSYSTEM range still has no qualified comparator in this increment.

Qualify **all** bounds in a range before allowing it to support a positive or
negative. An unknown/malformed/limited condition inside that range cannot be
ignored because another event or limit appears to prove a match.

1. Only exact `introduced:"0"` is the minus-infinity sentinel. Only exact
   `limit:"*"` is the infinity sentinel. All other bounds require strict concrete
   SemVer; `fixed:"0"`, `limit:"0"` and `limit:"*suffix"` stay indeterminate.
2. Evaluate a separate derived event view ordered by SemVer precedence, with
   introduced-zero before all concrete versions. Preserve source order/indices
   and duplicates in the input and retain them for diagnostics.
3. Different non-limit transition kinds at equal precedence make the entire
   range indeterminate, including build-distinct texts of equal precedence.
   Do not select a tie winner from source order or sorting implementation.
   Identical-kind duplicate transitions and alternative limits are not this tie.
4. Limits are alternatives: any qualified limit above the query, or infinity,
   permits transition evaluation. No recorded limit means an implicit unbounded
   evaluation ceiling, not a fabricated source event. Query equal to a concrete
   limit fails that limit. Do not intersect limits or choose their minimum.
5. Starting unaffected, applicable introduced transitions set affected for
   `query >= introduced`; fixed transitions clear it for `query >= fixed`;
   last_affected transitions clear it for `query > last_affected`. This preserves
   inclusive introduced/last_affected and exclusive fixed. Apply qualifying
   transitions in derived precedence order, never source-order heuristics.
6. Do not impose first-introduced, alternating events or ascending source order.
   A fixed before an introduction and repeated transitions have the exact #15
   expectations. Preserve the checker's prohibition on mixed fixed/last_affected.

A completely qualified range contributes match/no-match only for its version
condition. Prereleases follow SemVer ordering, not npm dependency-selection
prerelease filtering. Build metadata is ignored for range precedence only.

## Alternative aggregation and explicit uncertainty

Within one affected slot, enumerated versions OR individual ranges contribute:

| Qualified alternatives | Outcome | FullyEvaluated |
| --- | --- | --- |
| At least one positive; no unevaluated alternatives | match | true |
| At least one positive; an unusable/unsupported sibling | match | false |
| At least one usable condition, all fully evaluated negatives | no-match | true |
| No positive and an unevaluated alternative | indeterminate | false |
| No usable condition (only absent/empty lists) | indeterminate | false |

A range containing an internal unresolved condition is not a qualifying positive
clause. A positive version-only result never bypasses header/query gates or the
future identity/origin/activity requirements. No-match is neither a safety verdict
nor proof there are no active advisory records or installed packages.

## Guards, bounds and controlled diagnostics

Validate consumed layout and all budgets before allocating decisions, even when
header/query qualification blocks evaluation. Reuse range structure guards for
same digest, parent/list/member shape, sequential locators and the existing
20,000 affected-slot / combined 20,000 range-event-field bounds. Also validate
version-list/member representation and its existing cumulative 20,000-slot bound;
non-value lists have nil entries and null/invalid affected parents have unavailable
children. Unknown enum/contradictory consumed representation is invalid-shape.

A new **4 MiB cumulative consumed-text allowance**, inclusive, counts every
version string, range type, event field name and event value inspected across
all affected slots, including unsupported conditions and repeated strings. Count
by byte length without scanning/copying large text first; never deduplicate the
work allowance. Query retains #35's separate inclusive 1 MiB maximum. This mirrors
the original reader's 4 MiB envelope while bounding direct projection consumers;
it is not a new reader limit or hard RSS promise. Limits apply to the whole call,
not per affected slot, and must use checked remaining-budget arithmetic.

Per-text SemVer rejection/1 MiB limitation inside an otherwise bounded call is a
semantic problem, not a negative. Cumulative/layout failure returns whole-zero
`OSVVersionConditions` and existing `*intel.ParseError` with exactly:

- `intel: invalid-shape` for incoherent consumed representations/digests.
- `intel: limit-exceeded` for cumulative structural/text work bounds.

No partial success accompanies those fatal errors. Callers must represent the
failure as an evaluation gap, not replace it with an empty successful result.
Semantic problems are fixed typed kinds, with only numeric source locators:

| Exact kind | Meaning |
| --- | --- |
| `header-unsupported` | No supported v1 semantic profile |
| `query-unqualified` | No qualified concrete query |
| `affected-uninspectable` | Root list or affected slot unusable |
| `versions-uninspectable` | Present unusable versions list |
| `version-outside-profile` / `version-limit` | Member grammar / per-text work gap |
| `range-outside-profile` | Unqualified range type/comparator |
| `range-structure` | Range structure not satisfied |
| `bound-outside-profile` / `bound-limit` | Event bound/sentinel / per-text work gap |
| `precedence-tie` | Ambiguous different-kind transitions |
| `no-usable-condition` | No usable nonempty version condition |

Unused locators are -1, never invented zero indices. A root problem has all -1;
entry membership supplies the affected index. Structure problems reference the
range; its existing structure projection retains detailed source-event diagnostics.
Bound/tie problems reference each offending source event, in original event order.
For multiple entry problems, order list-level/member problems before range-level
problems, ranges/events by source indices, then no-usable-condition if applicable.
Never echo raw values, event field names, decoder text, lengths or secrets.
No logging, report rendering, clocks or exit side effects occur.

## Acceptance and review sequence

1. Owner reviews this written specification. Resolve substantive changes here
   before preparing a separate implementation plan; no code is authorized yet.
2. The plan maps all **R01–R28, A01–A20, U01–U16** unchanged from #15 to literal
   expectations and this API. R cases wrap one SEMVER range; A cases preserve
   optional-list states; U01/U03/U15/U16 retain header/query/root/member gaps.
   It adds representation, ownership, diagnostic and exact-budget boundaries.
   Existing 50 S/O primitive cases are reused, not copied into a second parser.
3. Obtain separate complete-plan approval and explicit local execution authority.
   Observe compilation/API RED separately from behavioral RED, implement only
   the two owned Go files, and rerun focused/full offline tests and vet.
4. Required regression checks distinguish fixed/last_affected inclusivity,
   prereleases, literal build membership, alternative limits, sentinels,
   source-order independence, precedence ties, positive-with-unknown siblings,
   late fatal failure, privacy and cumulative budgets. Restoration precedes
   final checks. The plan chooses the smallest checks that discriminate them.
5. Review exact consumer boundaries and privacy/coverage effects, then obtain
   independent final-head review and integration under separate publication
   authority. No child/parent shipping gate closes on local tests alone.

No native, producer, feed, scanner or release qualification is claimed. CI #38
and macOS #22 remain independent; they do not block this pure in-memory delivery.
The next product steps are advisory applicability and coverage/report integration,
with separately approved scope; their implementation is not smuggled into this API.

## Observed local delivery

The implementation is scoped commit `2ddf20cf5b1c9bfe84f65f3acba4246e0219db70`,
containing only the two proposed Go files. Existing readers, projections, SemVer,
CLI, module and workflow files are unchanged. Documentary authority was written
before code, but the first scoped jj commit failed due to cwd-relative fileset
resolution; documentary commit `d4179603` was made after initial RED/GREEN and
before the code commit. It must not be described as a pre-code committed receipt.

Observed API compilation RED was followed by a compiling-stub behavioral RED
with 89 failed/0 passed tests/subtests, including all 64 R/A/U reference IDs.
The final actual workspace passes **2,897 root tests/subtests**, including **101
new** and all 64 reference IDs, with `go vet ./...` exit 0 and clean gofmt.
The compiler is local `go1.27.1-X:nodwarf5 linux/amd64`, using
`GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0`. These are owned synthetic
checks, not official-toolchain, native, producer or scanner qualification; module
acquisition settings are not an OS network sandbox.

Eleven distinct production mutations were caught and exactly restored. The first
source-order mutation survived the R18-only check because its fixed event lay
above that query; adding literal E05 at the fixed boundary caught it. Author
review also added multiple-affected-slot and root-state checks, each observed
RED against its corresponding mutation, then GREEN after source restoration.
The 64 approved reference cases and production implementation remained unchanged.

This is author self-review, not independent peer approval or reviewed integration.
No remaining in-scope critical/important issue or deferred minor was identified
in that pass. No issue/PR, push, merge, release, new agent, acquisition, target
scan, probe or hosted CI operation was performed. The original checkout and its
unrelated deletion checkpoint remain intact; the new workspace is retained.
