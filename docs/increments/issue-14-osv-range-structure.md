# Issue 14: bounded OSV range/event structure checks

Status: the written specification is approved, including the SEMVER/ECOSYSTEM
structural profile and whole-advisory input design. Implementation-plan approval
and explicit execution authorization remain pending.
Tracking: [issue #14](https://github.com/landroval/PackTrace/issues/14).
Authority: [design decisions](../design-decisions.md).
Prerequisites: integrated [header contract](issue-12-osv-header.md) and
[recorded ranges/events](11-osv-ranges.md), not npm identity qualification or matching.

## Goal and source reference

Check only a bounded set of v1 range/event structure rules over existing projections
from one advisory. Preserve source claims and uncertainty. A satisfied structure
profile is not a valid version, interval, full advisory, eligible identity or match.

Reference: [OSV 1.9.1, pinned commit
8e3305dedc0786c4869c7bb0b14564e03ec277b3](https://github.com/ossf/osv-schema/blob/8e3305dedc0786c4869c7bb0b14564e03ec277b3/docs/schema.md#affectedrangesevents-fields).
The referenced event rules require one known kind per event, at least one introduced
object, and no mixture of fixed/last_affected in one events array. Sorting is
recommended, **not required**. Multiple limit events are allowed. No first-event or
alternation rule is specified. Do not invent such rules or fabricate an implicit
limit event in recorded evidence. Only public schema text was consulted; no advisory
corpus, repository or investigated input was acquired.

## Proposed internal interface

Only new `internal/intel/osv_range_structure.go` and
`internal/intel/osv_range_structure_test.go`. Existing types, readers and projections
remain unchanged. Proposed types (internal evidence, not report/IPC schema):

```go
type OSVRangeProblemKind uint8

const (
    OSVRangeProblemUnknown OSVRangeProblemKind = iota
    OSVRangeProblemRangeNotObject
    OSVRangeProblemTypeUnusable
    OSVRangeProblemTypeOutsideProfile
    OSVRangeProblemEventsUnusable
    OSVRangeProblemEmptyEvents
    OSVRangeProblemEventNotObject
    OSVRangeProblemNoKnownEventKind
    OSVRangeProblemMultipleKnownEventKinds
    OSVRangeProblemUnknownEventField
    OSVRangeProblemEventValueUnusable
    OSVRangeProblemIntroducedNotRecorded
    OSVRangeProblemMixedFixedLastAffected
)

type OSVRangeStructureProblem struct {
    Kind OSVRangeProblemKind
    EventIndex int
    Field string
}

type OSVRangeStructure struct {
    Index int
    State, EventsState OSVFieldState
    Checked, Satisfied bool
    Problems []OSVRangeStructureProblem
}

type OSVAffectedRangeStructure struct {
    Index int
    State, RangesState OSVFieldState
    Entries []OSVRangeStructure
}

type OSVRangeStructureProjection struct {
    SourceSHA256 [32]byte
    HeaderSchema OSVHeaderSchemaState
    State OSVFieldState
    Entries []OSVAffectedRangeStructure
}

func CheckOSVRangeStructure(header OSVHeader, affected OSVAffectedProjection) (OSVRangeStructureProjection, error)
```

Consume unchanged successful header/affected projections from the same unchanged
successful OSVDocument, with no concurrent mutation. Basic guards do not authenticate
forged data or supplied digests. Copy the shared digest, header schema state and
source indices/states; never normalize, sort, deduplicate or select source bounds.

The original document and affected projection remain the source evidence. This
result adds checks/locators, not another copy of raw fields, type/repo strings,
versions or package identities. Source locators are digest + affected index + range
index, optionally event index/field. Output changes must not affect inputs and later
input mutation must not change returned results.

## Hierarchy and profile gate

- Top State retains affected.State. Preserve every affected slot, including unusable
  elements, and every range slot from enumerable lists. Index is the source index.
- Non-value affected/ranges lists have nil result Entries; value lists, even empty,
  have non-nil Entries. Unavailable parents leave unavailable child states, not absent.
  Missing/null/invalid lists are not fabricated range rows or satisfied empty ranges.
- Each range retains its State and EventsState. Source package identity/version
  usability does not control the independent range structure result.
- Only header V1Implicit/V1Declared permits profile inspection. For Unknown or
  Unsupported header states, retain the hierarchy/locators but leave every range
  Checked=false, Satisfied=false, Problems=nil. Do not apply v1 rules to another
  header profile or infer a negative. HeaderSchema explains this abstention.
- Under an inspectable header, a non-object range gets RangeNotObject; missing/null/
  invalid type gets TypeUnusable; any string other than exact SEMVER/ECOSYSTEM gets
  TypeOutsideProfile, including GIT, empty, whitespace or differently cased strings.
  These ranges have Checked=false and Satisfied=false; event rules are not applied.
  Their Problems are non-nil. Unsupported does not mean invalid OSV.
- A value object with an exact supported type has Checked=true: the bounded profile
  was attempted, even if events are unusable. Satisfied=true only when no problem
  was detected. Checked is not full schema inspection; Satisfied is not matchability.
  Checked ranges have non-nil Problems, including empty on success.
- Repo and package/ecosystem/version claims remain uninterpreted. ECOSYSTEM support
  here is generic structure only, not npm ordering or concrete-version qualification.

## Event rules for checked ranges

1. Missing/null/non-array events produce EventsUnusable. Do not inspect invented
   children or infer IntroducedNotRecorded from an unavailable event list.
2. A value empty array produces EmptyEvents and IntroducedNotRecorded. An introduced-
   only list can satisfy this profile; a closing bound is not required.
3. A null/non-object event produces EventNotObject at its original index. Preserve
   usable siblings. If any event is not an object, do not infer absent introduced
   claims from that partially inspectable list.
4. In each object inspect **all** recorded field names. Known names are exact
   introduced, fixed, last_affected and limit. Zero known names produces
   NoKnownEventKind; more than one produces MultipleKnownEventKinds. No preferred
   bound is selected. Each unknown name produces UnknownEventField with its exact
   decoded name, including the empty name; this is outside the narrow profile,
   not proof that every extension is invalid OSV.
5. Each known field must have value state and a nonempty exact string; otherwise
   produce EventValueUnusable. This minimum-string rule is the bounded profile,
   not full version parsing. Do not trim: whitespace/nonstandard nonempty strings
   are opaque structurally usable text, not qualified versions. Unknown-field values
   are not validated as bound values. Source null/invalid/empty claims remain intact.
6. Record presence of known keys independently of value usability/cardinality.
   If every event is an object and no introduced key is recorded, add
   IntroducedNotRecorded. An explicit introduced:null or multi-kind introduced claim
   is not rewritten as absent; its other problems prevent Satisfied.
7. If both fixed and last_affected keys are recorded anywhere in the same range,
   add MixedFixedLastAffected, even if other problems coexist. This does not cross
   range or affected-entry boundaries. Presence is not proof of usable bounds.
8. Preserve array order/duplicates. Do not require introduced first, alternation,
   monotonicity, non-overlap or duplicate removal. Do not compare bounds or interpret
   special values. Exact introduced:"0", limit:"*" and multiple limit events remain
   recorded claims; no missing limit is materialized.

## Diagnostics and deterministic order

Problems retain all detected bounded-profile problems rather than only one preferred
reason. Do not use OSVRangeProblemUnknown for emitted diagnostics. Range/list problems
use EventIndex=-1; event problems use the original event index. Field is "type" for
range type problems, "events" for list/range-wide issues, the exact field name for
field issues, and empty for a whole non-object range or whole event object.

For each checked range: emit an events-list problem first when applicable; then scan
source events in order. A non-object event has its one event problem. For object
events emit zero/multiple-known-kind problems before per-field problems, scanning
fields in existing lexical order. Emit IntroducedNotRecorded, then MixedFixedLastAffected
last when applicable. EmptyEvents precedes IntroducedNotRecorded. Do not generate
extra problems from children that could not be inspected.

## Bounds, basic guards and errors

Reuse the existing 20,000 affected slots and 20,000 advisory-local range/event/field
units, with unchanged counting of all range slots, event slots and object fields,
including unusable/unknown/duplicate evidence. No budget resets per range/entry and
no silent prefix. Inspect counts regardless of header/type profile abstention.

Before allocating result collections, validate digest agreement, positional indices
and basic nil/list layout against unchanged projector guarantees. An unavailable
top-level affected state or a value list/object with missing backing collection is
invalid-shape, not reader-produced absence. Non-value lists/events must not carry
fabricated child collections. These guards do not establish forged-input authenticity.
Respect legitimate unavailable children of unusable parents.

Mismatched digests/basic layout yield existing ParseError with Code invalid-shape;
excess yields limit-exceeded. Errors have exact intel: CODE messages and zero whole
OSVRangeStructureProjection, without source values or decoder diagnostics.
Semantic/profile problems are structured results, not fatal parse errors.

Original 4 MiB/depth-128 reader bounds remain the byte/depth precondition. Work is
linear in recorded slots/field names/text under those bounds; no hard RSS guarantee.
The diagnostic rules emit at most two range-wide problems plus one per event and
one per field: at most 40,000 problems under the existing range-unit budget. This is
an output bound derived from the rules, not a new source quota or truncation limit.

## Acceptance cases and verification

Use reader-valid synthetic envelopes through ParseOSVRecord, ProjectOSVHeader and
ProjectOSVAffected, except explicit basic-guard/forged-budget tests:

- All hierarchy states and nil/empty distinctions; both v1 header modes, uninspectable
  headers, and mismatched digests. Header abstention must not become a negative.
- Both supported types, GIT/unknown/type-shape cases, package/repo/version independence.
- Introduced-only, fixed or last_affected closures, multiple intervals and multiple
  limits; exact special/opaque/escaped strings, empty/null/wrong-type known values.
- Unsorted/non-alternating input and introduced after a closing claim remain structurally
  inspectable. Include distinct nonmonotonic fixtures; preserve original order/indices.
- Empty/null/non-object events, empty/unknown/multi-kind fields, valid siblings alongside
  problems, complete deterministic diagnostics, and introduced presence vs unusability.
- Fixed/last_affected mixtures within one range but not across ranges/affected entries;
  no inferred missing introduced from non-object/unavailable event parents.
- Exact/over cumulative budgets across entries and late zero-result failure, including
  abstaining headers/types; unchanged old projection budgets and source tests.
- Input/output snapshots and nested mutation ownership; old readers/shared helpers,
  inventory/Bun/module/probes unchanged. Behavioral RED before logic, fresh offline
  root tests/vet after inline review, actual counts/toolchain and synthetic limitations.

No implementation/Go verification for this draft is claimed. The current integrated
base c5337ea8 independently passed 945 root tests/subtests and vet before drafting;
that validates prior merged work, not these proposed structure checks.

## Coordination and exclusions

Keep #14 Preparation until this specification, a written plan and explicit execution
are approved. Work on issue-14-osv-range-structure-spec from integrated development,
not another open feature branch. An agreed second-person review is required before
integration. Do not close #14 or clear #15 merely because this draft exists/is approved.

No reader/shared-state changes, full OSV conformance, identity/origin qualification,
SemVer/dependency acquisition, interval/version/overlap evaluation, Git reconstruction,
matching/negative findings, withdrawals/freshness, real corpus/target access, network
execution, worker/CLI/report/storage/CI implementation, native probes or release gates.
