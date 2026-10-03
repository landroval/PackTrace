# Issue #21: bounded in-memory intelligence snapshot manifest

## Status and intent

I record this **approved written specification** for [#21](https://github.com/landroval/PackTrace/issues/21)
from integrated `development` commit `63b5873d747419e494432b2d1b80e10a611875d3`.
The owner explicitly approved the reviewed local draft `66cd372391f9b7157bede60dadeb728ccf67ce71`
and authorized publication of its one-document bookmark/draft PR. This approves
this contract alone; the later [approved implementation plan](issue-21-intel-snapshot-manifest-plan.md)
and pre-code authority `ced92531da31aa8c16fab9157455d81a05882521` separately authorized
inline reader/tests, offline checks, restored mutations and scoped draft publication.
I preserve the technical contract unchanged. I implemented the two-file slice in
`aac473dbc062dedd80839b6600b49266c0562457`: fresh 2,578 root tests/subtests (359 new)
and offline vet pass. This is author verification, not independent review.
I keep #21 open/In progress, PR #33 draft and its [storage parent #9](https://github.com/landroval/PackTrace/issues/9) open.

I need a small manifest that names immutable snapshot objects and retains acquisition
claims without mistaking metadata for verified content, publisher trust or freshness.
This slice defines one internal, PackTrace-owned format, not an upstream feed schema,
a public report/IPC ABI, a working store or an operational snapshot.

I choose one strict-core reader with retained evidence over a raw-reader/qualifier
pair, explicit 256 slots over a partial-object list, and temporal interpretation over
an additional recency evaluator. I add no abstraction/dependency for unimplemented
storage consumers. [Design sections 8/9](../design-decisions.md#8-synchronization-and-recovery)
and [25](../design-decisions.md#25-filesystem-backed-snapshot-and-object-layout) remain authoritative.

## Scope and future surface

After written-spec and plan approval plus explicit execution authority, I propose:

```go
type SnapshotObjectReference struct {
	Fields         map[string]json.RawMessage
	SHA256         [32]byte
	Bytes, Records uint64
}

type SnapshotBlockReference struct {
	Index     int
	Reference SnapshotObjectReference
}

type SnapshotSource struct {
	Fields                                      map[string]json.RawMessage
	ID                                          string
	Locator, AcquisitionMethod, Attribution     OSVString
	AcquiredAt, ExportedAt                      OSVTimestamp
	LastSuccessfulCheck, LastFullReconciliation OSVTimestamp
}

type SnapshotManifest struct {
	SHA256        [32]byte
	Fields        map[string]json.RawMessage
	SchemaVersion string
	Source        SnapshotSource
	Originals     SnapshotObjectReference
	Blocks        []SnapshotBlockReference
}

func ParseSnapshotManifest(data []byte) (SnapshotManifest, error)
```

I use only a new `internal/intel/snapshot_manifest.go` and its synthetic tests.
I reuse `internal/jsoninput.Object`, the existing `intel.ParseError`, and the
unchanged OSV temporal grammar where the contracts coincide. I do not rename or
extract a shared helper, change the OSV reader/JSON validator, introduce policy,
modify the Go module or implement any filesystem consumer.

The successful internal analysis value records the original-byte SHA-256, exact
schema string, retained top-level raw fields, source fields, the originals-index
reference and 256 positional block references. Each reference retains its raw fields
alongside decoded digest/bytes/records; each block also records its slot index.
`Reference.Fields` contains the entire original block object including `index`;
there is no `reference` wrapper in the JSON. Every successfully decoded object
has nonnil `Fields`; successful `Blocks` is nonnil with exactly 256 owned entries.
Source temporal claims retain state, exact decoded text and an interpreted UTC
instant only when usable. I reuse `OSVTimestamp` solely for that identical syntax
contract, not OSV record/withdrawal/freshness semantics. I reuse `OSVString` solely
for decoded string states: Absent/Null/InvalidType/Value, never Unavailable under
the required inspectable source parent. Neither scalar type nor helper is changed.
The implementation plan must preserve these concrete fields and semantics.

All maps/raw bytes/slices are owned. The caller must not mutate `data` concurrently.
Input mutation after return, or mutation of one retained parent raw field, must not
change a separately decoded nested record or another returned raw field. No shared
mutable singleton or concurrent worker is needed. Time-zone objects are immutable.
Successful raw metadata can be sensitive; this is **not log/report/IPC-ready output**.

## Strict core format 1.0

Field names and source text are exact and case-sensitive; I do not trim, normalize,
case-fold, decode paths or infer source/producer authority. Unknown members at every
object level remain owned raw evidence; they grant no new semantics or capabilities.

| Location | Required core value | Interpretation |
| --- | --- | --- |
| root | nonnull JSON object | One original-byte evidence document |
| `schemaVersion` | exact string `"1.0"` | This manifest profile only, not report schema or OSV version |
| `source` | nonnull object | Claimed provenance, not an authenticated source |
| `source.id` | nonempty string, 1..256 UTF-8 bytes, no NUL | Opaque identifier, not a URL/path/config selector or allowlist |
| `originals` | nonnull reference object | One immutable index of original-advisory references, not the advisory bytes themselves |
| `blocks` | array of exactly 256 reference objects | Slots 0..255, complete declarations rather than inferred omissions |
| `blocks[i].index` | canonical nonnegative integer literal equal to `i` | Original array position must match the declared slot; no sorting/repair |
| every reference `.sha256` | exactly 64 lowercase ASCII hex digits | Fixed SHA-256 bytes, no prefix/URI/alternative algorithm |
| every reference `.bytes` | canonical nonnegative integer literal | Declared byte length, not measured reads or disk usage |
| every reference `.records` | canonical nonnegative integer literal | Declared record units for that role, not verified completeness |

Missing/null/wrong-type core members reject the whole manifest. An empty schema
string is invalid-shape; any other nonempty schema string except `"1.0"` is
unsupported-version, including `"1"`, `"01.0"` or `"1.0.0"`. I do not invoke SemVer
or infer compatibility. I validate the entire JSON envelope first, then the version
gate, then this known profile; I do not reinterpret a future profile's reference shape.

Canonical integers are raw JSON `0` or `[1-9][0-9]*`, ignoring JSON whitespace
outside the token. Negative/`-0`/fraction/exponent/quoted/bool/null forms are
invalid-shape. Integer spelling with a forbidden leading zero is invalid-json.
I retain unknown-number precision and never decode required counts through float64.

A reference with declared `bytes=0` must have `records=0` and exact empty-byte digest
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
This is a mathematical empty-byte constraint, **not evidence the object exists**.
Declared `records=0` may coexist with positive bytes: this reader does not freeze
or parse the index/block content schema, infer absence, or decide whether such bytes
are valid for that future schema. A structurally accepted reference is not validated content.

Repeated digests are allowed, including shared empty objects. All references to the
same digest must declare the same byte length. Repeated projection-block digests
must also declare the same record count; originals-index versus block counts use
different roles, so I do not force those counts equal. Conflicting claims are
invalid-shape, not arbitrary first/last-wins selection. Declared counts per role
need not equal each other; one original advisory may support several projections.
No identity-to-slot routing, advisory/projection binding or hash collision handling
is proven by this coherence check.

I calculate manifest identity from **exact original bytes**, including formatting;
there is no self-referential wire digest/id or invented canonical reserialization.
Object locators must eventually be derived from digest bytes by an approved safe
store consumer; an unknown path member or source locator is never an opening instruction.
I cannot activate a manifest merely because this parser returns successfully.

## Acquisition and temporal claims

Within the required `source` object I retain all raw members. I explicitly project
optional `locator`, `acquisitionMethod` and `attribution` as exact string claims:
absent, null, invalid-type or value, with empty/unknown strings retained as values.
These are evidence, not downloader configuration, licensed-use approval, trusted
operator policy or an allowlisted endpoint. I open no URI, infer no registry origin,
and grant no import/check permission based on `acquisitionMethod` text.

I project optional `acquiredAt`, `exportedAt`, `lastSuccessfulCheck` and
`lastFullReconciliation` independently with the unchanged temporal profile in
[the OSV-times contract](08-osv-times.md):

- Absent/null/wrong type remain distinct; a string outside the temporal profile is
  uninterpretable, with exact text retained. None rejects otherwise valid core refs.
- Four-digit calendar years, exact uppercase T/Z or explicit numeric offset, optional
  1..9 fractional digits, valid calendar/time and offset no larger than 23:59.
- Interpret with explicit UTC context; preserve source offset spelling/text, return
  UTC only on success, and require the converted year to remain 0000..9999.
- Empty/date-only/lowercase/whitespace/leap-second/>9-fraction/bad-calendar strings
  are uninterpretable, not silently normalized/truncated. Year 0000/zero time may be
  valid; `IsZero` is not an absence test.

I do not call `time.Now`, consult Local, schedule checks, compare dates, decide
chronological coherence, trust declarations, select policy intervals or label the
snapshot fresh/stale/complete. Future dates or contradictory but individually
parseable times remain **claims**, never qualified freshness. A later consumer
needs explicit trusted acquisition/check evidence and a qualified clock/policy;
missing/untrusted/future/overdue evidence prevents full required intelligence coverage.

Copy/import preserves the original last-successful-check/full-reconciliation text
and values. A newer local `acquiredAt`, file mtime, manifest digest, advisory `modified`,
failed check or unknown `acquisitionMethod` cannot refresh them. A parser cannot
authenticate a forged timestamp, prove the writer actually preserved history, or
qualify unchanged-source revalidation; these require separately authorized consumers.
No timestamp is filled from another field or defaulted to the present.

## Bounds, order and controlled failure

I accept at most **1,048,576 input bytes**, with the shared JSON **depth 128** and
UTF-8/decoded-duplicate/surrogate/EOF guarantees. Every byte, including unknown fields,
counts; there is no preliminary `json.Valid` pass or decoder error disclosure.
Exactly 256 blocks means no unbounded reference list or millions of raw advisory
references in this manifest. Overlength block arrays reject before per-block output.

I accept at most **2,000,000 declared originals** and separately at most **2,000,000
cumulative declared projection records** across all 256 slots. Shared/repeated slots
still count per reference toward the projection allowance; they are not deduplicated
out of that bound. I do not require originals/projection counts to be equal.

Each declared object length and the aggregate length of **distinct digests** must
be at most **34,359,738,368 bytes (32 GiB)**. Reused coherent digests count once for this
manifest-reference bound, while contradictory lengths always fail. I use checked
remaining-allowance arithmetic; arbitrarily large canonical integer tokens produce
limit-exceeded rather than overflow, rounding or invalid negative values.
These bounds do not reserve space, qualify the actual global store quota or scan-read
budget, prove complete retrieval, or authorize downloading/storing this volume.

Failure returns whole-zero `SnapshotManifest` and exactly existing pointer
`*intel.ParseError` with one of these controlled codes/texts:

| Code | Exact text | Reason |
| --- | --- | --- |
| `invalid-json` | `intel: invalid-json` | Shared strict JSON/UTF-8/surrogate/EOF failure |
| `duplicate-key` | `intel: duplicate-key` | Decoded duplicate at any depth, including unknown members |
| `limit-exceeded` | `intel: limit-exceeded` | Byte/depth/block/cardinality/source-id/count/size bound exceeded |
| `invalid-shape` | `intel: invalid-shape` | Core layout, scalar spelling, digest, slot order or coherence failure |
| `unsupported-version` | `intel: unsupported-version` | Nonempty unsupported exact schema string |

Fewer than 256 blocks is invalid-shape; more than 256 is limit-exceeded. For supported
schema I check core in fixed order: source/id, originals, block list, then blocks in
source order. The source-id type, empty/NUL checks precede its byte bound.
Inside refs: object/layout/index, digest, byte value/bound, record
value/bound, empty-byte consistency, repeated-digest consistency, then cumulative
allowances. Earlier encountered fatal code wins; I inspect no data after fatal error.
Optional temporal/string interpretation occurs only after every core ref succeeds.
No raw value, field path, decoded content, URI, secret, partial manifest or wrapped
error appears in failure text; I print/log/exit nothing.

Work is linear in bounded input text plus 257 refs and retained unknown members;
fixed 256 positions permit simple maps for digest coherence/unique-byte accounting.
The byte/ref bounds are not hard RSS, native race safety, disk quota or release qualification.

## Planned literal reference scenarios

These **48 authored scenarios are unexecuted expectations**, not passing Go tests.
I author expectations independently of the future implementation.

Base B is a complete synthetic core: version `"1.0"`; source id
`"packtrace-synthetic-i21"`; originals ref `(empty SHA above, bytes=0, records=0)`;
exactly 256 blocks whose `index` is the literal sequence 0..255, each with that same
empty reference. No optional source claims. This recipe expands to concrete fixtures;
no fixture generator may derive an expected result from the production parser.

Let D be 64 lowercase `a` characters, E be 64 lowercase `b` characters, and H the
empty-byte digest above. Modifications replace only the stated members of B.
`success` means owned structural/temporal evidence only, never verified objects,
complete matching/coverage, source authenticity or freshness.

| ID | Input/modification | Literal expected result |
| --- | --- | --- |
| C01 | B | success;256 slots; shared empty ref; optional claims absent |
| C02 | B plus unknown root/source/originals/block members, including integer beyond uint64 | success; exact unknown raw evidence/precision retained |
| C03 | Different JSON whitespace/member order, same semantic B | success; different original-byte digest, no canonical rewrite |
| C04 | Input slice and retained parent raw field mutated independently after return | other typed/nested raw evidence unchanged |
| C05 | Exactly 1 MiB valid B padded with JSON whitespace | success, owned bytes; no RSS claim |
| C06 | Valid B at 1 MiB+1 | whole-zero; limit-exceeded |
| C07 | 128 versus 129 simultaneously open containers, including root, using unknown nesting | allowed boundary succeeds; excess limit-exceeded |
| C08 | Invalid UTF-8, unpaired surrogate, malformed JSON or trailing second document | whole-zero; invalid-json |
| C09 | Decoded duplicate known/unknown nested key, including escaped-equivalent spelling | whole-zero; duplicate-key |
| C10 | Root null/array/nonobject | whole-zero; invalid-shape |
| C11 | Schema absent/null/nonstring/empty string | whole-zero; invalid-shape |
| C12 | Schema strings `"1"`, `"01.0"`, `"1.0.0"`, `"1.1"`, `"2.0"`, trailing LF | whole-zero; unsupported-version |
| C13 | Unsupported nonempty version with malformed known-profile refs | unsupported-version after JSON, no profile interpretation |
| C14 | source absent/null/nonobject or source.id absent/null/wrong type/empty/NUL | whole-zero; invalid-shape |
| C15 | source.id 256 bytes versus 257 bytes | first success; second limit-exceeded |
| C16 | Case/Unicode/leading spaces/URI-looking opaque source.id within bounds | exact value retained, no path/source authority |
| C17 | originals absent/null/nonobject or any mandatory ref member absent/null/wrong type | whole-zero; invalid-shape |
| C18 | blocks absent/null/nonarray;255 entries | whole-zero; invalid-shape |
| C19 |257 entries | whole-zero; limit-exceeded before nested output |
| C20 | Block null/nonobject; index absent/null/wrong type | whole-zero; invalid-shape |
| C21 | Repeated/out-of-range/out-of-position indices; swapped first two blocks | whole-zero; invalid-shape; no reorder/repair |
| C22 | Uppercase/63/65-digit/prefixed/nonhex digest; leading/trailing whitespace | whole-zero; invalid-shape |
| C23 | Any required count/bytes/index `-0`, negative, fraction, exponent, quoted number or bool | whole-zero; invalid-shape |
| C24 | Forbidden JSON number spelling `01` | whole-zero; invalid-json |
| C25 | Huge canonical digits beyond uint64 for bytes or records | whole-zero; limit-exceeded, no overflow/rounding |
| C26 | originals records=2,000,000 at positive declared bytes/D versus 2,000,001 | boundary success; excess limit-exceeded |
| C27 | Two distinct positive blocks with records=1,000,000 each versus 1,000,001+1,000,000 | cumulative boundary success; excess limit-exceeded |
| C28 | One D reference at 32 GiB versus 32 GiB+1 | boundary success; excess limit-exceeded |
| C29 | Distinct D/E positive lengths sum 32 GiB versus 32 GiB+1 | boundary success; excess limit-exceeded |
| C30 | Slots 0/1 both D, each 20 GiB/1 record, other refs empty | success: unique 20 GiB, not logical 40 GiB; logical records=2; no content/routing proof |
| C31 | Same digest, different lengths across any roles | whole-zero; invalid-shape, no first/last winner |
| C32 | Same block digest/length, different record counts | whole-zero; invalid-shape |
| C33 | Same digest/length across originals/block but differing role counts | success structurally; no content/binding claim |
| C34 | bytes=0 with digest not H or records positive | whole-zero; invalid-shape |
| C35 | records=0 with positive bytes and valid digest | success structurally; content/emptiness remains unqualified |
| C36 | Original/projection declared totals differ, within bounds, coherent refs | success; no invented count equality/completeness |
| C37 | Optional source strings absent/null/type-invalid/empty/unknown methods including `"import"` | exact states/raw values retained; no trust/permission inferred |
| C38 | Optional timestamps absent/null/type-invalid/date-only/empty/whitespace/lowercase | absent/null/type/uninterpretable distinguished, core remains usable |
| C39 | `lastSuccessfulCheck="2026-10-02T00:00:00Z"` | exact text plus usable UTC temporal claim, not fresh |
| C40 | Explicit offset `"2026-10-02T02:30:00+02:30"`, 9 fractional digits, year 0000 and `"0001-01-01T00:00:00Z"` | usable exact text/UTC claims; valid zero time not absent |
| C41 |10 fractional digits/leap second/bad calendar/nonprofile offset/UTC year overflow | uninterpretable exact text, no truncation/normalization |
| C42 | Reconciliation time later than successful-check time, both parseable | both claims retained; no chronology/qualified freshness inferred |
| C43 | Parseable future-dated check/reconciliation declarations | temporal claims only; no implicit now/trust/fresh status |
| C44 | Old check/reconciliation plus newer acquiredAt/import method/exportedAt | retain old claims, no freshness renewal/default |
| C45 | Locator contains credentials/control/target path text; attribution/method unknowns | retained success evidence, never log/URI/output-safe or fetch authority |
| C46 | Source timestamp sentinel/private marker in malformed required core value | whole-zero controlled error; marker absent from text; no partial result |
| C47 | Missing/corrupt/inaccessible external objects; forged counts/digest bindings/slot contents | no lookup in reader; structural result is not object availability/verification or complete coverage |
| C48 | Successful parser requested to strengthen policy/activate store/report no findings | no such authority/effect; consumer/clock/coverage acceptance remains separately gated |

Before execution approval I will pin exact concrete variants/boundary construction in
an implementation plan. This table already fixes their expectations; construction
must not weaken failure classes or silently replace ambiguous evidence with absence.

## Consumers, exclusions and review gate

The future safe store reader/writer must separately qualify content schemas, actual
object lengths/digests, originals/projection bindings, identity routing/collisions,
full candidate retrieval and completeness. Source lookup, successful remote checks,
full reconciliation, import preservation, update cursors, disappearing records and
withdrawals moving to `[EMPTY]` remain separate semantic/lifecycle work.

No disk paths/opens, atomic activation, durability/recovery, writer locks/reader pins,
quota reservation/pruning, HTTP/sync/archive acquisition, real-corpus ingestion,
policy/clock/recency evaluation, matching, report/redaction/supervisor IPC, native
qualification or CI implementation belongs to #21. The future consumer must apply
[report/privacy rules](../design-decisions.md#13-report-contract)
and the separately reviewed coverage contract; scalar success/raw fields are not a
coverage result. Current [exit facts](issue-19-cli-exits.md) remain caller-qualified.
I do not close those gates or weaken [shipping acceptance](../pre-1.0-features.md).

I ask independent future consumer review specifically for strict-core versus claimed
counts, unknown fields/compatibility, digest sharing/roles, freshness preservation,
privacy and reader activation boundaries. Assignment/approval of this draft cannot
serve as that review or as implementation permission. I executed only the separately
approved plan/authority above; its completion evidence records synthetic tests, not
measured scanner capability, object conformance, native support or peer approval.
Storage/consumer/clock/HTTP/acquisition/CI, ready/reviewer and merge remain excluded.
