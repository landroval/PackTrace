# Bounded snapshot-manifest reader Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. I preserve inline execution with separate GitHub peer review, not a workflow/subagent dispatch or independent author approval.

**Goal:** Implement the approved pure format 1.0 snapshot-manifest reader with strict core references and retained acquisition claims, without storage activation, object verification or freshness decisions.

**Architecture:** One new intel module reuses the owned strict JSON envelope and existing scalar string/time projectors, validates exactly 257 references with independent logical/unique-byte budgets and returns owned positional evidence. One new test file pins independently authored literals, boundaries, privacy, sharing and temporal non-authority. No existing source/shared helper/type/consumer changes.

**Tech Stack:** Go, standard library only, existing `internal/jsoninput` and `intel.ParseError`/`OSVString`/`OSVTimestamp`. No dependency/module changes.

**Spec:** [Approved snapshot contract](issue-21-intel-snapshot-manifest.md), [draft PR #33](https://github.com/landroval/PackTrace/pull/33) at `a67cd613a03a98dc74341a47c7d9103d0389ad37`. The spec controls; resolve a discrepancy before execution rather than treating illustrative code as permission to change it.

## Status and authority

I prepare this **unapproved local written plan** after contract approval. Generic
continuation permits planning, not source/test creation, execution or publication.
No snippet below has been compiled/executed during preparation. I keep #21 in
Preparation and PR #33 draft; ready/reviewer, source/consumer/native/acquisition/CI
and merge permissions remain separate.

I retain the selected existing bookmark `issue-21-intel-snapshot-manifest-spec`,
whose independent integrated base is `63b5873d747419e494432b2d1b80e10a611875d3`.
PR #32 is not a base dependency or implemented coverage consumer. Source execution
must follow explicit plan approval and inline owned-test/mutation/evidence-publication
authority recorded and published before Go creation. A failed authorization push
stops execution. The current plan is not that record.

## Global constraints

- Exact supported manifest string `"1.0"`; absent/null/nonstring/empty invalid-shape, other nonempty strings unsupported-version after full shared JSON validation.
- Required source object/id: exact opaque1..256 UTF-8 bytes/no NUL; type/empty/NUL before byte bound. No trim/source/path/URL/config/producer inference.
- Required originals object and exactly256 object blocks. Index literal equals source position0..255; no sorting/repair/fallback. Fewer invalid-shape; excess limit-exceeded before per-block output.
- Digests exactly64 lowercase ASCII hex; bytes/records canonical JSON nonnegative integers, no sign/`-0`/fraction/exponent/string/float64 conversion.
- Input at most1,048,576 bytes; existing decoded-duplicate/UTF-8/surrogate/EOF validation and depth128 unchanged. JSON whitespace counts.
- Originals count at most2,000,000; separately cumulative projection count at most2,000,000 including repeated refs. Per-object/aggregate distinct-digest declared bytes at most34,359,738,368. Checked allowances, no overflow/deduplication of logical units.
- bytes0 requires records0 and exact empty SHA-256. records0/positive bytes can be structurally accepted without content/absence proof. Same digest requires same bytes; same block digest requires same records; different roles need not have equal counts.
- Original-byte manifest SHA; owned root/source/reference raw fields, nonnil Fields and256 nonnil positional Blocks on success. Unknown fields retained with exact precision, no capabilities; parent/nested/sibling raw bytes do not alias.
- Optional source locator/method/attribution reuse string states; four timestamps reuse exact existing text/state/UTC profile. No clock/Local/default substitution/chronology/trust/freshness inference or copy/import renewal.
- Every failure whole-zero plus exact existing `*ParseError`, fixed `intel: ` text and code from the spec: `invalid-json`, `duplicate-key`, `limit-exceeded`, `invalid-shape`, `unsupported-version`. No wrap/raw value/partial/error path/printing; full envelope failures precede the version/profile gate.
- No target/object store I/O, dataset acquisition, sync/HTTP, lifecycle/activation/quota reservations, policy/recency, matching/routing/projection schemas, public reporting/IPC, native/race/fuzz/CI or source/module/shared-helper changes.
- Offline owned checks use GOTOOLCHAIN=local/GOPROXY=off/GOWORK=off/CGO_ENABLED=0, no go.sum. Source purity is not native qualification. Keep capability/shipping gates open.
- [Development guidelines](../development-guidelines.md) and [collaboration gates](../github-collaboration.md) govern scoped jj commits and independent review. CodeGraph was unavailable; do not retry/index.

## Review Focus

1. Shared digest versus role units: same-size/count repeated blocks may share bytes, but each still consumes logical record allowance; cross-role record counts need not match and cross-role lengths must match.
2. Exact canonical scalars under compound failures: unknown-version abstention cannot bypass full JSON; later bad metadata cannot mask earlier core fatal, and huge integers never overflow to usable/negative/rounded values.
3. Ownership across retained parent/nested/raw siblings: changing root source/blocks/originals raw fields or one digest's repeated slot must not silently change typed/nested/sibling evidence.
4. Zero/future/contradictory/imported temporal claims: valid zero time remains usable, text/offset/precision stays exact, new acquiredAt/import cannot renew original check/reconciliation fields or create freshness.
5. Sensitive success versus private fatal/non-authority: hostile source IDs/locators/methods remain data, errors contain no markers, unsupported content never activates/reads objects or implies snapshot-complete coverage.

## Task 1 — reader, owned synthetic tests and scoped evidence

**Files:**
- Create `internal/intel/snapshot_manifest.go`: exact four API structs, one parser, three private bounded JSON/scalar/reference helpers.
- Create `internal/intel/snapshot_manifest_test.go`: literal C01–C48 variants and focused envelope/core/limits/sharing/claims/ownership/privacy tests.
- After separate execution/evidence authority only: update the spec/this plan and one nested `docs/pre-1.0-features.md` milestone. No existing Go/module/probe/shared-helper/error/type/consumer or top-level shipping checkbox change.

**Consumes:**
- `jsoninput.Object(data []byte, byteLimit int) (map[string]json.RawMessage, string)` from `internal/jsoninput/object.go`.
- Existing `ParseError{Code string}` and its controlled `Error() string` from `internal/intel/osv.go`.
- Existing `projectOSVString(map[string]json.RawMessage, string) OSVString`/`OSVFieldAbsent`, Null, InvalidType, Value from `osv_affected.go`.
- Existing `projectOSVTimestamp(map[string]json.RawMessage, string) OSVTimestamp`/`TimestampAbsent`, Null, InvalidType, Uninterpretable, Value from `osv_times.go`.

**Produces:** exact `SnapshotObjectReference`, `SnapshotBlockReference`,
`SnapshotSource`, `SnapshotManifest` and `ParseSnapshotManifest([]byte)
(SnapshotManifest, error)` from the approved spec. I add no exported helper,
collector, clock or general registry. Existing scalar helpers already return owned
strings/immutable UTC times; reuse adds calls, not changed shared behavior.

### Approval and fresh baseline

- [ ] Obtain approval of this written plan **and explicit inline source/test, offline owned checks, restored mutations, scoped evidence/publication authorization**. Record/commit/push/read back that pre-code authority before Go creation; stop if publication fails.
- [ ] Recheck live owner/comments, exact PR/head/base/clean tree, approved technical spec bytes and absent two new Go files; no rebase/sibling merge or another workspace. Declare reuse/no consumer change in the issue before source work. Resolve shared-interface concerns before altering anything outside this scope.
- [ ] Run fresh offline root JSON tests/vet and capture exact compiler/outputs/status outside the repo. Count pass records with nonempty Test, never package-pass records or added parallel totals. No historical2,219 count substitutes for this baseline.

### Independent literals and RED

- [ ] Write tests before declarations. Use the complete initial tests below, then transcribe all48 spec rows into named independently expected cases. All successful rows must check SchemaVersion/Source.ID/full256 blocks and owned fields, not merely nil error; all fatal rows check typed exact code/text and whole-zero. Construction helpers create inputs only and never consult production helpers/Markdown or generate expected outcomes from the reader.

```go
package intel

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const snapshotTestEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func snapshotTestBase() map[string]any {
	blocks := make([]any, 256)
	for i := range blocks {
		blocks[i] = map[string]any{"index": i, "sha256": snapshotTestEmpty, "bytes": 0, "records": 0}
	}
	return map[string]any{
		"schemaVersion": "1.0", "source": map[string]any{"id": "packtrace-synthetic-i21"},
		"originals": map[string]any{"sha256": snapshotTestEmpty, "bytes": 0, "records": 0},
		"blocks":    blocks,
	}
}

func snapshotTestBytes(t *testing.T, input map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal("invalid test construction")
	}
	return data
}

func snapshotTestError(t *testing.T, data []byte, code string) {
	t.Helper()
	got, err := ParseSnapshotManifest(data)
	pe, ok := err.(*ParseError)
	if !ok || pe == nil || pe.Code != code || pe.Error() != "intel: "+code || !reflect.DeepEqual(got, SnapshotManifest{}) {
		t.Fatal("missing fixed whole-zero error")
	}
}

func TestParseSnapshotManifestReference(t *testing.T) {
	t.Run("C30", func(t *testing.T) {
		input := snapshotTestBase()
		blocks := input["blocks"].([]any)
		for _, index := range []int{0, 1} {
			blocks[index] = map[string]any{"index": index, "sha256": strings.Repeat("a", 64), "bytes": uint64(20) << 30, "records": 1}
		}
		got, err := ParseSnapshotManifest(snapshotTestBytes(t, input))
		if err != nil || got.SchemaVersion != "1.0" || got.Source.ID != "packtrace-synthetic-i21" || len(got.Blocks) != 256 {
			t.Fatal("shared-byte reference result missing")
		}
		for _, index := range []int{0, 1} {
			ref := got.Blocks[index].Reference
			if got.Blocks[index].Index != index || ref.SHA256 != ([32]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}) || ref.Bytes != uint64(20)<<30 || ref.Records != 1 || ref.Fields == nil {
				t.Fatal("literal reference claim changed")
			}
		}
	})
	t.Run("C19", func(t *testing.T) {
		input := snapshotTestBase()
		input["blocks"] = append(input["blocks"].([]any), nil)
		snapshotTestError(t, snapshotTestBytes(t, input), "limit-exceeded")
	})
}

func TestParseSnapshotManifestTemporalPreservation(t *testing.T) {
	input := snapshotTestBase()
	source := input["source"].(map[string]any)
	source["acquisitionMethod"] = "import"
	source["acquiredAt"] = "2099-01-01T00:00:00Z"
	source["lastSuccessfulCheck"] = "0001-01-01T00:00:00Z"
	source["lastFullReconciliation"] = "2026-10-02T02:30:00+02:30"
	got, err := ParseSnapshotManifest(snapshotTestBytes(t, input))
	if err != nil || got.SchemaVersion != "1.0" || len(got.Blocks) != 256 {
		t.Fatal("claim result missing")
	}
	if got.Source.LastSuccessfulCheck.State != TimestampValue || got.Source.LastSuccessfulCheck.Text != "0001-01-01T00:00:00Z" || !got.Source.LastSuccessfulCheck.Value.IsZero() {
		t.Fatal("zero-time claim lost or renewed")
	}
	want := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	if got.Source.LastFullReconciliation.Text != "2026-10-02T02:30:00+02:30" || got.Source.LastFullReconciliation.State != TimestampValue || !got.Source.LastFullReconciliation.Value.Equal(want) || got.Source.LastFullReconciliation.Value.Location() != time.UTC {
		t.Fatal("exact offset text/UTC claim lost")
	}
}

func TestParseSnapshotManifestOwnershipExamples(t *testing.T) {
	for _, actor := range []string{"input", "parent-source", "parent-originals", "parent-blocks", "sibling"} {
		t.Run(actor, func(t *testing.T) {
			data := snapshotTestBytes(t, snapshotTestBase())
			got, err := ParseSnapshotManifest(data)
			if err != nil || got.Source.ID != "packtrace-synthetic-i21" || len(got.Blocks) != 256 || got.Source.Fields == nil || got.Originals.Fields == nil {
				t.Fatal("owned success missing")
			}
			idRaw := append([]byte(nil), got.Source.Fields["id"]...)
			originalRaw := append([]byte(nil), got.Originals.Fields["sha256"]...)
			siblingRaw := append([]byte(nil), got.Blocks[1].Reference.Fields["sha256"]...)
			switch actor {
			case "input":
				clear(data)
			case "parent-source":
				clear(got.Fields["source"])
			case "parent-originals":
				clear(got.Fields["originals"])
			case "parent-blocks":
				clear(got.Fields["blocks"])
			case "sibling":
				clear(got.Blocks[0].Reference.Fields["sha256"])
			}
			if got.Source.ID != "packtrace-synthetic-i21" || !bytes.Equal(got.Source.Fields["id"], idRaw) || !bytes.Equal(got.Originals.Fields["sha256"], originalRaw) || !bytes.Equal(got.Blocks[1].Reference.Fields["sha256"], siblingRaw) {
				t.Fatal("retained parent/input/sibling aliases nested evidence")
			}
		})
	}
}

func TestParseSnapshotManifestCompoundExamples(t *testing.T) {
	t.Run("version-before-profile", func(t *testing.T) {
		input := snapshotTestBase()
		input["schemaVersion"], input["originals"] = "2.0", nil
		snapshotTestError(t, snapshotTestBytes(t, input), "unsupported-version")
		input["unknown"] = json.RawMessage(`{"dup":0,"\u0064up":1}`)
		snapshotTestError(t, snapshotTestBytes(t, input), "duplicate-key")
	})
	t.Run("core-before-claims-private", func(t *testing.T) {
		input := snapshotTestBase()
		source := input["source"].(map[string]any)
		source["locator"], source["lastSuccessfulCheck"] = "private-i21-marker", "private-i21-marker"
		input["originals"].(map[string]any)["bytes"] = "private-i21-marker"
		snapshotTestError(t, snapshotTestBytes(t, input), "invalid-shape")
	})
}
```

- [ ] Add `TestParseSnapshotManifestEnvelope` for C05–C13/C24. Exact1 MiB and+1 are B plus trailing ASCII spaces, never enlarged object content. C07 inserts an unknown value with127 versus128 nested arrays under the root (128 versus129 open containers including root). Pin invalid UTF-8, unpaired `\ud800`, trailing object, malformed JSON; decoded duplicates at root/source/ref and unknown nested maps (including escaped-equivalent keys), and unsupported version with both malformed profile refs and duplicate unknown envelope. Full envelope errors precede version abstention.
- [ ] Add `TestParseSnapshotManifestCore` for C14–C25/C34/C46 with separately named variants per root/source/originals/block position. Use literal source256/257 ASCII bytes and128 `é` plus optionalASCII `a`; null/nonobject/no id/empty/escapedNUL. Pin original/block mandatory fields missing/null/wrong type; block arrays255/257, null/block scalar, duplicate/swapped/outside/huge indices. Digest uppercase/63/65 chars/prefix/nonhex/spaces. Raw integer values `-0`, `-1`, `1.0`, `1e0`, `"1"`, `true`, `null`, `01`, `18446744073709551616`; no float expectation. For raw `01`, edit only a known `bytes:0` token in serialized B so JSON syntax failure is real, not json.Marshal rejecting the fixture first.
- [ ] Add `TestParseSnapshotManifestLimitsSharing` for C26–C36 and focus1. Per-role/unique-byte boundaries are literal integers, not production constants: originals2,000,000/2,000,001; two distinct blocks1,000,000 each versus1,000,001+1,000,000; individual32 GiB/+1; distinct20 GiB+12 GiB/+1. Same D across four slots with records500,000 each succeeds at2M; fifth same D makes logical2.5M and must fail even though unique bytes fit. Pin byte conflict across originals/block and block/block, same-block count conflict, cross-role same-length count differences, bytes0 wrong digest/count, records0 positive bytes and differing original/projected totals. Keep all other refs valid/coherent so compound conflicts cannot suppress the targeted allowance.
- [ ] Add `TestParseSnapshotManifestClaims` for C16/C37–C45 and focus4/5. Literal source strings and all four temporal fields each get absent/null/bool/object/empty/date-only/space/LF/lowercase states. For each time field pin offset above, `.1200` trailing zeros, `.123456789`, `-00:00`, year0000/year0001 zero, and future2099. Pin10 digits, leap second, invalid2023-02-29, +24:00, UTC underflow0000+00:01 and overflow9999-00:01 as uninterpretable. Use independently written `time.Date` values, never the production projector as expected evaluator. Old check/reconciliation and newer acquired/export/import/failed methods stay unchanged; chronology is not repaired or interpreted. Raw secret/URL/control/path strings remain exact sensitive successful evidence.
- [ ] Add `TestParseSnapshotManifestOwnership` for C02–C04/focus3: snapshot original inputs/result before mutations; verify root digest equals `sha256.Sum256(originalData)` and differs for whitespace/reordered originals. Preserve unknown large integer lexeme `18446744073709551616000` and unknown fields at every level. Mutate original data, root `Fields["source"]`/`["originals"]`/`["blocks"]`, nested source field, originals digest and one repeated block raw digest independently in separate calls; compare all untouched typed/nested/sibling snapshots and a fresh second call. Assert nonnil Fields/256 Blocks and untouched original array positions; do not compare a shallow alias as the ownership oracle.
- [ ] Add `TestParseSnapshotManifestPrecedencePrivacySeparation` for C46–C48/focus2/5. Private-marker bad core always typed whole-zero/fixed code; malformed optional timestamps/locators cannot mask source/originals/slot/digest/count failures. Pin originals invalid before overlong block list, index invalid before digest, digest invalid before huge bytes, bytes bound before bad records, count bound before empty consistency, shared conflict before later cumulative allowance. Every unrelated object locator/content is inert. An AST guard on this owned Go source allows only bytes/crypto-sha256/encoding-hex/encoding-json/strconv/strings/internal-jsoninput imports, no IO/print/exit/environment/network/clock/global mutation; inspect the unchanged consumed helpers as well. Do not create fake storage/target files or claim no-write/no-open/native safety from test fixtures. Purity supports bounded non-authority, not actual object/consumer qualification.
- [ ] Run focused tests before API declarations; inspect missing-API compilation RED. Then copy the exact four structs from the approved API into the new file, import encoding/json, and use this temporary behavioral RED stub. Rerun all reference/guard variants: successful rows must now fail full result checks and fatal rows must fail typed-error checks. Record actual stub pass/fail counts; do not claim all auxiliary AST checks fail or equate48 rows with eventual test/subtest counts.

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

func ParseSnapshotManifest(data []byte) (SnapshotManifest, error) {
	return SnapshotManifest{}, nil
}
```

### Minimal GREEN, unchanged API and existing helpers

- [ ] Replace the stub with the following bounded algorithm. Copy the four approved struct declarations unchanged. Production imports bytes, crypto/sha256, encoding/hex, encoding/json, strconv, strings and packtrace/internal/jsoninput only. Add comments documenting pure owned analysis, exact original SHA/no trust, controlled whole-zero errors and no clock/activation. This is planned code, not a compiled implementation.

```go
const (
	maxSnapshotManifestBytes              = 1 << 20
	maxSnapshotManifestBlocks             = 256
	maxSnapshotManifestRecords     uint64 = 2_000_000
	maxSnapshotManifestObjectBytes uint64 = 32 << 30
)

func snapshotManifestObject(raw json.RawMessage) (map[string]json.RawMessage, string) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, "invalid-shape"
	}
	return fields, ""
}

func snapshotManifestUint(raw json.RawMessage, limit uint64) (uint64, string) {
	text := string(bytes.TrimSpace(raw))
	if text == "" || (len(text) > 1 && text[0] == '0') {
		return 0, "invalid-shape"
	}
	for i := range text {
		if text[i] < '0' || text[i] > '9' {
			return 0, "invalid-shape"
		}
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil || value > limit {
		return 0, "limit-exceeded"
	}
	return value, ""
}

func snapshotManifestReference(raw json.RawMessage, index int) (SnapshotObjectReference, string) {
	fields, code := snapshotManifestObject(raw)
	if code != "" {
		return SnapshotObjectReference{}, code
	}
	if index >= 0 && string(bytes.TrimSpace(fields["index"])) != strconv.Itoa(index) {
		return SnapshotObjectReference{}, "invalid-shape"
	}
	digest := projectOSVString(fields, "sha256")
	if digest.State != OSVFieldValue || len(digest.Value) != 64 {
		return SnapshotObjectReference{}, "invalid-shape"
	}
	decoded, err := hex.DecodeString(digest.Value)
	if err != nil || hex.EncodeToString(decoded) != digest.Value {
		return SnapshotObjectReference{}, "invalid-shape"
	}
	result := SnapshotObjectReference{Fields: fields}
	copy(result.SHA256[:], decoded)
	result.Bytes, code = snapshotManifestUint(fields["bytes"], maxSnapshotManifestObjectBytes)
	if code != "" {
		return SnapshotObjectReference{}, code
	}
	result.Records, code = snapshotManifestUint(fields["records"], maxSnapshotManifestRecords)
	if code != "" {
		return SnapshotObjectReference{}, code
	}
	if result.Bytes == 0 && (result.Records != 0 || result.SHA256 != sha256.Sum256(nil)) {
		return SnapshotObjectReference{}, "invalid-shape"
	}
	return result, ""
}

func ParseSnapshotManifest(data []byte) (SnapshotManifest, error) {
	fields, code := jsoninput.Object(data, maxSnapshotManifestBytes)
	if code != "" {
		return SnapshotManifest{}, &ParseError{Code: code}
	}
	version := projectOSVString(fields, "schemaVersion")
	if version.State != OSVFieldValue || version.Value == "" {
		return SnapshotManifest{}, &ParseError{Code: "invalid-shape"}
	}
	if version.Value != "1.0" {
		return SnapshotManifest{}, &ParseError{Code: "unsupported-version"}
	}
	sourceFields, code := snapshotManifestObject(fields["source"])
	if code != "" {
		return SnapshotManifest{}, &ParseError{Code: code}
	}
	id := projectOSVString(sourceFields, "id")
	if id.State != OSVFieldValue || id.Value == "" || strings.ContainsRune(id.Value, 0) {
		return SnapshotManifest{}, &ParseError{Code: "invalid-shape"}
	}
	if len(id.Value) > 256 {
		return SnapshotManifest{}, &ParseError{Code: "limit-exceeded"}
	}
	originals, code := snapshotManifestReference(fields["originals"], -1)
	if code != "" {
		return SnapshotManifest{}, &ParseError{Code: code}
	}
	var blocks []json.RawMessage
	if json.Unmarshal(fields["blocks"], &blocks) != nil || blocks == nil || len(blocks) < maxSnapshotManifestBlocks {
		return SnapshotManifest{}, &ParseError{Code: "invalid-shape"}
	}
	if len(blocks) > maxSnapshotManifestBlocks {
		return SnapshotManifest{}, &ParseError{Code: "limit-exceeded"}
	}
	result := SnapshotManifest{
		SHA256: sha256.Sum256(data), Fields: fields, SchemaVersion: version.Value,
		Source: SnapshotSource{Fields: sourceFields, ID: id.Value}, Originals: originals,
		Blocks: make([]SnapshotBlockReference, maxSnapshotManifestBlocks),
	}
	lengths := map[[32]byte]uint64{originals.SHA256: originals.Bytes}
	blockCounts := make(map[[32]byte]uint64)
	remainingBytes := maxSnapshotManifestObjectBytes - originals.Bytes
	remainingRecords := maxSnapshotManifestRecords
	for index, raw := range blocks {
		ref, code := snapshotManifestReference(raw, index)
		if code != "" {
			return SnapshotManifest{}, &ParseError{Code: code}
		}
		length, shared := lengths[ref.SHA256]
		if shared && length != ref.Bytes {
			return SnapshotManifest{}, &ParseError{Code: "invalid-shape"}
		}
		if count, exists := blockCounts[ref.SHA256]; exists && count != ref.Records {
			return SnapshotManifest{}, &ParseError{Code: "invalid-shape"}
		}
		if !shared {
			if ref.Bytes > remainingBytes {
				return SnapshotManifest{}, &ParseError{Code: "limit-exceeded"}
			}
			remainingBytes -= ref.Bytes
			lengths[ref.SHA256] = ref.Bytes
		}
		if ref.Records > remainingRecords {
			return SnapshotManifest{}, &ParseError{Code: "limit-exceeded"}
		}
		remainingRecords -= ref.Records
		blockCounts[ref.SHA256] = ref.Records
		result.Blocks[index] = SnapshotBlockReference{Index: index, Reference: ref}
	}
	result.Source.Locator = projectOSVString(sourceFields, "locator")
	result.Source.AcquisitionMethod = projectOSVString(sourceFields, "acquisitionMethod")
	result.Source.Attribution = projectOSVString(sourceFields, "attribution")
	result.Source.AcquiredAt = projectOSVTimestamp(sourceFields, "acquiredAt")
	result.Source.ExportedAt = projectOSVTimestamp(sourceFields, "exportedAt")
	result.Source.LastSuccessfulCheck = projectOSVTimestamp(sourceFields, "lastSuccessfulCheck")
	result.Source.LastFullReconciliation = projectOSVTimestamp(sourceFields, "lastFullReconciliation")
	return result, nil
}
```

- [ ] Run focused GREEN; inspect every reference variant, role/budget boundary, compound precedence and five focus classes. Diagnose unexpected failures; do not weaken/normalize bounds, claim types, whole-zero errors or ownership expectations. Standard JSON unmarshal creates separately owned nested RawMessages, so do not add a redundant generic deep-copy framework.

### Restored mutations, final review and authorized publication

- [ ] Save new source SHA and shared-source fingerprints outside repo. Temporarily consume projection allowance only for unseen digests: repeated D five-slot logical-overflow test must fail. Restore and verify SHA before proceeding.
- [ ] Temporarily sum every ref's bytes or relax cross-role length/block-count conflicts: C30 success and C31/C32 guard tests respectively must detect those mutations. Test these separately; restore source SHA each time.
- [ ] Temporarily remove index==position/canonical-lowercase guard: swapped slots/uppercase-digest tests must fail without changing expected fixtures. Restore/check SHA.
- [ ] Temporarily replace LastSuccessfulCheck with AcquiredAt or classify zero time absent: temporal/import/zero-text tests must fail. Never modify the shared OSV helper as a mutation. Restore/check SHA; no shared byte change remains.
- [ ] Temporarily return a populated partial result on late fatal or append a source locator marker to the error: whole-zero/privacy tests must fail. Restore/check SHA; save observed failing tests/classes, not a fabricated pass count.
- [ ] Format only the two new Go files; freshly run offline root JSON tests/vet and count actual tested tree/new `TestParseSnapshotManifest` cases. Record exact toolchain/flags/stderr/status separately. Check all preexisting Go/module/probe/checklist bytes, no go.sum and no restored mutation difference.
- [ ] Self-review five focus classes against source and tests; make a scoped two-file jj code commit only after observed checks. Record author review accurately, not independent approval.
- [ ] Only under separate evidence/publication authorization, update spec/plan/nested milestone with exact measured RED/GREEN/mutation/count/limits, then commit only those docs and push only issue bookmark. Read back exact final PR head/body/path scope. Keep PR #33 draft/#21 open and top-level capability/shipping gates unchanged until separately authorized handoff and reviewed integration.

## Offline commands and scoped commits

These are future commands, not executed preparation evidence. Capture stdout/stderr,
JSON streams and exit status outside the repo; stop on unexpected failures.

```nu
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go test -count=1 -run '^TestParseSnapshotManifest' ./internal/intel
}
```

```nu
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go version
    go test -count=1 -json ./...
    go vet ./...
}
```

After approved source creation/observed checks only:

```nu
gofmt -w internal/intel/snapshot_manifest.go internal/intel/snapshot_manifest_test.go
jj diff --name-only
jj commit internal/intel/snapshot_manifest.go internal/intel/snapshot_manifest_test.go -m "feat: parse snapshot manifest claims (#21)"
```

An executor preserves the separately recorded pre-code authorization commit and
approved spec/plan. It must not fold an unexpected unrelated file into these commits,
use `--all` push or infer publication/ready/merge authority from command examples.

## Coverage and handoff

The one task maps C01–C48 to Reference/Envelope/Core/LimitsSharing/Claims/Ownership/
PrecedencePrivacySeparation, with all five review-focus classes exercised. The fixed
API/version/owned maps/raw bytes/bounds/role coherence/time claims/private fatal and
consumer exclusions remain those of the written spec. C47/C48 are bounded purity/
inert-data assertions, not physical object, lifecycle, reporter or coverage tests.
The minimum code preserves independent originals/projection count roles and both
unique declared bytes/logical repeated-reference budgets without adding a consumer.

I self-reviewed coverage, placeholders, type/signature/constant consistency,
compound precedence and all five test mappings. I pin fixtures/expected states
independently of production helpers and preserve the exact approved API/body.
Syntax-format and Nushell checks during preparation are not compilation,
executed fixtures/Go tests or independent review. I retain the inline method, and
wait for explicit approval/execution/evidence publication before beginning Task1.
