package intel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"packtrace/internal/jsoninput"
)

const (
	maxSnapshotManifestBytes              = 1 << 20
	maxSnapshotManifestBlocks             = 256
	maxSnapshotManifestRecords     uint64 = 2_000_000
	maxSnapshotManifestObjectBytes uint64 = 32 << 30
)

// SnapshotObjectReference retains declared metadata, not verified object bytes.
// Fields own the entire reference object; its digest is not publisher authenticity.
type SnapshotObjectReference struct {
	Fields         map[string]json.RawMessage
	SHA256         [32]byte
	Bytes, Records uint64
}

// SnapshotBlockReference preserves a manifest slot; no content routing is checked.
type SnapshotBlockReference struct {
	Index     int
	Reference SnapshotObjectReference
}

// SnapshotSource retains opaque source and temporal claims without trust or recency.
// The existing OSV scalar types supply identical string/time syntax states only.
type SnapshotSource struct {
	Fields                                      map[string]json.RawMessage
	ID                                          string
	Locator, AcquisitionMethod, Attribution     OSVString
	AcquiredAt, ExportedAt                      OSVTimestamp
	LastSuccessfulCheck, LastFullReconciliation OSVTimestamp
}

// SnapshotManifest is owned internal evidence, not an activated/complete snapshot.
// SHA256 binds original manifest bytes; sensitive raw fields are not log-safe.
type SnapshotManifest struct {
	SHA256        [32]byte
	Fields        map[string]json.RawMessage
	SchemaVersion string
	Source        SnapshotSource
	Originals     SnapshotObjectReference
	Blocks        []SnapshotBlockReference
}

// ParseSnapshotManifest validates format1.0 core and independently retains claims.
// No object/storage/source/clock/policy operations occur. The caller must not mutate
// data concurrently. Failures are whole-zero with fixed ParseError codes; byte and
// declared-reference bounds are not hard RSS, actual quota or coverage guarantees.
func ParseSnapshotManifest(data []byte) (SnapshotManifest, error) {
	return parseSnapshotManifestVersion(data, "1.0")
}

func ParseSnapshotManifestV11(data []byte) (SnapshotManifest, error) {
	return parseSnapshotManifestVersion(data, "1.1")
}

func parseSnapshotManifestVersion(data []byte, requiredVersion string) (SnapshotManifest, error) {
	fields, code := jsoninput.Object(data, maxSnapshotManifestBytes)
	if code != "" {
		return SnapshotManifest{}, &ParseError{Code: code}
	}
	version := projectOSVString(fields, "schemaVersion")
	if version.State != OSVFieldValue || version.Value == "" {
		return SnapshotManifest{}, &ParseError{Code: "invalid-shape"}
	}
	if version.Value != requiredVersion {
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
