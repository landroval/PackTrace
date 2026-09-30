package inventory

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"strings"
)

// BunResolutionKind names the resolution form Bun wrote for a package tuple.
type BunResolutionKind uint8

const (
	BunKindUnknown BunResolutionKind = iota
	BunKindNPM
	BunKindGit
	BunKindGitHub
	BunKindTarball
	BunKindFolder
	BunKindLink
	BunKindWorkspace
	BunKindRoot
)

// BunLockedRecord describes a bun.lock tuple, not an observed installed package.
type BunLockedRecord struct {
	Key        string
	Kind       BunResolutionKind
	Name       LockField[string]
	Resolution LockField[string]
	Registry   LockField[string]
	Integrity  LockField[string]
	GitTag     LockField[string]
	Info       json.RawMessage
}

// BunLockProjection links typed claims to the unchanged document's byte digest.
type BunLockProjection struct {
	SourceSHA256 [32]byte
	Records      []BunLockedRecord
}

// ProjectBunLock requires an unchanged successful ParseBunLock result and no
// concurrent input mutation. It types tuple claims, not installed state, and
// keeps unrecognized tuples as BunKindUnknown records rather than rejecting them.
func ProjectBunLock(doc BunLockDocument) (BunLockProjection, error) {
	if doc.Fields == nil || doc.Packages == nil {
		return BunLockProjection{}, &ParseError{Code: "invalid-shape"}
	}
	if len(doc.Packages) > maxProjectedRecords {
		return BunLockProjection{}, &ParseError{Code: "limit-exceeded"}
	}
	records := make([]BunLockedRecord, 0, len(doc.Packages))
	for _, key := range slices.Sorted(maps.Keys(doc.Packages)) {
		var tuple []json.RawMessage
		if err := json.Unmarshal(doc.Packages[key], &tuple); err != nil || tuple == nil {
			return BunLockProjection{}, &ParseError{Code: "invalid-shape"}
		}
		records = append(records, projectBunTuple(key, tuple))
	}
	return BunLockProjection{SourceSHA256: doc.SHA256, Records: records}, nil
}

func projectBunTuple(key string, tuple []json.RawMessage) BunLockedRecord {
	var first json.RawMessage
	var rest []json.RawMessage
	if len(tuple) > 0 {
		first, rest = tuple[0], tuple[1:]
	}
	record := BunLockedRecord{Key: strings.Clone(key)}
	record.Name, record.Resolution = splitBunResolution(decodeBunString(first))
	if record.Resolution.State != FieldValue {
		return record
	}
	record.Kind = classifyBunTuple(record.Resolution.Value, rest)
	switch record.Kind {
	case BunKindNPM:
		record.Registry = decodeBunString(rest[0])
		record.Info = bytes.Clone(rest[1])
		record.Integrity = decodeBunString(rest[2])
	case BunKindGit, BunKindGitHub:
		record.Info = bytes.Clone(rest[0])
		record.GitTag = decodeBunString(rest[1])
		record.Integrity = decodeBunString(bunElement(rest, 2))
	case BunKindTarball:
		record.Info = bytes.Clone(rest[0])
		record.Integrity = decodeBunString(bunElement(rest, 1))
	case BunKindFolder, BunKindLink, BunKindRoot:
		record.Info = bytes.Clone(rest[0])
	case BunKindWorkspace:
		record.Info = bytes.Clone(bunElement(rest, 0))
	}
	return record
}

// bunElement returns a tuple element, or nil when the optional element is missing.
func bunElement(rest []json.RawMessage, i int) json.RawMessage {
	if i < len(rest) {
		return rest[i]
	}
	return nil
}

// splitBunResolution splits "<name>@<resolution>" at the first '@' after index 0,
// not the last, so scoped names and git URLs containing '@' stay intact.
func splitBunResolution(first LockField[string]) (name, resolution LockField[string]) {
	if first.State != FieldValue {
		return first, first
	}
	if first.Value == "@root:" {
		return LockField[string]{State: FieldValue}, LockField[string]{State: FieldValue, Value: "root:"}
	}
	invalid := LockField[string]{State: FieldInvalidType}
	if first.Value == "" {
		return invalid, invalid
	}
	at := strings.IndexByte(first.Value[1:], '@')
	if at < 0 || at+2 >= len(first.Value) {
		return invalid, invalid
	}
	at++
	return LockField[string]{State: FieldValue, Value: strings.Clone(first.Value[:at])},
		LockField[string]{State: FieldValue, Value: strings.Clone(first.Value[at+1:])}
}

// classifyBunTuple requires both the resolution form and the exact tuple shape;
// any mismatch is BunKindUnknown, never a partially trusted kind.
func classifyBunTuple(resolution string, rest []json.RawMessage) BunResolutionKind {
	switch {
	case resolution == "root:":
		return shapeKind(BunKindRoot, rest, bunObject)
	case strings.HasPrefix(resolution, "link:"):
		return shapeKind(BunKindLink, rest, bunObject)
	case strings.HasPrefix(resolution, "workspace:"):
		if len(rest) == 0 {
			return BunKindWorkspace
		}
		return shapeKind(BunKindWorkspace, rest, bunObject)
	case strings.HasPrefix(resolution, "file:"):
		return shapeKind(BunKindFolder, rest, bunObject)
	case strings.HasPrefix(resolution, "github:"):
		return shapeKind(BunKindGitHub, rest, bunObject, bunString, bunOptionalString)
	case strings.HasPrefix(resolution, "git+"):
		return shapeKind(BunKindGit, rest, bunObject, bunString, bunOptionalString)
	case isBunTarball(resolution):
		return shapeKind(BunKindTarball, rest, bunObject, bunOptionalString)
	default:
		return shapeKind(BunKindNPM, rest, bunString, bunObject, bunString)
	}
}

type bunShape struct {
	check    func(json.RawMessage) bool
	optional bool
}

var (
	bunObject         = bunShape{check: isJSONObject}
	bunString         = bunShape{check: isJSONString}
	bunOptionalString = bunShape{check: isJSONString, optional: true}
)

func shapeKind(kind BunResolutionKind, rest []json.RawMessage, shape ...bunShape) BunResolutionKind {
	if len(rest) > len(shape) {
		return BunKindUnknown
	}
	for i, want := range shape {
		if i >= len(rest) {
			if want.optional {
				continue
			}
			return BunKindUnknown
		}
		if !want.check(rest[i]) {
			return BunKindUnknown
		}
	}
	return kind
}

func isBunTarball(resolution string) bool {
	lower := strings.ToLower(resolution)
	isRemote := strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
	isArchive := strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz") ||
		strings.HasSuffix(lower, ".tar")
	return isRemote || isArchive
}

func isJSONString(raw json.RawMessage) bool {
	var value *string
	return json.Unmarshal(raw, &value) == nil && value != nil
}

// decodeBunString applies the four-state field rules to one tuple element.
func decodeBunString(raw json.RawMessage) LockField[string] {
	if raw == nil {
		return LockField[string]{State: FieldAbsent}
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return LockField[string]{State: FieldNull}
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return LockField[string]{State: FieldInvalidType}
	}
	return LockField[string]{State: FieldValue, Value: value}
}
