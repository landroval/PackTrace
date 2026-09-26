package inventory

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
)

const (
	maxProjectedRecords   = 20_000
	maxLockedRequirements = 20_000
)

// FieldState distinguishes absence, null, a typed value, and a wrong JSON type.
type FieldState uint8

const (
	FieldAbsent FieldState = iota
	FieldNull
	FieldValue
	FieldInvalidType
)

// LockField contains an explicit claim. FieldValue validates only its JSON type,
// not name/version/origin/digest semantics. Other states have a zero Value.
type LockField[T string | bool] struct {
	State FieldState
	Value T
}

// LockedRecord describes a lockfile entry, not an observed installed instance.
// Location is opaque evidence and must not be used as an unchecked filesystem path.
type LockedRecord struct {
	Location  string
	Name      LockField[string]
	Version   LockField[string]
	Resolved  LockField[string]
	Integrity LockField[string]
	Link      LockField[bool]
	// Requirements are recorded claims, not current manifest declarations or resolved edges.
	Requirements []DependencyGroup
}

// NPMLockProjection links typed claims to the unchanged document's byte digest.
// It is internal analysis data, not a public report or an authenticity assertion.
type NPMLockProjection struct {
	SourceSHA256 [32]byte
	Records      []LockedRecord
}

// ProjectNPMLock requires an unchanged successful ParseNPMLock result and no
// concurrent input mutation. Basic guards do not authenticate a forged document.
func ProjectNPMLock(doc Document) (NPMLockProjection, error) {
	if doc.Fields == nil || doc.Packages == nil {
		return NPMLockProjection{}, &ParseError{Code: "invalid-shape"}
	}
	if len(doc.Packages) > maxProjectedRecords {
		return NPMLockProjection{}, &ParseError{Code: "limit-exceeded"}
	}
	records := make([]LockedRecord, 0, len(doc.Packages))
	remaining := maxLockedRequirements
	for _, location := range slices.Sorted(maps.Keys(doc.Packages)) {
		fields := doc.Packages[location]
		if fields == nil {
			return NPMLockProjection{}, &ParseError{Code: "invalid-shape"}
		}
		groups, used, err := projectDependencyGroups(fields, remaining)
		if err != nil {
			return NPMLockProjection{}, err
		}
		remaining -= used
		records = append(records, LockedRecord{
			Location:     location,
			Name:         projectField[string](fields, "name"),
			Version:      projectField[string](fields, "version"),
			Resolved:     projectField[string](fields, "resolved"),
			Integrity:    projectField[string](fields, "integrity"),
			Link:         projectField[bool](fields, "link"),
			Requirements: groups,
		})
	}
	return NPMLockProjection{SourceSHA256: doc.SHA256, Records: records}, nil
}

func projectField[T string | bool](fields map[string]json.RawMessage, key string) LockField[T] {
	raw, ok := fields[key]
	if !ok {
		return LockField[T]{State: FieldAbsent}
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return LockField[T]{State: FieldNull}
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return LockField[T]{State: FieldInvalidType}
	}
	return LockField[T]{State: FieldValue, Value: value}
}
