package intel

import (
	"bytes"
	"encoding/json"
)

const (
	maxAffectedEntries  = 20_000
	maxAffectedVersions = 20_000
)

// OSVFieldState describes JSON shape, not identity validity. Unavailable children
// must not be confused with absent fields in a successfully inspected parent.
type OSVFieldState uint8

const (
	OSVFieldUnavailable OSVFieldState = iota
	OSVFieldAbsent
	OSVFieldNull
	OSVFieldInvalidType
	OSVFieldValue
)

// OSVString retains an exact decoded string, not a normalized or validated identity.
type OSVString struct {
	State OSVFieldState
	Value string
}

// OSVVersions preserves version-list evidence, not validated concrete versions.
// Member position is its source index; duplicate and unusable members are retained.
type OSVVersions struct {
	State   OSVFieldState
	Entries []OSVString
}

// OSVAffectedEntry is one positional claim, not an installed or matched package.
// Unusable parents leave their children's states unavailable.
type OSVAffectedEntry struct {
	Index                 int
	State, PackageState   OSVFieldState
	Ecosystem, Name, PURL OSVString
	Versions              OSVVersions
}

// OSVAffectedProjection binds claims to source digest + affected index + field.
// A value array, even empty, establishes neither complete coverage nor no-match.
type OSVAffectedProjection struct {
	SourceSHA256 [32]byte
	State        OSVFieldState
	Entries      []OSVAffectedEntry
}

// ProjectOSVAffected requires an unchanged successful OSVDocument with no
// concurrent mutation. Basic guards do not authenticate or revalidate forged data.
func ProjectOSVAffected(doc OSVDocument) (OSVAffectedProjection, error) {
	if doc.Fields == nil {
		return OSVAffectedProjection{}, &ParseError{Code: "invalid-shape"}
	}
	raw, present := doc.Fields["affected"]
	items, state := decodeOSVField[[]json.RawMessage](raw, present)
	result := OSVAffectedProjection{SourceSHA256: doc.SHA256, State: state}
	if state != OSVFieldValue {
		return result, nil
	}
	if len(items) > maxAffectedEntries {
		return OSVAffectedProjection{}, &ParseError{Code: "limit-exceeded"}
	}
	result.Entries = make([]OSVAffectedEntry, 0, len(items))
	remaining := maxAffectedVersions
	for index, raw := range items {
		fields, state := decodeOSVField[map[string]json.RawMessage](raw, true)
		entry := OSVAffectedEntry{Index: index, State: state}
		if state == OSVFieldValue {
			versions, used, err := projectOSVVersions(fields, remaining)
			if err != nil {
				return OSVAffectedProjection{}, err
			}
			remaining -= used
			entry.Versions = versions
			packageRaw, present := fields["package"]
			packageFields, packageState := decodeOSVField[map[string]json.RawMessage](packageRaw, present)
			entry.PackageState = packageState
			if packageState == OSVFieldValue {
				entry.Ecosystem = projectOSVString(packageFields, "ecosystem")
				entry.Name = projectOSVString(packageFields, "name")
				entry.PURL = projectOSVString(packageFields, "purl")
			}
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}

func projectOSVVersions(fields map[string]json.RawMessage, remaining int) (OSVVersions, int, error) {
	raw, present := fields["versions"]
	items, state := decodeOSVField[[]json.RawMessage](raw, present)
	result := OSVVersions{State: state}
	if state != OSVFieldValue {
		return result, 0, nil
	}
	if len(items) > remaining {
		return OSVVersions{}, 0, &ParseError{Code: "limit-exceeded"}
	}
	result.Entries = make([]OSVString, 0, len(items))
	for _, raw := range items {
		value, state := decodeOSVField[string](raw, true)
		result.Entries = append(result.Entries, OSVString{State: state, Value: value})
	}
	return result, len(items), nil
}

// decodeOSVField checks only type: the reader already validated raw JSON syntax.
func decodeOSVField[T string | []json.RawMessage | map[string]json.RawMessage](raw json.RawMessage, present bool) (T, OSVFieldState) {
	var value T
	if !present {
		return value, OSVFieldAbsent
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return value, OSVFieldNull
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		var zero T
		return zero, OSVFieldInvalidType
	}
	return value, OSVFieldValue
}

func projectOSVString(fields map[string]json.RawMessage, key string) OSVString {
	raw, present := fields[key]
	value, state := decodeOSVField[string](raw, present)
	return OSVString{State: state, Value: value}
}
