// Package inventory reads dependency evidence without resolving or executing it.
package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	"packtrace/internal/jsoninput"
)

const maxLockfileBytes = 64 << 20

// Document contains locked, uninterpreted evidence, not an installed inventory.
// Raw values own their bytes. Fields includes packages and unknown top-level data.
type Document struct {
	SHA256   [32]byte
	Fields   map[string]json.RawMessage
	Packages map[string]map[string]json.RawMessage
}

// ParseError exposes a category without disclosing input contents.
type ParseError struct{ Code string }

func (e *ParseError) Error() string { return "inventory: " + e.Code }

// ParseNPMLock reads one lockfile-version-2 or -3 document from memory. The caller
// must not mutate data during the call. Successful parsing does not establish
// producer compatibility, effective-input selection, provenance, or safety.
func ParseNPMLock(data []byte) (Document, error) {
	fields, err := parseJSONFields(data, maxLockfileBytes)
	if err != nil {
		return Document{}, err
	}
	version := bytes.TrimSpace(fields["lockfileVersion"])
	if !integerLiteral(version) {
		return Document{}, &ParseError{Code: "invalid-shape"}
	}
	if string(version) != "2" && string(version) != "3" {
		return Document{}, &ParseError{Code: "unsupported-version"}
	}
	var records map[string]json.RawMessage
	if err := json.Unmarshal(fields["packages"], &records); err != nil || records == nil {
		return Document{}, &ParseError{Code: "invalid-shape"}
	}
	packages := make(map[string]map[string]json.RawMessage, len(records))
	for key, raw := range records {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(raw, &record); err != nil || record == nil {
			return Document{}, &ParseError{Code: "invalid-shape"}
		}
		packages[key] = record
	}
	return Document{SHA256: sha256.Sum256(data), Fields: fields, Packages: packages}, nil
}

// parseJSONFields preserves inventory error categories around shared validation.
func parseJSONFields(data []byte, byteLimit int) (map[string]json.RawMessage, error) {
	fields, code := jsoninput.Object(data, byteLimit)
	if code != "" {
		return nil, &ParseError{Code: code}
	}
	return fields, nil
}

// JSON syntax validation has already ruled out leading zeros and bare minus.
// Avoid fixed-width numeric conversion: any other integer version is unsupported,
// even when it is too large to fit in a machine integer.
func integerLiteral(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	if value[0] == '-' {
		value = value[1:]
	}
	if len(value) == 0 {
		return false
	}
	for _, b := range value {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}
