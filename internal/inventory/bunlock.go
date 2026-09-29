package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
)

// BunLockDocument contains locked, uninterpreted Bun evidence, not an installed
// inventory or validated package tuples. Raw values own their bytes.
type BunLockDocument struct {
	SHA256     [32]byte
	Fields     map[string]json.RawMessage
	Workspaces map[string]json.RawMessage
	Packages   map[string]json.RawMessage
}

// ParseBunLock reads one text bun.lock document (versions 0-3) from memory after
// JSONC normalization; the caller must not mutate data during the call. Success
// does not interpret tuples or establish producer compatibility or safety.
func ParseBunLock(data []byte) (BunLockDocument, error) {
	if len(data) > maxLockfileBytes {
		return BunLockDocument{}, &ParseError{Code: "limit-exceeded"}
	}
	normalized, ok := normalizeJSONC(data)
	if !ok {
		return BunLockDocument{}, &ParseError{Code: "invalid-json"}
	}
	fields, err := parseJSONFields(normalized, maxLockfileBytes)
	if err != nil {
		return BunLockDocument{}, err
	}
	if err := validateBunLockVersion(fields["lockfileVersion"]); err != nil {
		return BunLockDocument{}, err
	}
	workspaces, err := rawObjectMembers(fields["workspaces"])
	if err != nil {
		return BunLockDocument{}, err
	}
	for _, raw := range workspaces {
		if !isJSONObject(raw) {
			return BunLockDocument{}, &ParseError{Code: "invalid-shape"}
		}
	}
	packages, err := rawObjectMembers(fields["packages"])
	if err != nil {
		return BunLockDocument{}, err
	}
	for _, raw := range packages {
		if !isJSONArray(raw) {
			return BunLockDocument{}, &ParseError{Code: "invalid-shape"}
		}
	}
	return BunLockDocument{
		SHA256:     sha256.Sum256(data),
		Fields:     fields,
		Workspaces: workspaces,
		Packages:   packages,
	}, nil
}

// validateBunLockVersion accepts only integer literals 0-3; other integers are
// unsupported rather than malformed.
func validateBunLockVersion(raw json.RawMessage) error {
	version := bytes.TrimSpace(raw)
	if !integerLiteral(version) {
		return &ParseError{Code: "invalid-shape"}
	}
	switch string(version) {
	case "0", "1", "2", "3":
		return nil
	default:
		return &ParseError{Code: "unsupported-version"}
	}
}

// rawObjectMembers returns a required object's members as raw JSON; missing, null,
// array, and scalar values are all invalid shape.
func rawObjectMembers(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, &ParseError{Code: "invalid-shape"}
	}
	return members, nil
}

// isJSONObject reports whether raw decodes as a non-null JSON object.
func isJSONObject(raw json.RawMessage) bool {
	var value map[string]json.RawMessage
	return json.Unmarshal(raw, &value) == nil && value != nil
}

// isJSONArray reports a non-null JSON array without interpreting its elements.
func isJSONArray(raw json.RawMessage) bool {
	var value []json.RawMessage
	return json.Unmarshal(raw, &value) == nil && value != nil
}
