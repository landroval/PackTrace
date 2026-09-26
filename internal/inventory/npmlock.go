// Package inventory reads dependency evidence without resolving or executing it.
package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

const (
	maxLockfileBytes = 64 << 20
	maxJSONDepth     = 128
)

// Document contains locked, uninterpreted evidence, not an installed inventory.
// Raw values own their bytes. Fields includes packages and unknown top-level data.
type Document struct {
	SHA256   [32]byte
	Fields   map[string]json.RawMessage
	Packages map[string]map[string]json.RawMessage
}

// ParseError exposes a category without disclosing input contents.
type ParseError struct{ Code string }

func (e *ParseError) Error() string { return "npm v3: " + e.Code }

// ParseNPMLockV3 reads one lockfile-version-3 document from memory. The caller
// must not mutate data during the call. Successful parsing does not establish
// producer compatibility, effective-input selection, provenance, or safety.
func ParseNPMLockV3(data []byte) (Document, error) {
	if len(data) > maxLockfileBytes {
		return Document{}, &ParseError{Code: "limit-exceeded"}
	}
	if !utf8.Valid(data) {
		return Document{}, &ParseError{Code: "invalid-json"}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateValue(decoder, 0); err != nil {
		return Document{}, err
	}
	if _, err := decoder.Token(); err != io.EOF || !validSurrogates(data) {
		return Document{}, &ParseError{Code: "invalid-json"}
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return Document{}, &ParseError{Code: "invalid-shape"}
	}
	version := bytes.TrimSpace(fields["lockfileVersion"])
	if !integerLiteral(version) {
		return Document{}, &ParseError{Code: "invalid-shape"}
	}
	if string(version) != "3" {
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

// validateValue combines syntax, depth, and duplicate-key validation so the
// application depth bound is enforced before the decoder's larger internal limit.
func validateValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return &ParseError{Code: "invalid-json"}
	}
	open, container := token.(json.Delim)
	if !container {
		return nil
	}
	if open != '{' && open != '[' {
		return &ParseError{Code: "invalid-json"}
	}
	if depth >= maxJSONDepth {
		return &ParseError{Code: "limit-exceeded"}
	}
	close := json.Delim(']')
	var keys map[string]struct{}
	if open == '{' {
		close = '}'
		keys = make(map[string]struct{})
	}
	for decoder.More() {
		if open == '{' {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok {
				return &ParseError{Code: "invalid-json"}
			}
			if _, duplicate := keys[key]; duplicate {
				return &ParseError{Code: "duplicate-key"}
			}
			keys[key] = struct{}{}
		}
		if err := validateValue(decoder, depth+1); err != nil {
			return err
		}
	}
	if token, err := decoder.Token(); err != nil || token != close {
		return &ParseError{Code: "invalid-json"}
	}
	return nil
}

// validSurrogates supplements encoding/json, which otherwise replaces unpaired
// escaped UTF-16 surrogates with U+FFFD. Syntax must already have been validated.
func validSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			i++
			if data[i] != 'u' {
				continue
			}
			code, _ := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
			i += 4
			if code >= 0xdc00 && code <= 0xdfff {
				return false
			}
			if code >= 0xd800 && code <= 0xdbff {
				if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
					return false
				}
				low, _ := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
				if low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			}
		}
	}
	return true
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
