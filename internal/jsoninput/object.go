// Package jsoninput validates bounded JSON evidence without format semantics.
package jsoninput

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

const maxJSONDepth = 128

// Object returns owned raw fields and an empty code on success. Failures return
// nil fields and only invalid-json, duplicate-key, limit-exceeded, or invalid-shape.
// The caller must not mutate data concurrently. The byte bound is not an RSS cap.
func Object(data []byte, byteLimit int) (map[string]json.RawMessage, string) {
	if len(data) > byteLimit {
		return nil, "limit-exceeded"
	}
	if !utf8.Valid(data) {
		return nil, "invalid-json"
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if code := validateValue(decoder, 0); code != "" {
		return nil, code
	}
	if _, err := decoder.Token(); err != io.EOF || !validSurrogates(data) {
		return nil, "invalid-json"
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, "invalid-shape"
	}
	return fields, ""
}

// validateValue combines syntax, depth, and duplicate-key validation so the
// application depth bound is enforced before the decoder's larger internal limit.
func validateValue(decoder *json.Decoder, depth int) string {
	token, err := decoder.Token()
	if err != nil {
		return "invalid-json"
	}
	open, container := token.(json.Delim)
	if !container {
		return ""
	}
	if open != '{' && open != '[' {
		return "invalid-json"
	}
	if depth >= maxJSONDepth {
		return "limit-exceeded"
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
				return "invalid-json"
			}
			if _, duplicate := keys[key]; duplicate {
				return "duplicate-key"
			}
			keys[key] = struct{}{}
		}
		if code := validateValue(decoder, depth+1); code != "" {
			return code
		}
	}
	if token, err := decoder.Token(); err != nil || token != close {
		return "invalid-json"
	}
	return ""
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
