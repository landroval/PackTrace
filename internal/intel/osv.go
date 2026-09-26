// Package intel retains intelligence evidence without fetching or matching it.
package intel

import (
	"crypto/sha256"
	"encoding/json"

	"packtrace/internal/jsoninput"
)

const maxOSVRecordBytes = 4 << 20

// OSVDocument is raw evidence, not a validated or matchable advisory.
// Fields own their bytes; SHA256 binds the exact original input, not publisher trust.
type OSVDocument struct {
	SHA256 [32]byte
	Fields map[string]json.RawMessage
}

// ParseError exposes a category without disclosing advisory content.
type ParseError struct{ Code string }

func (e *ParseError) Error() string { return "intel: " + e.Code }

// ParseOSVRecord checks strict JSON and nonempty id/modified strings only.
// Dates, schema versions, affectedness and withdrawal semantics remain unvalidated.
// The caller must not mutate data concurrently; returned fields own their bytes.
func ParseOSVRecord(data []byte) (OSVDocument, error) {
	fields, code := jsoninput.Object(data, maxOSVRecordBytes)
	if code != "" {
		return OSVDocument{}, &ParseError{Code: code}
	}
	for _, key := range []string{"id", "modified"} {
		var value string
		if err := json.Unmarshal(fields[key], &value); err != nil || value == "" {
			return OSVDocument{}, &ParseError{Code: "invalid-shape"}
		}
	}
	return OSVDocument{SHA256: sha256.Sum256(data), Fields: fields}, nil
}
