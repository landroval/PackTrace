package integrityscan

import (
	"bytes"
	"encoding/json"
)

// This is the existing semantic reference ceiling, not a renewed table budget.
const maxPolicyReferences = 20000

// parseReferenceTable consumes only bounded, duplicate-free JSON already checked
// by ParsePolicy. Six explicit strings per row; only lockKey repeats location.
// Shared enums are validated before expansion, so neither expanded string storage
// nor semantic work multiplies arbitrary source text. Row text is bounded by the
// existing source byte cap; decoded references by the existing reference ceiling.
// Streaming fixed-width tuples avoids an unbounded intermediate [][]string and
// rejects excess cells before allocating them. Failed work is never retried with
// another representation. Wire, private-material and traffic budgets are unchanged.
func parseReferenceTable(raw json.RawMessage) ([]Reference, error) {
	fields, ok := strictFields(raw, []string{"format", "classification", "context", "rows"})
	if !ok {
		return nil, ErrPolicy
	}
	var format, classification, context string
	if json.Unmarshal(fields["format"], &format) != nil || format != "same-location-lockkey-v1" ||
		json.Unmarshal(fields["classification"], &classification) != nil || !oneOf(classification, "public", "private", "unknown") ||
		json.Unmarshal(fields["context"], &context) != nil || !oneOf(context, "none", "patch", "generated") {
		return nil, ErrPolicy
	}
	d := json.NewDecoder(bytes.NewReader(fields["rows"]))
	if token, err := d.Token(); err != nil || token != json.Delim('[') {
		return nil, ErrPolicy
	}
	refs := []Reference{}
	for d.More() {
		if len(refs) >= maxPolicyReferences {
			return nil, ErrPolicy
		}
		if token, err := d.Token(); err != nil || token != json.Delim('[') {
			return nil, ErrPolicy
		}
		var row [6]string
		for i := range row {
			if !d.More() {
				return nil, ErrPolicy
			}
			token, err := d.Token()
			value, ok := token.(string)
			if err != nil || !ok {
				return nil, ErrPolicy
			}
			row[i] = value
		}
		if token, err := d.Token(); err != nil || token != json.Delim(']') {
			return nil, ErrPolicy
		}
		refs = append(refs, Reference{Location: row[0], LockKey: row[0], Name: row[1], Version: row[2], Origin: row[3], ExpectedSRI: row[4], Archive: row[5], Classification: classification, Context: context})
	}
	if token, err := d.Token(); err != nil || token != json.Delim(']') {
		return nil, ErrPolicy
	}
	return refs, nil
}
