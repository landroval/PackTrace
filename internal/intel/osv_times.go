package intel

import (
	"bytes"
	"encoding/json"
	"regexp"
	"time"
)

// Explicit profile prevents permissive parsing and silent precision truncation.
var osvTimestampPattern = regexp.MustCompile(
	`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}` +
		`(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$`)

// TimestampState distinguishes absent/unusable evidence from an interpreted instant.
type TimestampState uint8

const (
	TimestampAbsent TimestampState = iota
	TimestampNull
	TimestampInvalidType
	TimestampUninterpretable
	TimestampValue
)

// OSVTimestamp retains original decoded text. Value is UTC only when State is
// TimestampValue; a zero time can be valid. Uninterpretable does not mean invalid RFC3339.
type OSVTimestamp struct {
	State TimestampState
	Text  string
	Value time.Time
}

// WithdrawalState describes a source claim, never active or matchable status.
type WithdrawalState uint8

const (
	WithdrawalUnknown WithdrawalState = iota
	WithdrawalNotDeclared
	WithdrawalReported
)

// OSVTimes binds independent field claims to source bytes, not to acquisition freshness.
type OSVTimes struct {
	SourceSHA256                   [32]byte
	Modified, Published, Withdrawn OSVTimestamp
	Withdrawal                     WithdrawalState
}

// ProjectOSVTimes requires an unchanged successful OSVDocument and no concurrent
// mutation. It neither authenticates a forged document nor qualifies an advisory.
func ProjectOSVTimes(doc OSVDocument) (OSVTimes, error) {
	if doc.Fields == nil {
		return OSVTimes{}, &ParseError{Code: "invalid-shape"}
	}
	result := OSVTimes{
		SourceSHA256: doc.SHA256,
		Modified:     projectOSVTimestamp(doc.Fields, "modified"),
		Published:    projectOSVTimestamp(doc.Fields, "published"),
		Withdrawn:    projectOSVTimestamp(doc.Fields, "withdrawn"),
	}
	switch result.Withdrawn.State {
	case TimestampAbsent:
		result.Withdrawal = WithdrawalNotDeclared
	case TimestampValue:
		result.Withdrawal = WithdrawalReported
	}
	return result, nil
}

func projectOSVTimestamp(fields map[string]json.RawMessage, key string) OSVTimestamp {
	raw, present := fields[key]
	if !present {
		return OSVTimestamp{}
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return OSVTimestamp{State: TimestampNull}
	}
	result := OSVTimestamp{State: TimestampUninterpretable}
	if err := json.Unmarshal(raw, &result.Text); err != nil {
		return OSVTimestamp{State: TimestampInvalidType}
	}
	if !osvTimestampPattern.MatchString(result.Text) {
		return result
	}
	// UTC avoids the implicit local-zone lookup performed by time.Parse.
	value, err := time.ParseInLocation(time.RFC3339Nano, result.Text, time.UTC)
	if err != nil {
		return result
	}
	value = value.UTC()
	if value.Year() < 0 || value.Year() > 9999 {
		return result
	}
	result.State, result.Value = TimestampValue, value
	return result
}
