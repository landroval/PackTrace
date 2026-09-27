package intel

import (
	"encoding/json"
	"maps"
	"slices"
)

const maxRangeUnits = 20_000

// OSVRanges retains range-list shape and positions, not evaluated intervals.
type OSVRanges struct {
	State   OSVFieldState
	Entries []OSVRange
}

// OSVRange retains type/repo claims even when its events cannot be inspected.
// Unusable range elements leave their children unavailable.
type OSVRange struct {
	Index      int
	State      OSVFieldState
	Type, Repo OSVString
	Events     OSVEvents
}

// OSVEvents retains event-array order and duplicates without selecting bounds.
type OSVEvents struct {
	State   OSVFieldState
	Entries []OSVEvent
}

// OSVEvent fields are sorted by exact decoded name, including unknown names.
// Only object events have non-nil Fields, including empty objects.
type OSVEvent struct {
	Index  int
	State  OSVFieldState
	Fields []OSVEventField
}

// OSVEventField is one recorded claim, not a qualified event kind or version.
type OSVEventField struct {
	Name  string
	Value OSVString
}

func projectOSVRanges(fields map[string]json.RawMessage, remaining *int) (OSVRanges, error) {
	raw, present := fields["ranges"]
	items, state := decodeOSVField[[]json.RawMessage](raw, present)
	result := OSVRanges{State: state}
	if state != OSVFieldValue {
		return result, nil
	}
	if err := consumeOSVRangeUnits(remaining, len(items)); err != nil {
		return OSVRanges{}, err
	}
	result.Entries = make([]OSVRange, 0, len(items))
	for index, raw := range items {
		fields, state := decodeOSVField[map[string]json.RawMessage](raw, true)
		entry := OSVRange{Index: index, State: state}
		if state == OSVFieldValue {
			entry.Type = projectOSVString(fields, "type")
			entry.Repo = projectOSVString(fields, "repo")
			events, err := projectOSVEvents(fields, remaining)
			if err != nil {
				return OSVRanges{}, err
			}
			entry.Events = events
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}

func projectOSVEvents(fields map[string]json.RawMessage, remaining *int) (OSVEvents, error) {
	raw, present := fields["events"]
	items, state := decodeOSVField[[]json.RawMessage](raw, present)
	result := OSVEvents{State: state}
	if state != OSVFieldValue {
		return result, nil
	}
	if err := consumeOSVRangeUnits(remaining, len(items)); err != nil {
		return OSVEvents{}, err
	}
	result.Entries = make([]OSVEvent, 0, len(items))
	for index, raw := range items {
		fields, state := decodeOSVField[map[string]json.RawMessage](raw, true)
		entry := OSVEvent{Index: index, State: state}
		if state == OSVFieldValue {
			if err := consumeOSVRangeUnits(remaining, len(fields)); err != nil {
				return OSVEvents{}, err
			}
			entry.Fields = make([]OSVEventField, 0, len(fields))
			for _, name := range slices.Sorted(maps.Keys(fields)) {
				entry.Fields = append(entry.Fields, OSVEventField{Name: name, Value: projectOSVString(fields, name)})
			}
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}

// All callers share one advisory-local counter and pass collection lengths.
func consumeOSVRangeUnits(remaining *int, count int) error {
	if count > *remaining {
		return &ParseError{Code: "limit-exceeded"}
	}
	*remaining -= count
	return nil
}
