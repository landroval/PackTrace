package intel

// OSVRangeProblemKind identifies bounded structure/profile problems, not matches.
type OSVRangeProblemKind uint8

const (
	OSVRangeProblemUnknown OSVRangeProblemKind = iota
	OSVRangeProblemRangeNotObject
	OSVRangeProblemTypeUnusable
	OSVRangeProblemTypeOutsideProfile
	OSVRangeProblemEventsUnusable
	OSVRangeProblemEmptyEvents
	OSVRangeProblemEventNotObject
	OSVRangeProblemNoKnownEventKind
	OSVRangeProblemMultipleKnownEventKinds
	OSVRangeProblemUnknownEventField
	OSVRangeProblemEventValueUnusable
	OSVRangeProblemIntroducedNotRecorded
	OSVRangeProblemMixedFixedLastAffected
)

// OSVRangeStructureProblem locates a problem within its source range.
// EventIndex is -1 for range/list problems; Field is exact decoded field text.
type OSVRangeStructureProblem struct {
	Kind       OSVRangeProblemKind
	EventIndex int
	Field      string
}

// OSVRangeStructure preserves source shape and position with bounded checks.
// Checked means the selected event profile was attempted; Satisfied is not full
// OSV conformance, a valid version/interval, or matching eligibility.
type OSVRangeStructure struct {
	Index              int
	State, EventsState OSVFieldState
	Checked, Satisfied bool
	Problems           []OSVRangeStructureProblem
}

// OSVAffectedRangeStructure retains an affected slot and its range-list shape.
// Unavailable lists are nil; enumerable empty lists are non-nil empty slices.
type OSVAffectedRangeStructure struct {
	Index              int
	State, RangesState OSVFieldState
	Entries            []OSVRangeStructure
}

// OSVRangeStructureProjection binds checks to digest + affected/range indices.
// Original documents/projections remain the source evidence, not duplicated here.
type OSVRangeStructureProjection struct {
	SourceSHA256 [32]byte
	HeaderSchema OSVHeaderSchemaState
	State        OSVFieldState
	Entries      []OSVAffectedRangeStructure
}

// CheckOSVRangeStructure requires unchanged successful header/affected projections
// from the same unchanged successful OSVDocument, with no concurrent mutation.
// Basic guards do not authenticate forged data/digests. No versions or intervals
// are evaluated, and results establish neither complete coverage nor no-match.
func CheckOSVRangeStructure(header OSVHeader, affected OSVAffectedProjection) (OSVRangeStructureProjection, error) {
	if err := validateOSVRangeStructureInput(header, affected); err != nil {
		return OSVRangeStructureProjection{}, err
	}
	result := OSVRangeStructureProjection{SourceSHA256: affected.SourceSHA256, HeaderSchema: header.Schema, State: affected.State}
	if affected.State != OSVFieldValue {
		return result, nil
	}
	result.Entries = make([]OSVAffectedRangeStructure, 0, len(affected.Entries))
	inspectHeader := header.Schema == OSVHeaderSchemaV1Implicit || header.Schema == OSVHeaderSchemaV1Declared
	for _, entry := range affected.Entries {
		out := OSVAffectedRangeStructure{Index: entry.Index, State: entry.State, RangesState: entry.Ranges.State}
		if entry.Ranges.State == OSVFieldValue {
			out.Entries = make([]OSVRangeStructure, 0, len(entry.Ranges.Entries))
			for _, item := range entry.Ranges.Entries {
				out.Entries = append(out.Entries, checkOSVRangeStructure(item, inspectHeader))
			}
		}
		result.Entries = append(result.Entries, out)
	}
	return result, nil
}

func validOSVStructureList(state OSVFieldState, nilItems bool) bool {
	switch state {
	case OSVFieldValue:
		return !nilItems
	case OSVFieldAbsent, OSVFieldNull, OSVFieldInvalidType:
		return nilItems
	default:
		return false
	}
}

func validOSVStructureMember(state OSVFieldState) bool {
	return state == OSVFieldValue || state == OSVFieldNull || state == OSVFieldInvalidType
}

// Validate consumed layout and all budgets before allocating output, including
// scopes whose header/type cannot be inspected. This is not forged-input authentication.
func validateOSVRangeStructureInput(header OSVHeader, affected OSVAffectedProjection) error {
	badShape := func() error { return &ParseError{Code: "invalid-shape"} }
	if header.SourceSHA256 != affected.SourceSHA256 || !validOSVStructureList(affected.State, affected.Entries == nil) {
		return badShape()
	}
	if len(affected.Entries) > maxAffectedEntries {
		return &ParseError{Code: "limit-exceeded"}
	}
	remaining := maxRangeUnits
	for ai, entry := range affected.Entries {
		if entry.Index != ai || !validOSVStructureMember(entry.State) {
			return badShape()
		}
		if entry.State != OSVFieldValue {
			if entry.Ranges.State != OSVFieldUnavailable || entry.Ranges.Entries != nil {
				return badShape()
			}
			continue
		}
		if !validOSVStructureList(entry.Ranges.State, entry.Ranges.Entries == nil) {
			return badShape()
		}
		if err := consumeOSVRangeUnits(&remaining, len(entry.Ranges.Entries)); err != nil {
			return err
		}
		for ri, item := range entry.Ranges.Entries {
			if item.Index != ri || !validOSVStructureMember(item.State) {
				return badShape()
			}
			if item.State != OSVFieldValue {
				if item.Events.State != OSVFieldUnavailable || item.Events.Entries != nil {
					return badShape()
				}
				continue
			}
			if !validOSVStructureList(item.Events.State, item.Events.Entries == nil) {
				return badShape()
			}
			if err := consumeOSVRangeUnits(&remaining, len(item.Events.Entries)); err != nil {
				return err
			}
			for ei, event := range item.Events.Entries {
				if event.Index != ei || !validOSVStructureMember(event.State) {
					return badShape()
				}
				if event.State != OSVFieldValue {
					if event.Fields != nil {
						return badShape()
					}
					continue
				}
				if event.Fields == nil {
					return badShape()
				}
				if err := consumeOSVRangeUnits(&remaining, len(event.Fields)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkOSVRangeStructure(item OSVRange, inspectHeader bool) OSVRangeStructure {
	result := OSVRangeStructure{Index: item.Index, State: item.State, EventsState: item.Events.State}
	if !inspectHeader {
		return result
	}
	add := func(kind OSVRangeProblemKind, index int, field string) {
		result.Problems = append(result.Problems, OSVRangeStructureProblem{Kind: kind, EventIndex: index, Field: field})
	}
	if item.State != OSVFieldValue {
		add(OSVRangeProblemRangeNotObject, -1, "")
		return result
	}
	if item.Type.State != OSVFieldValue {
		add(OSVRangeProblemTypeUnusable, -1, "type")
		return result
	}
	if item.Type.Value != "SEMVER" && item.Type.Value != "ECOSYSTEM" {
		add(OSVRangeProblemTypeOutsideProfile, -1, "type")
		return result
	}
	result.Checked = true
	result.Problems = make([]OSVRangeStructureProblem, 0)
	if item.Events.State != OSVFieldValue {
		add(OSVRangeProblemEventsUnusable, -1, "events")
		return result
	}
	if len(item.Events.Entries) == 0 {
		add(OSVRangeProblemEmptyEvents, -1, "events")
	}
	allObjects, introduced, fixed, lastAffected := true, false, false, false
	for _, event := range item.Events.Entries {
		if event.State != OSVFieldValue {
			allObjects = false
			add(OSVRangeProblemEventNotObject, event.Index, "")
			continue
		}
		known := 0
		for _, field := range event.Fields {
			if isOSVRangeEventKind(field.Name) {
				known++
			}
			switch field.Name {
			case "introduced":
				introduced = true
			case "fixed":
				fixed = true
			case "last_affected":
				lastAffected = true
			}
		}
		if known == 0 {
			add(OSVRangeProblemNoKnownEventKind, event.Index, "")
		}
		if known > 1 {
			add(OSVRangeProblemMultipleKnownEventKinds, event.Index, "")
		}
		for _, field := range event.Fields {
			if !isOSVRangeEventKind(field.Name) {
				add(OSVRangeProblemUnknownEventField, event.Index, field.Name)
			} else if field.Value.State != OSVFieldValue || field.Value.Value == "" {
				add(OSVRangeProblemEventValueUnusable, event.Index, field.Name)
			}
		}
	}
	if allObjects && !introduced {
		add(OSVRangeProblemIntroducedNotRecorded, -1, "events")
	}
	if fixed && lastAffected {
		add(OSVRangeProblemMixedFixedLastAffected, -1, "events")
	}
	result.Satisfied = len(result.Problems) == 0
	return result
}

func isOSVRangeEventKind(name string) bool {
	return name == "introduced" || name == "fixed" || name == "last_affected" || name == "limit"
}
