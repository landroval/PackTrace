package intel

import (
	"errors"
	"slices"
)

type OSVVersionOutcome uint8

const (
	OSVVersionIndeterminate OSVVersionOutcome = iota
	OSVVersionNoMatch
	OSVVersionMatch
)

type OSVVersionProblemKind string

type OSVVersionProblem struct {
	Kind                                 OSVVersionProblemKind
	VersionIndex, RangeIndex, EventIndex int
}

type OSVVersionSupport struct{ VersionIndex, RangeIndex int }

type OSVVersionEntryDecision struct {
	Index          int
	State          OSVFieldState
	Outcome        OSVVersionOutcome
	FullyEvaluated bool
	Support        []OSVVersionSupport
	Problems       []OSVVersionProblem
}

type OSVVersionConditions struct {
	SourceSHA256 [32]byte
	HeaderSchema OSVHeaderSchemaState
	Query        SemVer
	State        OSVFieldState
	Entries      []OSVVersionEntryDecision
	Problems     []OSVVersionProblem
}

func versionConditionProblem(kind OSVVersionProblemKind, vi, ri, ei int) OSVVersionProblem {
	return OSVVersionProblem{kind, vi, ri, ei}
}

// EvaluateOSVVersionConditions derives version-only decisions from unchanged successful
// same-document projections. It does not qualify identity, origin, activity or coverage.
// Basic shape/digest guards do not authenticate fabricated evidence. Query values must
// come from ParseSemVer (or be unqualified zero); concurrent/unsafe mutation is excluded.
func EvaluateOSVVersionConditions(header OSVHeader, affected OSVAffectedProjection, query SemVer) (OSVVersionConditions, error) {
	if err := validateOSVVersionConditionsInput(header, affected); err != nil {
		return OSVVersionConditions{}, err
	}
	structure, err := CheckOSVRangeStructure(header, affected)
	if err != nil {
		return OSVVersionConditions{}, err
	}
	out := OSVVersionConditions{SourceSHA256: affected.SourceSHA256, HeaderSchema: header.Schema, Query: query, State: affected.State, Problems: make([]OSVVersionProblem, 0)}
	if header.Schema != OSVHeaderSchemaV1Implicit && header.Schema != OSVHeaderSchemaV1Declared {
		out.Problems = append(out.Problems, versionConditionProblem("header-unsupported", -1, -1, -1))
	}
	if !query.qualified {
		out.Problems = append(out.Problems, versionConditionProblem("query-unqualified", -1, -1, -1))
	}
	if affected.State != OSVFieldValue {
		out.Problems = append(out.Problems, versionConditionProblem("affected-uninspectable", -1, -1, -1))
		return out, nil
	}
	blocked := len(out.Problems) != 0
	out.Entries = make([]OSVVersionEntryDecision, 0, len(affected.Entries))
	for i, entry := range affected.Entries {
		d := OSVVersionEntryDecision{Index: entry.Index, State: entry.State, Problems: make([]OSVVersionProblem, 0)}
		if entry.State != OSVFieldValue {
			d.Problems = append(d.Problems, versionConditionProblem("affected-uninspectable", -1, -1, -1))
		} else if !blocked {
			evaluateOSVVersionEntry(&d, entry, structure.Entries[i], query)
		}
		out.Entries = append(out.Entries, d)
	}
	return out, nil
}

func validVersionConditionScalar(v OSVString, allowAbsent bool) bool {
	if v.State == OSVFieldValue {
		return true
	}
	return v.Value == "" && (v.State == OSVFieldNull || v.State == OSVFieldInvalidType || allowAbsent && v.State == OSVFieldAbsent)
}

// Validate all consumed shape/text before allocating decisions, including blocked
// headers and late slots. These bounds are work limits, not hard resident-memory caps.
func validateOSVVersionConditionsInput(h OSVHeader, a OSVAffectedProjection) error {
	bad := func() error { return &ParseError{Code: "invalid-shape"} }
	if h.Schema > OSVHeaderSchemaUnsupported {
		return bad()
	}
	if err := validateOSVRangeStructureInput(h, a); err != nil {
		return err
	}
	versions, text := maxAffectedVersions, 4<<20
	consume := func(s string) error {
		if len(s) > text {
			return &ParseError{Code: "limit-exceeded"}
		}
		text -= len(s)
		return nil
	}
	for _, entry := range a.Entries {
		if entry.State != OSVFieldValue {
			if entry.Versions.State != OSVFieldUnavailable || entry.Versions.Entries != nil {
				return bad()
			}
			continue
		}
		if !validOSVStructureList(entry.Versions.State, entry.Versions.Entries == nil) {
			return bad()
		}
		if len(entry.Versions.Entries) > versions {
			return &ParseError{Code: "limit-exceeded"}
		}
		versions -= len(entry.Versions.Entries)
		for _, v := range entry.Versions.Entries {
			if !validVersionConditionScalar(v, false) {
				return bad()
			}
			if err := consume(v.Value); err != nil {
				return err
			}
		}
		for _, r := range entry.Ranges.Entries {
			if r.State != OSVFieldValue {
				continue
			}
			if !validVersionConditionScalar(r.Type, true) {
				return bad()
			}
			if err := consume(r.Type.Value); err != nil {
				return err
			}
			for _, event := range r.Events.Entries {
				if event.State != OSVFieldValue {
					continue
				}
				for i, field := range event.Fields {
					if !validVersionConditionScalar(field.Value, false) {
						return bad()
					}
					if err := consume(field.Name); err != nil {
						return err
					}
					if err := consume(field.Value.Value); err != nil {
						return err
					}
					if i > 0 && field.Name <= event.Fields[i-1].Name {
						return bad()
					}
				}
			}
		}
	}
	return nil
}

func versionConditionTextProblem(err error, prefix string) OSVVersionProblemKind {
	var pe *ParseError
	if errors.As(err, &pe) && pe.Code == "limit-exceeded" {
		return OSVVersionProblemKind(prefix + "-limit")
	}
	return OSVVersionProblemKind(prefix + "-outside-profile")
}

func evaluateOSVVersionEntry(d *OSVVersionEntryDecision, e OSVAffectedEntry, s OSVAffectedRangeStructure, q SemVer) {
	d.Support = make([]OSVVersionSupport, 0)
	usable := false
	if e.Versions.State == OSVFieldValue {
		for i, v := range e.Versions.Entries {
			if v.State != OSVFieldValue {
				d.Problems = append(d.Problems, versionConditionProblem("version-outside-profile", i, -1, -1))
				continue
			}
			parsed, err := ParseSemVer(v.Value)
			if err != nil {
				d.Problems = append(d.Problems, versionConditionProblem(versionConditionTextProblem(err, "version"), i, -1, -1))
				continue
			}
			usable = true
			if parsed.Text() == q.Text() {
				d.Support = append(d.Support, OSVVersionSupport{i, -1})
			}
		}
	} else if e.Versions.State != OSVFieldAbsent {
		d.Problems = append(d.Problems, versionConditionProblem("versions-uninspectable", -1, -1, -1))
	}
	if e.Ranges.State == OSVFieldValue {
		for i, r := range e.Ranges.Entries {
			match, known, problems := evaluateOSVVersionRange(r, s.Entries[i], q)
			usable = usable || known
			d.Problems = append(d.Problems, problems...)
			if match {
				d.Support = append(d.Support, OSVVersionSupport{-1, r.Index})
			}
		}
	} else if e.Ranges.State != OSVFieldAbsent {
		d.Problems = append(d.Problems, versionConditionProblem("range-structure", -1, -1, -1))
	}
	if !usable {
		d.Problems = append(d.Problems, versionConditionProblem("no-usable-condition", -1, -1, -1))
	}
	d.FullyEvaluated = usable && len(d.Problems) == 0
	if len(d.Support) != 0 {
		d.Outcome = OSVVersionMatch
	} else if d.FullyEvaluated {
		d.Outcome = OSVVersionNoMatch
	}
}

type osvVersionTransition struct {
	kind  string
	value SemVer
	zero  bool
	index int
}

func compareOSVVersionTransitions(a, b osvVersionTransition) int {
	if a.zero && b.zero {
		return 0
	}
	if a.zero {
		return -1
	}
	if b.zero {
		return 1
	}
	// Both operands were successfully parsed; no zero/unqualified value reaches here.
	n, _ := CompareSemVer(a.value, b.value)
	return n
}

func evaluateOSVVersionRange(r OSVRange, s OSVRangeStructure, q SemVer) (bool, bool, []OSVVersionProblem) {
	problem := func(kind OSVVersionProblemKind) (bool, bool, []OSVVersionProblem) {
		return false, false, []OSVVersionProblem{versionConditionProblem(kind, -1, r.Index, -1)}
	}
	if r.State != OSVFieldValue {
		return problem("range-structure")
	}
	if r.Type.State != OSVFieldValue || r.Type.Value != "SEMVER" {
		return problem("range-outside-profile")
	}
	if !s.Checked || !s.Satisfied {
		return problem("range-structure")
	}
	transitions := make([]osvVersionTransition, 0, len(r.Events.Entries))
	problems := make([]OSVVersionProblem, 0)
	hasLimit, allowed := false, false
	for _, event := range r.Events.Entries {
		// Satisfied structure guarantees exactly one known, nonempty string field.
		field := event.Fields[0]
		if field.Name == "limit" && field.Value.Value == "*" {
			hasLimit, allowed = true, true
			continue
		}
		if field.Name == "introduced" && field.Value.Value == "0" {
			transitions = append(transitions, osvVersionTransition{kind: "introduced", zero: true, index: event.Index})
			continue
		}
		v, err := ParseSemVer(field.Value.Value)
		if err != nil {
			problems = append(problems, versionConditionProblem(versionConditionTextProblem(err, "bound"), -1, r.Index, event.Index))
			continue
		}
		if field.Name == "limit" {
			hasLimit = true
			// q and v are qualified upstream; error cannot become an equality fallback.
			n, _ := CompareSemVer(q, v)
			allowed = allowed || n < 0
		} else {
			transitions = append(transitions, osvVersionTransition{field.Name, v, false, event.Index})
		}
	}
	// Every bound must qualify before this range can contribute any decision.
	if len(problems) != 0 {
		return false, false, problems
	}
	slices.SortFunc(transitions, compareOSVVersionTransitions)
	for i := 0; i < len(transitions); {
		j, mixed := i+1, false
		for j < len(transitions) && compareOSVVersionTransitions(transitions[i], transitions[j]) == 0 {
			mixed = mixed || transitions[i].kind != transitions[j].kind
			j++
		}
		if mixed {
			for _, tr := range transitions[i:j] {
				problems = append(problems, versionConditionProblem("precedence-tie", -1, r.Index, tr.index))
			}
		}
		i = j
	}
	if len(problems) != 0 {
		slices.SortFunc(problems, func(a, b OSVVersionProblem) int {
			if a.EventIndex < b.EventIndex {
				return -1
			}
			if a.EventIndex > b.EventIndex {
				return 1
			}
			return 0
		})
		return false, false, problems
	}
	if hasLimit && !allowed {
		return false, true, nil
	}
	affected := false
	for _, tr := range transitions {
		n := 1
		if !tr.zero {
			n, _ = CompareSemVer(q, tr.value)
		}
		switch tr.kind {
		case "introduced":
			if n >= 0 {
				affected = true
			}
		case "fixed":
			if n >= 0 {
				affected = false
			}
		case "last_affected":
			if n > 0 {
				affected = false
			}
		}
	}
	return affected, true, nil
}
