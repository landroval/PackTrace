package intel

import (
	"net/url"
	"strings"
)

// OSVNPMIdentityQualification is lexical/profile evidence, not origin, matching
// or enforcement eligibility. Unknown is abstention, not a negative identity.
type OSVNPMIdentityQualification uint8

const (
	OSVNPMIdentityUnknown OSVNPMIdentityQualification = iota
	OSVNPMIdentityCandidate
	OSVNPMIdentityUnqualified
	OSVNPMIdentityConflict
)

type OSVNPMIdentityProblemKind uint8

const (
	OSVNPMIdentityProblemUnknown OSVNPMIdentityProblemKind = iota
	OSVNPMIdentityProblemEcosystemUnusable
	OSVNPMIdentityProblemEcosystemOutsideProfile
	OSVNPMIdentityProblemNameUnusable
	OSVNPMIdentityProblemNameOutsideProfile
	OSVNPMIdentityProblemPURLUnusable
	OSVNPMIdentityProblemPURLOutsideProfile
	OSVNPMIdentityProblemPURLNameConflict
)

type OSVNPMIdentityProblem struct {
	Kind  OSVNPMIdentityProblemKind
	Field string
}

// OSVNPMIdentityEntry retains source claims at their original affected locator.
// PURLName is separately derived; it never fills a missing explicit name.
type OSVNPMIdentityEntry struct {
	Index                 int
	State, PackageState   OSVFieldState
	Ecosystem, Name, PURL OSVString
	Qualification         OSVNPMIdentityQualification
	PURLUsable            bool
	PURLName              string
	Problems              []OSVNPMIdentityProblem
}

type OSVNPMIdentityProjection struct {
	SourceSHA256 [32]byte
	HeaderSchema OSVHeaderSchemaState
	State        OSVFieldState
	Entries      []OSVNPMIdentityEntry
}

// QualifyOSVNPMIdentities requires unchanged successful projections from the
// same unchanged successful document, with no concurrent mutation. Basic guards
// validate consumed layout, not authenticity or full advisory conformance.
func QualifyOSVNPMIdentities(header OSVHeader, affected OSVAffectedProjection) (OSVNPMIdentityProjection, error) {
	if err := validateOSVNPMIdentityInput(header, affected); err != nil {
		return OSVNPMIdentityProjection{}, err
	}
	result := OSVNPMIdentityProjection{SourceSHA256: affected.SourceSHA256, HeaderSchema: header.Schema, State: affected.State}
	if affected.State != OSVFieldValue {
		return result, nil
	}
	result.Entries = make([]OSVNPMIdentityEntry, 0, len(affected.Entries))
	inspect := header.Schema == OSVHeaderSchemaV1Implicit || header.Schema == OSVHeaderSchemaV1Declared
	for _, entry := range affected.Entries {
		out := OSVNPMIdentityEntry{Index: entry.Index, State: entry.State, PackageState: entry.PackageState,
			Ecosystem: entry.Ecosystem, Name: entry.Name, PURL: entry.PURL}
		if inspect && entry.State == OSVFieldValue && entry.PackageState == OSVFieldValue {
			out = qualifyOSVNPMIdentityEntry(entry)
		}
		result.Entries = append(result.Entries, out)
	}
	return result, nil
}

func validateOSVNPMIdentityInput(header OSVHeader, affected OSVAffectedProjection) error {
	bad := func() error { return &ParseError{Code: "invalid-shape"} }
	if header.SourceSHA256 != affected.SourceSHA256 {
		return bad()
	}
	if len(affected.Entries) > maxAffectedEntries {
		return &ParseError{Code: "limit-exceeded"}
	}
	switch affected.State {
	case OSVFieldValue:
		if affected.Entries == nil {
			return bad()
		}
	case OSVFieldAbsent, OSVFieldNull, OSVFieldInvalidType:
		if affected.Entries != nil {
			return bad()
		}
		return nil
	default:
		return bad()
	}
	for index, entry := range affected.Entries {
		if entry.Index != index {
			return bad()
		}
		switch entry.State {
		case OSVFieldValue:
			if entry.PackageState < OSVFieldAbsent || entry.PackageState > OSVFieldValue {
				return bad()
			}
		case OSVFieldNull, OSVFieldInvalidType:
			if entry.PackageState != OSVFieldUnavailable {
				return bad()
			}
		default:
			return bad()
		}
		for _, claim := range []OSVString{entry.Ecosystem, entry.Name, entry.PURL} {
			if entry.PackageState != OSVFieldValue {
				if claim != (OSVString{}) {
					return bad()
				}
			} else if claim.State < OSVFieldAbsent || claim.State > OSVFieldValue || claim.State != OSVFieldValue && claim.Value != "" {
				return bad()
			}
		}
	}
	return nil
}

func qualifyOSVNPMIdentityEntry(entry OSVAffectedEntry) OSVNPMIdentityEntry {
	out := OSVNPMIdentityEntry{Index: entry.Index, State: entry.State, PackageState: entry.PackageState,
		Ecosystem: entry.Ecosystem, Name: entry.Name, PURL: entry.PURL,
		Qualification: OSVNPMIdentityUnqualified, Problems: []OSVNPMIdentityProblem{}}
	problem := func(kind OSVNPMIdentityProblemKind, field string) {
		out.Problems = append(out.Problems, OSVNPMIdentityProblem{Kind: kind, Field: field})
	}
	ecoOK := entry.Ecosystem.State == OSVFieldValue && entry.Ecosystem.Value == "npm"
	if entry.Ecosystem.State != OSVFieldValue {
		problem(OSVNPMIdentityProblemEcosystemUnusable, "ecosystem")
	} else if !ecoOK {
		problem(OSVNPMIdentityProblemEcosystemOutsideProfile, "ecosystem")
	}
	nameOK := entry.Name.State == OSVFieldValue && validOSVNPMName(entry.Name.Value)
	if entry.Name.State != OSVFieldValue {
		problem(OSVNPMIdentityProblemNameUnusable, "name")
	} else if !nameOK {
		problem(OSVNPMIdentityProblemNameOutsideProfile, "name")
	}
	switch entry.PURL.State {
	case OSVFieldAbsent:
		// Optional absence, not a fabricated PURL identity.
	case OSVFieldValue:
		out.PURLName, out.PURLUsable = parseOSVNPMIdentityPURL(entry.PURL.Value)
		if !out.PURLUsable {
			problem(OSVNPMIdentityProblemPURLOutsideProfile, "purl")
		}
	default:
		problem(OSVNPMIdentityProblemPURLUnusable, "purl")
	}
	if ecoOK && nameOK && out.PURLUsable && entry.Name.Value != out.PURLName {
		problem(OSVNPMIdentityProblemPURLNameConflict, "purl")
		out.Qualification = OSVNPMIdentityConflict
	} else if len(out.Problems) == 0 {
		out.Qualification = OSVNPMIdentityCandidate
	}
	return out
}

// validOSVNPMName implements the agreed case-sensitive ASCII/legacy subset,
// not the complete npm publishing validator or registration policy.
func validOSVNPMName(name string) bool {
	if len(name) == 0 || len(name) > 214 {
		return false
	}
	component := func(s string) bool {
		if s == "" {
			return false
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(name, "@") {
		parts := strings.Split(name[1:], "/")
		return len(parts) == 2 && component(parts[0]) && component(parts[1])
	}
	return name[0] != '.' && name[0] != '_' && component(name)
}

func parseOSVNPMIdentityPURL(text string) (string, bool) {
	// 8-byte prefix + at most three encoded bytes per ASCII identity character.
	if len(text) > 650 || !strings.HasPrefix(text, "pkg:npm/") {
		return "", false
	}
	tail := strings.TrimPrefix(text, "pkg:npm/")
	if strings.ContainsAny(tail, "@?#") {
		return "", false
	}
	parts := strings.Split(tail, "/")
	if len(parts) != 1 && len(parts) != 2 {
		return "", false
	}
	// Splitting before one-time path decoding prevents escaped separators from
	// inventing namespace/name positions. Query decoding would mishandle plus.
	name, err := url.PathUnescape(parts[len(parts)-1])
	if err != nil || strings.ContainsAny(name, "@/") {
		return "", false
	}
	if len(parts) == 2 {
		scope, err := url.PathUnescape(parts[0])
		if err != nil || !strings.HasPrefix(scope, "@") {
			return "", false
		}
		name = scope + "/" + name
	}
	if !validOSVNPMName(name) {
		return "", false
	}
	return name, true
}
