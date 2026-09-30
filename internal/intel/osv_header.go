package intel

import (
	"regexp"
	"strings"
)

// OSVHeaderSchemaState interprets only a bounded schema-header profile, not
// full advisory conformance, authenticity or matching eligibility.
type OSVHeaderSchemaState uint8

const (
	OSVHeaderSchemaUnknown OSVHeaderSchemaState = iota
	OSVHeaderSchemaV1Implicit
	OSVHeaderSchemaV1Declared
	OSVHeaderSchemaUnsupported
)

// OSVHeader retains exact source claims; implicit v1 never replaces source absence.
// Evidence locators are SourceSHA256 plus id or schema_version.
type OSVHeader struct {
	SourceSHA256      [32]byte
	ID, SchemaVersion OSVString
	Schema            OSVHeaderSchemaState
}

var osvHeaderCorePattern = regexp.MustCompile(
	`\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z`,
)

// ProjectOSVHeader requires an unchanged successful OSVDocument with no concurrent
// mutation. Basic guards do not authenticate or revalidate forged documents.
// Only canonical numeric cores are interpreted; SemVer suffixes remain unknown.
func ProjectOSVHeader(doc OSVDocument) (OSVHeader, error) {
	if doc.Fields == nil {
		return OSVHeader{}, &ParseError{Code: "invalid-shape"}
	}
	result := OSVHeader{
		SourceSHA256:  doc.SHA256,
		ID:            projectOSVString(doc.Fields, "id"),
		SchemaVersion: projectOSVString(doc.Fields, "schema_version"),
	}
	schema := result.SchemaVersion
	if schema.State == OSVFieldAbsent {
		result.Schema = OSVHeaderSchemaV1Implicit
	} else if schema.State == OSVFieldValue && osvHeaderCorePattern.MatchString(schema.Value) {
		if strings.HasPrefix(schema.Value, "1.") {
			result.Schema = OSVHeaderSchemaV1Declared
		} else {
			result.Schema = OSVHeaderSchemaUnsupported
		}
	}
	return result, nil
}
