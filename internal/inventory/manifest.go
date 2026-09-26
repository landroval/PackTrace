package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"maps"
	"slices"
)

const (
	maxManifestBytes        = 2 << 20
	maxManifestDeclarations = 20_000
)

// ManifestDocument retains raw declared evidence, not an installed inventory.
type ManifestDocument struct {
	SHA256 [32]byte
	Fields map[string]json.RawMessage
}

// DeclaredDependency retains an exact local key and its uninterpreted requirement.
// State describes the requirement's JSON type, not npm name/range validity.
type DeclaredDependency struct {
	Name        string
	Requirement string
	State       FieldState
}

// DependencyGroup distinguishes absent, null, object, and wrong-type groups.
// FieldValue means an object; individual declarations may still have invalid types.
type DependencyGroup struct {
	Name    string
	State   FieldState
	Entries []DeclaredDependency
}

// ManifestProjection links declarations to source bytes, not resolved packages.
// It is internal analysis data, not a public report or an authenticity assertion.
type ManifestProjection struct {
	SourceSHA256 [32]byte
	Groups       []DependencyGroup
}

// ParseManifest reads one manifest object without interpreting its configuration.
// The caller must not mutate data concurrently; returned raw fields own their bytes.
func ParseManifest(data []byte) (ManifestDocument, error) {
	fields, err := parseJSONFields(data, maxManifestBytes)
	if err != nil {
		return ManifestDocument{}, err
	}
	return ManifestDocument{SHA256: sha256.Sum256(data), Fields: fields}, nil
}

// ProjectManifest requires an unchanged successful ParseManifest result and no
// concurrent mutation. It does not authenticate or revalidate a forged document.
func ProjectManifest(doc ManifestDocument) (ManifestProjection, error) {
	if doc.Fields == nil {
		return ManifestProjection{}, &ParseError{Code: "invalid-shape"}
	}
	groups, _, err := projectDependencyGroups(doc.Fields, maxManifestDeclarations)
	if err != nil {
		return ManifestProjection{}, err
	}
	return ManifestProjection{SourceSHA256: doc.SHA256, Groups: groups}, nil
}

// projectDependencyGroups projects recorded requirements without resolving them.
// Callers supply a remaining whole-document allowance; source class stays with them.
func projectDependencyGroups(fields map[string]json.RawMessage, allowance int) ([]DependencyGroup, int, error) {
	groups := []DependencyGroup{
		{Name: "dependencies"},
		{Name: "devDependencies"},
		{Name: "optionalDependencies"},
		{Name: "peerDependencies"},
	}
	total := 0
	for i := range groups {
		group := &groups[i]
		raw, present := fields[group.Name]
		if !present {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			group.State = FieldNull
			continue
		}
		var entries map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			group.State = FieldInvalidType
			continue
		}
		if len(entries) > allowance-total {
			return nil, 0, &ParseError{Code: "limit-exceeded"}
		}
		total += len(entries)
		group.State = FieldValue
		group.Entries = make([]DeclaredDependency, 0, len(entries))
		for _, name := range slices.Sorted(maps.Keys(entries)) {
			field := projectField[string](entries, name)
			group.Entries = append(group.Entries, DeclaredDependency{
				Name: name, Requirement: field.Value, State: field.State,
			})
		}
	}
	return groups, total, nil
}
