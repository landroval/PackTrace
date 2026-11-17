package intel

import "strings"

// CanonicalNPMName is the operational origin/routing subset, not the broader
// case-sensitive legacy identity parser. Keep construction and policy identical.
func CanonicalNPMName(name string) bool {
	if len(name) == 0 || len(name) > 214 {
		return false
	}
	parts := strings.Split(name, "/")
	if strings.HasPrefix(name, "@") {
		if len(parts) != 2 {
			return false
		}
		parts[0] = strings.TrimPrefix(parts[0], "@")
	} else if len(parts) != 1 {
		return false
	}
	for _, p := range parts {
		if p == "" || p[0] == '.' || p[0] == '_' {
			return false
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~') {
				return false
			}
		}
	}
	return true
}

// OSVAllSlotsRoutable is the construction and scan routing predicate. Counters
// cannot substitute for checking each actual affected slot in the original.
func OSVAllSlotsRoutable(header OSVHeader, affected OSVAffectedProjection, identities OSVNPMIdentityProjection) bool {
	if header.SourceSHA256 != affected.SourceSHA256 || header.SourceSHA256 != identities.SourceSHA256 || (header.Schema != OSVHeaderSchemaV1Implicit && header.Schema != OSVHeaderSchemaV1Declared) || affected.State != OSVFieldValue || len(identities.Entries) == 0 || len(identities.Entries) != len(affected.Entries) {
		return false
	}
	for i, identity := range identities.Entries {
		if identity.Index != i || identity.Qualification != OSVNPMIdentityCandidate || identity.Ecosystem.Value != "npm" || !CanonicalNPMName(identity.Name.Value) {
			return false
		}
	}
	return true
}
