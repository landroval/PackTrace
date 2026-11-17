package intel

// OSVAllSlotsRoutable is the construction and scan routing predicate. Counters
// cannot substitute for checking each actual affected slot in the original.
func OSVAllSlotsRoutable(header OSVHeader, affected OSVAffectedProjection, identities OSVNPMIdentityProjection) bool {
	if header.SourceSHA256 != affected.SourceSHA256 || header.SourceSHA256 != identities.SourceSHA256 || (header.Schema != OSVHeaderSchemaV1Implicit && header.Schema != OSVHeaderSchemaV1Declared) || affected.State != OSVFieldValue || len(identities.Entries) == 0 || len(identities.Entries) != len(affected.Entries) {
		return false
	}
	for i, identity := range identities.Entries {
		if identity.Index != i || identity.Qualification != OSVNPMIdentityCandidate || identity.Ecosystem.Value != "npm" || !validOSVNPMName(identity.Name.Value) {
			return false
		}
	}
	return true
}
