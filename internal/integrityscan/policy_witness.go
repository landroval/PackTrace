package integrityscan

// PolicyDifferenceWitness is admitted with the original integrity record, apart
// from the later policy-material stream. It binds a material's private path,
// file sides and installed endpoint to that exact difference. It is structural
// association evidence, not independent reexecution of the physical worker.
type PolicyDifferenceWitness struct {
	Difference  int    `json:"difference"`
	EntryID     string `json:"entryID"`
	EvidenceID  string `json:"evidenceID"`
	Fingerprint string `json:"fingerprint"`
}

func PolicyDifferenceFingerprint(m PolicyMaterial) string {
	return policyFingerprint("integrity-record-witness", m)
}
