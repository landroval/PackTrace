package integrityscan

// PolicyReview is deliberately not PolicyMaterial: only explicitly local safe
// review fields survive. In particular raw origins, authority pins, absolute
// paths and worker graph/physical identifiers cannot be serialized here.
type PolicyReview struct {
	Project              string        `json:"project"`
	Rule                 string        `json:"rule"`
	Class                string        `json:"class"`
	Advisory             string        `json:"advisory,omitempty"`
	Change               string        `json:"change,omitempty"`
	OriginFingerprint    string        `json:"originFingerprint"`
	RootManifestSHA256   string        `json:"rootManifestSHA256"`
	SelectedLockSHA256   string        `json:"selectedLockSHA256"`
	ObservationSHA256    string        `json:"observationSHA256"`
	OriginalSHA256       string        `json:"originalSHA256,omitempty"`
	Profile              string        `json:"profile"`
	Expected             *EvidenceSide `json:"expected,omitempty"`
	Observed             *EvidenceSide `json:"observed,omitempty"`
	ReferenceSRI         string        `json:"referenceSRI,omitempty"`
	ReferenceObservedSRI string        `json:"referenceObservedSRI,omitempty"`
	Assurance            string        `json:"assurance,omitempty"`
}

func localPolicyReview(m PolicyMaterial) *PolicyReview {
	r := &PolicyReview{Project: m.Scope.Project, Rule: m.Scope.Rule, Class: m.Scope.Class, Advisory: m.Scope.Advisory, Change: m.Scope.Change, OriginFingerprint: policyFingerprint("origin", m.Scope.Origin), RootManifestSHA256: m.Project.ManifestSHA256, SelectedLockSHA256: m.Project.LockSHA256, ObservationSHA256: m.SourceSHA256, OriginalSHA256: m.OriginalSHA256, Profile: m.Profile}
	if m.Scope.Category == "integrity" {
		expected, observed := m.Expected, m.Observed
		r.Expected, r.Observed = &expected, &observed
		r.ReferenceSRI, r.ReferenceObservedSRI, r.Assurance = m.ReferenceSRI, m.ReferenceObservedSRI, m.Assurance
	}
	return r
}
