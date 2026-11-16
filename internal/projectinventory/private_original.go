package projectinventory

import (
	"packtrace/internal/inventory"
	"slices"
)

// PrivateOriginal normalizes finite collections for the strict private protocol
// without modifying the acquired model or reinterpreting absent field states.
func PrivateOriginal(r Result) Result {
	r.Model.Scopes = append([]Scope{}, r.Model.Scopes...)
	r.Model.Evidence = append([]Evidence{}, r.Model.Evidence...)
	r.Model.Relations = append([]Relation{}, r.Model.Relations...)
	r.Model.Gaps = append([]Gap{}, r.Model.Gaps...)
	r.Model.Observations = append([]Observation{}, r.Model.Observations...)
	for i := range r.Model.Observations {
		o := &r.Model.Observations[i]
		if o.Fields == nil {
			o.Fields = map[string]string{}
		}
		o.Requirements = append([]inventory.DependencyGroup{}, o.Requirements...)
		for j := range o.Requirements {
			o.Requirements[j].Entries = append([]inventory.DeclaredDependency{}, o.Requirements[j].Entries...)
		}
	}
	return r
}

// ValidateOriginalClaims joins a separately admitted private acquisition to its
// public numeric projection. It does not authenticate child-supplied acquisition
// claims against a fully malicious child or make manifests trusted identities.
func ValidateOriginalClaims(p PublicInventory) error {
	if p.OriginalClaims == nil || p.Selection.Family != "bun" || p.OriginalClaims.Selection.Family != "bun" || ValidatePublic(p) != nil {
		return ErrWire
	}
	original := PortableMatching(*p.OriginalClaims)
	if original.Selection != p.Selection || original.Counts != p.Counts || original.Complete != p.Complete || !slices.Equal(original.Scopes, p.Scopes) || !slices.Equal(original.Evidence, p.Evidence) || !slices.Equal(original.Observations, p.Observations) || !slices.Equal(original.Relations, p.Relations) || !slices.Equal(original.Gaps, p.Gaps) {
		return ErrWire
	}
	return nil
}
