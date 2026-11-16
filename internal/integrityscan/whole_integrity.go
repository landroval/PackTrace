package integrityscan

import (
	"crypto/sha256"
	"encoding/json"
	"strconv"

	"packtrace/internal/integrity"
	"packtrace/internal/projectinventory"
)

// IntegrityScopeWitness is a private native acquisition receipt, admitted with
// the comparison, independently of optional changed-file policy material. Its
// endpoints are checked against separately retained original inventory receipts.
// It is consistency evidence within the native acquisition boundary, not a grant
// of publisher authenticity, source/index or platform qualification.
type IntegrityScopeWitness struct {
	Reference        Reference                         `json:"reference"`
	Observation      uint32                            `json:"observation"`
	Manifest         projectinventory.Evidence         `json:"manifest"`
	Directory        projectinventory.Evidence         `json:"directory"`
	ManifestEntry    integrity.InstalledEntry          `json:"manifestEntry"`
	Catalog          integrity.ReferenceCatalogReceipt `json:"catalog"`
	PolicySourceHash string                            `json:"policySourceHash"`
	Comparison       [32]byte                          `json:"comparison"`
}

func comparisonDigest(r Record) [32]byte {
	if r.Assessment.Differences == nil {
		r.Assessment.Differences = []integrity.Difference{}
	}
	if r.Assessment.Gaps == nil {
		r.Assessment.Gaps = []integrity.Gap{}
	}
	if r.Assessment.Contexts == nil {
		r.Assessment.Contexts = []integrity.ScopedContext{}
	}
	data, _ := json.Marshal(struct {
		Index      int
		Lock       integrity.BindingClaim
		Assessment integrity.InstanceAssessment
		Entries    int
	}{r.Index, r.Lock, r.Assessment, r.ObservedEntries})
	return sha256.Sum256(data)
}

func integrityOwner(ref Reference, idx policyEvidenceInventory) (projectinventory.Observation, projectinventory.Evidence, bool) {
	rows := idx.installed[ref.Location]
	if len(rows) != 1 {
		return projectinventory.Observation{}, projectinventory.Evidence{}, false
	}
	o := rows[0]
	m, ok := idx.observationReceipt(ProjectEvidence{}, o)
	if !ok || o.Kind != "directory" || o.Name != ref.Name || o.Version != ref.Version || m.PhysicalTarget != ref.Location {
		return o, projectinventory.Evidence{}, false
	}
	mid, err := strconv.ParseUint(o.Fields["metadata-evidence"], 10, 32)
	return o, idx.evidence[uint32(mid)], err == nil
}

func qualifiedIntegrityOwners(plan Plan, idx policyEvidenceInventory) map[string]bool {
	owners := map[string]bool{}
	for _, ref := range plan.Policy.References {
		if _, _, ok := integrityOwner(ref, idx); ok {
			owners[ref.Location] = true
		}
	}
	return owners
}

func emitIntegrityScopeWitness(plan Plan, policyHash string, idx policyEvidenceInventory, r *Record, catalog integrity.ReferenceCatalog, installed integrity.InstalledSnapshot) {
	ref := plan.Policy.References[r.Index]
	o, directory, ok := integrityOwner(ref, idx)
	if !ok {
		return
	}
	var own integrity.InstalledEntry
	for _, entry := range installed.Entries {
		if entry.Name == "package.json" {
			if own.EvidenceID != "" {
				return
			}
			own = entry
		}
	}
	manifest := idx.evidence[o.Source]
	if own.Status != integrity.ObservationComplete || own.Type != integrity.EntryFile || own.SHA256 != manifest.SHA256 {
		return
	}
	r.IntegrityScope = &IntegrityScopeWitness{Reference: ref, Observation: o.ID, Manifest: manifest, Directory: directory, ManifestEntry: own, Catalog: catalog.Receipt(), PolicySourceHash: policyHash, Comparison: comparisonDigest(*r)}
}

// ValidateIntegrityScopeReceipt checks the catalog's actual binding receipt
// against the parent-owned policy source, before retaining the worker record.
// Absence is an accounting gap, not permission to reconstruct a receipt.
func ValidateIntegrityScopeReceipt(plan Plan, r Record, policyHash string) bool {
	w := r.IntegrityScope
	if w == nil {
		return true
	}
	if r.Index < 0 || r.Index >= len(plan.Policy.References) || w.Reference != plan.Policy.References[r.Index] || w.PolicySourceHash != policyHash || !strongSRI(policyHash) || w.Comparison != comparisonDigest(r) {
		return false
	}
	b, gaps := integrity.ResolveReferenceBinding(Binding(plan, r.Index, r.Lock, policyHash))
	return len(gaps) == 0 && integrity.ValidateReferenceCatalogReceipt(b, w.Catalog)
}

func validIntegrityScope(plan Plan, r Record, inv projectinventory.PublicInventory, claims map[string]integrity.BindingClaim) bool {
	w := r.IntegrityScope
	if w == nil || w.Observation == 0 || int(w.Observation) > len(inv.Observations) || r.Index < 0 || r.Index >= len(plan.Policy.References) || w.Reference != plan.Policy.References[r.Index] || w.Comparison != comparisonDigest(r) {
		return false
	}
	ref := w.Reference
	// The observed digest comes from the verified archive, not the policy claim
	// echoed as a boolean. Multi-token policies need only one selected digest.
	if !ValidateIntegrityScopeReceipt(plan, r, w.PolicySourceHash) {
		return false
	}
	original := inv.OriginalClaims
	if original == nil || int(w.Observation) > len(original.Model.Observations) {
		return false
	}
	o := original.Model.Observations[w.Observation-1]
	po := inv.Observations[w.Observation-1]
	if o.Class != "installed" || o.Kind != "directory" || o.Status != "complete" || o.Workspace != 1 || o.Location != ref.Location || o.Fields["physical-target"] != ref.Location || o.Name != ref.Name || o.Version != ref.Version || po.MetadataEvidence == 0 || o.Source == 0 {
		return false
	}
	if w.Manifest != original.Model.Evidence[o.Source-1] || w.Directory != original.Model.Evidence[po.MetadataEvidence-1] {
		return false
	}
	own := w.ManifestEntry
	if own.Name != "package.json" || own.Type != integrity.EntryFile || own.Status != integrity.ObservationComplete || own.InstanceID != instanceID(r.Index) || own.OwnerInstanceID != own.InstanceID || own.Size < 0 || own.SHA256 != w.Manifest.SHA256 {
		return false
	}
	rawSize := int64(-1)
	for _, input := range original.OriginalInputs {
		if input.Source == o.Source {
			rawSize = int64(len(input.Bytes))
		}
	}
	if own.Size != rawSize {
		return false
	}
	joined := false
	for _, d := range r.Assessment.Differences {
		if d.EvidenceID == own.EvidenceID {
			joined = true
		}
	}
	if !joined {
		return false
	}
	if !w.Manifest.Complete || !w.Directory.Complete || w.Manifest.Method != "native-input-lease" || w.Manifest.Location != ref.Location+"/package.json" || w.Directory.Method != "native-metadata-lease" || w.Directory.Location != ref.Location {
		return false
	}
	return claims[ref.LockKey] == r.Lock
}

func wholeIntegrityComplete(plan Plan, records []Record, inv *projectinventory.PublicInventory) bool {
	if inv == nil || !operationalInventoryComplete(inv) || projectinventory.ValidateOriginalClaims(*inv) != nil || inv.Selection.Family != "npm" && inv.Selection.Family != "bun" {
		return false
	}
	if len(inv.Scopes) != 1 || len(records) != len(plan.Policy.References) {
		return false
	}
	for _, e := range inv.Evidence {
		if e.Method == "unreferenced-store-metadata" {
			return false
		}
	}
	// A positively closed empty inventory is distinct from missing evidence. A
	// requested reference for an absent instance still fails the exact join below.
	if len(records) > 0 && !referenceComparisonsComplete(plan, records) {
		return false
	}
	claims := lockedFromInventory(*inv.OriginalClaims).claims
	accounted := map[uint32]bool{}
	locations := map[string]bool{}
	for _, r := range records {
		if !validIntegrityScope(plan, r, *inv, claims) || accounted[r.IntegrityScope.Observation] || locations[r.IntegrityScope.Reference.Location] {
			return false
		}
		accounted[r.IntegrityScope.Observation] = true
		locations[r.IntegrityScope.Reference.Location] = true
	}
	for _, o := range inv.Observations {
		if o.Class == "installed" && !accounted[o.ID] {
			return false
		}
	}
	return true
}
