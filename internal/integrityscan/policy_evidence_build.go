package integrityscan

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"packtrace/internal/integrity"
	"packtrace/internal/projectinventory"
)

func policyEvidenceNeeded(plan Plan) bool {
	return plan.Privacy == "local" || len(plan.Policy.Exceptions) != 0
}

// BuildProjectEvidence uses original bytes already read through stable native
// leases. A complete lease is insufficient without qualified input semantics.
func BuildProjectEvidence(result projectinventory.Result) (ProjectEvidence, bool) {
	s := result.Selection
	if s.State != "usable" || !profile(s.Profile) || !oneOf(s.File, "package-lock.json", "npm-shrinkwrap.json", "bun.lock") || (strings.HasPrefix(s.Profile, "npm@") != (s.Family == "npm")) || (strings.HasPrefix(s.Profile, "npm@") != (s.File != "bun.lock")) || !oneOf(s.Family, "npm", "bun") {
		return ProjectEvidence{}, false
	}
	root := false
	for _, scope := range result.Model.Scopes {
		if scope.ID == 1 && scope.Parent == 0 && scope.Kind == "project" && scope.Location == "" {
			root = true
		}
	}
	if !root {
		return ProjectEvidence{}, false
	}
	p := ProjectEvidence{Scope: 1, Profile: s.Profile, LockFile: s.File}
	for _, e := range result.Model.Evidence {
		if e.Scope != 1 || e.Method != "native-input-lease" || !e.Complete || e.SHA256 == ([32]byte{}) {
			continue
		}
		switch e.Location {
		case "package.json":
			if p.Manifest != 0 {
				return ProjectEvidence{}, false
			}
			p.Manifest = e.ID
			p.ManifestSHA256 = hex.EncodeToString(e.SHA256[:])
		case s.File:
			if p.Lock != 0 {
				return ProjectEvidence{}, false
			}
			p.Lock = e.ID
			p.LockSHA256 = hex.EncodeToString(e.SHA256[:])
		}
	}
	if p.Manifest == 0 || p.Lock == 0 {
		return ProjectEvidence{}, false
	}
	// Reject semantic or discovery ambiguity affecting these inputs, not unrelated
	// installed coverage gaps. Whole selected-lock bytes remain the project scope.
	for _, g := range result.Model.Gaps {
		if g.Evidence == p.Manifest || g.Evidence == p.Lock || oneOf(g.Code, "discovery-incomplete", "path-collision", "name-limit", "gap-list-truncated", "selection-invalid", "selection-indeterminate") {
			return ProjectEvidence{}, false
		}
	}
	return p, true
}

type policyEvidenceInventory struct {
	evidence     map[uint32]projectinventory.Evidence
	observations map[uint32]projectinventory.Observation
	installed    map[string][]projectinventory.Observation
}

func indexPolicyInventory(inv projectinventory.Result) policyEvidenceInventory {
	idx := policyEvidenceInventory{map[uint32]projectinventory.Evidence{}, map[uint32]projectinventory.Observation{}, map[string][]projectinventory.Observation{}}
	for _, e := range inv.Model.Evidence {
		idx.evidence[e.ID] = e
	}
	for _, o := range inv.Model.Observations {
		idx.observations[o.ID] = o
		if o.Class == "installed" {
			idx.installed[o.Location] = append(idx.installed[o.Location], o)
		}
	}
	return idx
}
func (idx policyEvidenceInventory) observationReceipt(p ProjectEvidence, o projectinventory.Observation) (PolicyMaterial, bool) {
	e, ok := idx.evidence[o.Source]
	if !ok || !e.Complete || e.Method != "native-input-lease" || e.Scope != o.Workspace || !oneOf(o.Class, "locked", "installed") || o.Status != "complete" || !relative(o.Location) || !canonicalNPMName(strings.ToLower(o.Name)) || o.Version == "" {
		return PolicyMaterial{}, false
	}
	m := PolicyMaterial{Project: p, Observation: o.ID, SourceSHA256: hex.EncodeToString(e.SHA256[:]), LockSourceSHA256: p.LockSHA256, Profile: p.Profile}
	m.Scope = FindingScope{Project: ProjectFingerprint(p), Class: o.Class, Package: o.Name, Version: o.Version, Origin: o.Origin, Instance: o.Location}
	if o.Class == "locked" {
		if o.Source != p.Lock || e.Location != p.LockFile {
			return PolicyMaterial{}, false
		}
		return m, true
	}
	if e.Location != o.Location+"/package.json" {
		return PolicyMaterial{}, false
	}
	mid, err := strconv.ParseUint(o.Fields["metadata-evidence"], 10, 32)
	meta, exists := idx.evidence[uint32(mid)]
	if err != nil || !exists || !meta.Complete || meta.Method != "native-metadata-lease" || meta.Scope != o.Workspace || meta.Location != o.Location || !oneOf(o.Kind, "directory", "link") || !relative(o.Fields["physical-target"]) {
		return PolicyMaterial{}, false
	}
	m.PhysicalTarget = o.Fields["physical-target"]
	m.DirectoryKind = o.Kind // a typed physical witness, NEVER metadata's zero SHA256
	if o.Kind == "link" {
		target, exists := o.Fields["link-target"]
		if !exists {
			return PolicyMaterial{}, false
		}
		m.LinkSHA256 = linkObjectSHA256(target)
	}
	return m, true
}
func buildAdvisoryPolicyEvidence(p ProjectEvidence, idx policyEvidenceInventory, o projectinventory.Observation, d AdvisoryDecision, original LocalAdvisory) (PolicyMaterial, bool) {
	if !d.EnforcementEligible || d.Candidate || original.ID == "" || original.SHA256 == "" || original.Advisory != d.Advisory || d.Affected < 0 {
		return PolicyMaterial{}, false
	}
	m, ok := idx.observationReceipt(p, o)
	if !ok {
		return PolicyMaterial{}, false
	}
	if o.Class == "installed" {
		locked, exists := idx.observations[d.LockedObservation]
		if !exists || locked.Class != "locked" || locked.Source != p.Lock || locked.Name != o.Name || locked.Version != o.Version || locked.Location != o.Location {
			return PolicyMaterial{}, false
		}
		m.Scope.Origin = locked.Origin
	}
	m.Advisory = d.Advisory
	m.Affected = d.Affected
	m.OriginalSHA256 = original.SHA256
	m.Scope.Category = d.Category
	m.Scope.Rule = "osv-npm"
	m.Scope.Advisory = original.ID
	// The advisory profile is substantive matching interpretation, distinct from
	// the project lock parser profile already bound in ProjectEvidence.
	m.Profile = d.Profile
	return m, true
}

func linkObjectSHA256(target string) string {
	h := sha256.Sum256([]byte("packtrace:policy-link-object:v1\x00" + target))
	return hex.EncodeToString(h[:])
}
func policyEntryType(t integrity.EntryType) string {
	switch t {
	case integrity.EntryFile:
		return "file"
	case integrity.EntryDirectory:
		return "directory"
	case integrity.EntryLink:
		return "link"
	}
	return ""
}
func policySide(t integrity.EntryType, size int64, sum [32]byte, target string) (EvidenceSide, bool) {
	side := EvidenceSide{State: "present", Type: policyEntryType(t)}
	switch t {
	case integrity.EntryFile:
		if size < 0 {
			return EvidenceSide{}, false
		}
		side.Size = size
		side.SHA256 = hex.EncodeToString(sum[:])
	case integrity.EntryDirectory:
	case integrity.EntryLink:
		side.LinkSHA256 = linkObjectSHA256(target)
	default:
		return EvidenceSide{}, false
	}
	return side, true
}
func emitIntegrityPolicyEvidence(p ProjectEvidence, plan Plan, record *Record, idx policyEvidenceInventory, catalog integrity.ReferenceCatalog, installed integrity.InstalledSnapshot, emit PolicyEvidenceEmitter) error {
	record.PolicyObservation = 0
	record.PolicyWitnesses = nil
	record.PolicyMaterialLimited = false
	r := plan.Policy.References[record.Index]
	// Own installed manifest and specific physical directory witness are required,
	// not a hash fabricated from a metadata enumeration or parent directory.
	observations := idx.installed[r.Location]
	if len(observations) != 1 {
		return nil
	}
	o := observations[0]
	base, ok := idx.observationReceipt(p, o)
	if !ok || o.Name != r.Name || o.Version != r.Version || base.PhysicalTarget != r.Location {
		return nil
	}
	record.PolicyObservation = o.ID
	base.Scope.Origin = r.Origin
	base.Scope.Category = "integrity"
	base.Scope.Rule = "integrity-drift"
	base.Record = record.Index
	base.ReferenceSRI = r.ExpectedSRI
	base.ReferenceObservedSRI = catalog.ObservedSRI()
	base.ReferenceContext = r.Context
	switch record.Assessment.Assurance {
	case integrity.AssuranceIndependent:
		base.Assurance = "independently-anchored"
	case integrity.AssuranceLockfile:
		base.Assurance = "lockfile-consistent"
	default:
		return nil
	}
	if base.ReferenceObservedSRI == "" {
		return nil
	}
	expected := map[string]integrity.ReferenceEntry{}
	observed := map[string]integrity.InstalledEntry{}
	scopes := map[string]integrity.InstalledScope{}
	for _, e := range catalog.Entries() {
		expected[e.EntryID] = e
	}
	for _, e := range installed.Entries {
		observed[e.EvidenceID] = e
	}
	for _, s := range installed.Scopes {
		scopes[s.EvidenceID] = s
	}
	absent := EvidenceSide{State: "absent", Type: "none"}
	for i, d := range record.Assessment.Differences {
		m := base
		m.Difference = i
		m.ReferenceEntryID = d.EntryID
		m.ObservedEntryID = d.EvidenceID
		m.Expected = absent
		m.Observed = absent
		ref, refOK := expected[d.EntryID]
		obs, obsOK := observed[d.EvidenceID]
		switch d.Kind {
		case integrity.DifferenceModified:
			m.Scope.Change = "modified"
		case integrity.DifferenceMissing:
			m.Scope.Change = "missing"
		case integrity.DifferenceAdded:
			m.Scope.Change = "added"
		case integrity.DifferenceTypeChanged:
			m.Scope.Change = "type-changed"
		default:
			continue
		}
		if d.Kind != integrity.DifferenceAdded {
			if !refOK {
				continue
			}
			m.Scope.Path = ref.Name
			m.Expected, ok = policySide(ref.Type, ref.Size, ref.SHA256, "")
			if !ok {
				continue
			}
		}
		if d.Kind == integrity.DifferenceMissing {
			s, exists := scopes[d.EvidenceID]
			if !exists || !s.Enumerated || !s.OwnershipKnown || s.Status != integrity.ObservationComplete || s.OwnerInstanceID != record.Assessment.InstanceID {
				continue
			}
		} else {
			if !obsOK || obs.Status != integrity.ObservationComplete || obs.OwnerInstanceID != record.Assessment.InstanceID || refOK && obs.Name != ref.Name {
				continue
			}
			m.Scope.Path = obs.Name
			m.Observed, ok = policySide(obs.Type, obs.Size, obs.SHA256, obs.LinkTarget)
			if !ok {
				continue
			}
		}
		if !relative(m.Scope.Path) || ValidatePolicyMaterialShape(m) != nil {
			continue
		}
		if len(record.PolicyWitnesses) >= MaxPolicyMaterials {
			record.PolicyMaterialLimited = true
			break
		}
		record.PolicyWitnesses = append(record.PolicyWitnesses, PolicyDifferenceWitness{Difference: i, EntryID: d.EntryID, EvidenceID: d.EvidenceID, Fingerprint: PolicyDifferenceFingerprint(m)})
		if err := emit(m); err != nil {
			return err
		}
	}
	return nil
}
