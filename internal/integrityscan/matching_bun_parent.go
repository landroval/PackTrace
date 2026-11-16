package integrityscan

import "packtrace/internal/projectinventory"

// Recompute the join from acquisition, never from the decision's rule number or
// the exception material's identity. The original inventory retains conflicts,
// requirements, tuple context, selected-lock and own-manifest/native receipts.
func boundBunDecision(p Plan, inv projectinventory.PublicInventory, d AdvisoryDecision) bool {
	if projectinventory.ValidateOriginalClaims(inv) != nil {
		return false
	}
	want, ok := indexedBunMatchingOrigins(p, *inv.OriginalClaims)[d.Observation]
	return ok && want.Rule == d.Rule && want.Origin == d.Origin && want.LockedObservation == d.LockedObservation
}

func boundBunMaterial(p Plan, inv projectinventory.PublicInventory, m PolicyMaterial, d AdvisoryDecision) bool {
	if !boundBunDecision(p, inv, d) {
		return false
	}
	original := *inv.OriginalClaims
	project, ok := BuildProjectEvidence(original)
	if !ok || project != m.Project || m.LockSourceSHA256 != project.LockSHA256 {
		return false
	}
	idx := indexPolicyInventory(original)
	o, ok := idx.observations[m.Observation]
	if !ok {
		return false
	}
	receipt, ok := idx.observationReceipt(project, o)
	if !ok || receipt.SourceSHA256 != m.SourceSHA256 || receipt.PhysicalTarget != m.PhysicalTarget || receipt.DirectoryKind != m.DirectoryKind || receipt.LinkSHA256 != m.LinkSHA256 || receipt.Scope.Class != m.Scope.Class || receipt.Scope.Package != m.Scope.Package || receipt.Scope.Version != m.Scope.Version || receipt.Scope.Instance != m.Scope.Instance {
		return false
	}
	locked := o
	if d.LockedObservation != 0 {
		locked = idx.observations[d.LockedObservation]
	}
	return locked.Fields["tuple-key"] == m.BunTupleKey && locked.Origin == m.BunRegistry
}
