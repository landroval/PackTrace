package integrity

import (
	"errors"
	"strings"
)

const maxAssessmentGaps = 256

// appendGap keeps the diagnostic list finite; truncation itself denies complete coverage.
func appendGap(gaps []Gap, gap Gap) []Gap {
	if len(gaps) < maxAssessmentGaps-1 {
		return append(gaps, gap)
	}
	if len(gaps) == maxAssessmentGaps-1 {
		return append(gaps, Gap{Code: GapTruncated, InstanceID: gap.InstanceID})
	}
	return gaps
}

// CompareReferenceCatalog compares only caller-supplied, explicitly owned observations.
// It never establishes that a native filesystem was inspected.
func CompareReferenceCatalog(b ReferenceBinding, c ReferenceCatalog, s InstalledSnapshot) (InstanceAssessment, error) {
	if !b.usable || !c.verified || b.instanceID == "" || b.instanceID != c.instanceID || b.fingerprint != c.bindingFingerprint {
		return InstanceAssessment{}, errors.New("unusable reference")
	}
	id := b.instanceID
	a := InstanceAssessment{InstanceID: id, Assurance: b.assurance}
	reference := make(map[string]ReferenceEntry, len(c.entries))
	publishedParents := make(map[string]bool)
	for _, r := range c.entries {
		if r.Name == "" && r.Type == EntryDirectory {
			continue // package/ is the envelope, not an installed entry.
		}
		if !qualifiedInstalledName(r.Name) || r.EntryID == "" || (r.Type != EntryFile && r.Type != EntryDirectory) {
			a.Gaps = appendGap(a.Gaps, Gap{Code: GapUnsupported, InstanceID: id, EntryID: r.EntryID})
			continue
		}
		if _, ok := reference[r.Name]; ok {
			a.Gaps = appendGap(a.Gaps, Gap{Code: GapReference, InstanceID: id, EntryID: r.EntryID})
			continue
		}
		reference[r.Name] = r
		// USTAR permits omitted directory headers. Published descendants still
		// justify those directories; their presence is not an added-content drift.
		for p := parentName(r.Name); p != ""; p = parentName(p) {
			publishedParents[p] = true
		}
	}
	if len(a.Gaps) > 0 {
		return a, nil // No malformed/partial catalog authorizes comparison.
	}

	// Reconcile the entire supplied tree BEFORE producing differences. Negative
	// scopes and ambiguous prefixes veto every covering positive scope, in any order.
	blocked := make(map[string]bool)
	spellings := make(map[string]string)
	parents, files := make(map[string]bool), make(map[string]bool)
	gap := func(code GapCode, prefix, evidence string) {
		blocked[strings.ToLower(prefix)] = true
		a.Gaps = appendGap(a.Gaps, Gap{Code: code, InstanceID: id, EvidenceID: evidence})
	}
	register := func(name, evidence string, supplied, file bool) {
		for p := name; p != ""; p = parentName(p) {
			key := strings.ToLower(p)
			if old, ok := spellings[key]; ok && old != p {
				gap(GapObservation, p, evidence)
			}
			spellings[key] = p
			if supplied && p != name {
				parents[key] = true
				if files[key] {
					gap(GapObservation, p, evidence)
				}
			}
		}
		if supplied && file {
			key := strings.ToLower(name)
			files[key] = true
			if parents[key] {
				gap(GapObservation, name, evidence)
			}
		}
	}
	for _, r := range c.entries {
		register(r.Name, "", false, false)
	}
	observed := make(map[string]InstalledEntry, len(s.Entries))
	for _, o := range s.Entries {
		if o.InstanceID != id {
			continue
		}
		if !qualifiedInstalledName(o.Name) {
			a.Gaps = appendGap(a.Gaps, Gap{Code: GapUnsupported, InstanceID: id, EvidenceID: o.EvidenceID})
			continue
		}
		register(o.Name, o.EvidenceID, true, o.Type != EntryDirectory)
		if o.OwnerInstanceID != id {
			gap(GapOwnership, o.Name, o.EvidenceID)
		}
		if _, ok := observed[o.Name]; ok {
			gap(GapObservation, o.Name, o.EvidenceID)
		}
		observed[o.Name] = o
		if o.EvidenceID == "" || o.Status != ObservationComplete || (o.Type != EntryFile && o.Type != EntryDirectory && o.Type != EntryLink) || o.Size < 0 {
			gap(GapObservation, o.Name, o.EvidenceID)
		}
		if o.Type == EntryLink {
			a.Gaps = appendGap(a.Gaps, Gap{Code: GapUnsupported, InstanceID: id, EvidenceID: o.EvidenceID})
		}
	}
	coverage := make(map[string]string)
	for _, scope := range s.Scopes {
		if scope.InstanceID != id {
			continue
		}
		if contextLabel(scope.Context) != "" {
			a.Contexts = append(a.Contexts, ScopedContext{Kind: scope.Context, InstanceID: id, EvidenceID: scope.EvidenceID})
		}
		prefix := strings.TrimSuffix(scope.Prefix, "/")
		if scope.Prefix != "" && !qualifiedInstalledName(prefix) {
			gap(GapObservation, "", scope.EvidenceID)
			continue
		}
		register(prefix, scope.EvidenceID, true, false)
		if scope.OwnerInstanceID != id || !scope.OwnershipKnown {
			gap(GapOwnership, prefix, scope.EvidenceID)
			continue
		}
		if !scope.Enumerated || scope.Status != ObservationComplete || scope.EvidenceID == "" {
			gap(GapObservation, prefix, scope.EvidenceID)
			continue
		}
		// Deterministic evidence selection, never first-matching-scope authority.
		if old := coverage[prefix]; old == "" || scope.EvidenceID < old {
			coverage[prefix] = scope.EvidenceID
		}
	}
	isBlocked := func(name string) bool {
		for p := strings.ToLower(name); ; p = parentName(p) {
			if blocked[p] {
				return true
			}
			if p == "" {
				return false
			}
		}
	}
	coveredBy := func(name string) string {
		for p := name; ; p = parentName(p) {
			if evidence := coverage[p]; evidence != "" {
				return evidence
			}
			if p == "" {
				return ""
			}
		}
	}
	for _, r := range c.entries {
		if r.Name == "" || isBlocked(r.Name) {
			continue
		}
		if o, ok := observed[r.Name]; ok {
			kind := DifferenceUnchanged
			if o.Type != r.Type {
				kind = DifferenceTypeChanged
			} else if r.Type == EntryFile && (r.Size != o.Size || r.SHA256 != o.SHA256) {
				kind = DifferenceModified
			}
			a.Differences = append(a.Differences, Difference{Kind: kind, InstanceID: id, EntryID: r.EntryID, EvidenceID: o.EvidenceID})
		} else if evidence := coveredBy(r.Name); evidence != "" {
			a.Differences = append(a.Differences, Difference{Kind: DifferenceMissing, InstanceID: id, EntryID: r.EntryID, EvidenceID: evidence})
		} else {
			a.Gaps = appendGap(a.Gaps, Gap{Code: GapObservation, InstanceID: id, EntryID: r.EntryID})
		}
	}
	for _, o := range s.Entries {
		if o.InstanceID != id || !qualifiedInstalledName(o.Name) || isBlocked(o.Name) || o.Type == EntryLink {
			continue
		}
		if _, ok := reference[o.Name]; ok || o.Type == EntryDirectory && publishedParents[o.Name] {
			continue
		}
		if coveredBy(o.Name) == "" {
			a.Gaps = appendGap(a.Gaps, Gap{Code: GapObservation, InstanceID: id, EvidenceID: o.EvidenceID})
			continue
		}
		a.Differences = append(a.Differences, Difference{Kind: DifferenceAdded, InstanceID: id, EvidenceID: o.EvidenceID})
	}
	if coverage[""] == "" {
		a.Gaps = appendGap(a.Gaps, Gap{Code: GapObservation, InstanceID: id})
	}
	a.SuppliedComparisonComplete = len(a.Gaps) == 0
	return a, nil
}

func parentName(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[:i]
	}
	return ""
}
func qualifiedInstalledName(name string) bool {
	if name == "" {
		return false
	}
	l, _ := normalizedLimits(Limits{})
	_, ok := archiveName("package/"+name, false, l)
	return ok
}
