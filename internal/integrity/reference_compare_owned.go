package integrity

import "strings"

// CompareReferenceCatalogOwned separates captured nested directory owners from
// the current instance. Historical supplied-scope comparison keeps its negative
// ownership semantics. Published content overlapping another owner is still a
// gap, not an exclusion. Callers must account for every excluded owner separately.
func CompareReferenceCatalogOwned(b ReferenceBinding, c ReferenceCatalog, s InstalledSnapshot) (InstanceAssessment, error) {
	var prefixes []string
	for _, scope := range s.Scopes {
		if scope.InstanceID != b.instanceID || scope.OwnerInstanceID == "" || scope.OwnerInstanceID == b.instanceID || !scope.OwnershipKnown || !scope.Enumerated || scope.Status != ObservationComplete || !qualifiedInstalledName(scope.Prefix) {
			continue
		}
		overlap := false
		for _, e := range c.entries {
			if e.Name == scope.Prefix || strings.HasPrefix(e.Name, scope.Prefix+"/") {
				overlap = true
				break
			}
		}
		if !overlap {
			prefixes = append(prefixes, scope.Prefix)
		}
	}
	excluded := func(name string) bool {
		for _, p := range prefixes {
			if name == p || strings.HasPrefix(name, p+"/") {
				return true
			}
		}
		return false
	}
	filtered := InstalledSnapshot{}
	for _, scope := range s.Scopes {
		if !excluded(scope.Prefix) {
			filtered.Scopes = append(filtered.Scopes, scope)
		}
	}
	for _, e := range s.Entries {
		if excluded(e.Name) {
			continue
		}
		// Empty package-manager namespace directories are not published content, but
		// a regular file at that same spelling must never disappear.
		namespace := false
		if e.Type == EntryDirectory && e.Status == ObservationComplete {
			for _, p := range prefixes {
				if strings.HasPrefix(p, e.Name+"/") {
					namespace = true
				}
			}
			if namespace {
				for _, r := range c.entries {
					if r.Name == e.Name || strings.HasPrefix(r.Name, e.Name+"/") {
						namespace = false
					}
				}
				for _, o := range s.Entries {
					if o.Type != EntryDirectory && strings.HasPrefix(o.Name, e.Name+"/") && !excluded(o.Name) {
						namespace = false
					}
				}
			}
		}
		if !namespace {
			filtered.Entries = append(filtered.Entries, e)
		}
	}
	return CompareReferenceCatalog(b, c, filtered)
}
