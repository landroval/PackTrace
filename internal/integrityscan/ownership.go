package integrityscan

import (
	"path"
	"strings"

	"packtrace/internal/integrity"
)

// publishedContentScopes supplies traversal candidates, not installed ownership
// or equality. An authenticated published file permits observing its exact
// ancestor namespace, but the package-shaped boundary remains ownership-ambiguous
// even for identical manifestless bytes. Native acquisition captures and stably
// reads the subtree, including extras; deeper unpublished boundaries stay unknown.
// Separately mapped or locked owners are never folded into the parent.
// Empty directories alone supply no content proof.
func publishedContentScopes(plan Plan, index int, locked lockedInputs, installed policyEvidenceInventory, catalog integrity.ReferenceCatalog) map[string]bool {
	result := map[string]bool{}
	prefix := plan.Policy.References[index].Location + "/"
	for _, entry := range catalog.Entries() {
		if entry.Type != integrity.EntryFile {
			continue
		}
		for dir := path.Dir(entry.Name); dir != "." && dir != ""; dir = path.Dir(dir) {
			name := prefix + dir
			if packageLocation(name) && !mappedLocation(plan, name) && !locked.locations[name] && len(installed.installed[name]) == 0 {
				if _, separate := locked.claims[name]; !separate {
					result[name] = true
				}
			}
		}
	}
	return result
}

// publishedBundles qualifies only the containing archive's published namespace,
// not general producer compatibility or a nested package's independent origin.
// Literal lock metadata and a fully validated reference must agree. An explicit
// separately mapped instance always wins; unknown nested content remains unread.
func publishedBundles(plan Plan, index int, locked lockedInputs, catalog integrity.ReferenceCatalog) map[string]bool {
	prefix := plan.Policy.References[index].Location + "/"
	candidates := map[string]string{}
	for name, bundled := range locked.bundled {
		if bundled && strings.HasPrefix(name, prefix) && !mappedLocation(plan, name) {
			candidates[strings.TrimPrefix(name, prefix)] = name
		}
	}
	result := map[string]bool{}
	if len(candidates) == 0 {
		return result
	}
	for _, entry := range catalog.Entries() {
		dir := entry.Name
		if entry.Type != integrity.EntryDirectory {
			dir = path.Dir(dir)
		}
		for dir != "." && dir != "" {
			if name := candidates[dir]; name != "" {
				result[name] = true
			}
			dir = path.Dir(dir)
		}
	}
	return result
}
