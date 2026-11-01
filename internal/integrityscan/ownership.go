package integrityscan

import (
	"path"
	"strings"

	"packtrace/internal/integrity"
)

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
