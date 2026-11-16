package projectinventory

import (
	"encoding/json"

	"packtrace/internal/inventory"
)

// BunMatchingContext must be called while the original selected Bun document and
// tuple INFO still exist, before projection drops unknown context. It grants no
// origin authority. Absence of this witness must remain unqualified in matching.
func BunMatchingContext(doc inventory.BunLockDocument, tuple inventory.BunLockedRecord) string {
	for key := range doc.Fields {
		if !allowed(key, "lockfileVersion", "configVersion", "workspaces", "packages") {
			return "unsupported"
		}
	}
	if len(doc.Workspaces) != 1 || doc.Workspaces[""] == nil {
		return "unsupported"
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(doc.Workspaces[""], &root) != nil || root == nil {
		return "unsupported"
	}
	for key := range root {
		if !allowed(key, "name", "version", "dependencies", "devDependencies", "optionalDependencies") {
			return "unsupported"
		}
	}
	if tuple.Kind != inventory.BunKindNPM || tuple.Info == nil {
		return "unsupported"
	}
	var info map[string]json.RawMessage
	if json.Unmarshal(tuple.Info, &info) != nil || info == nil {
		return "unsupported"
	}
	for key := range info {
		if !allowed(key, "dependencies", "devDependencies", "optionalDependencies") {
			return "unsupported"
		}
	}
	return "supported"
}
