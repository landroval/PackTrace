package inventory

import (
	"maps"
	"slices"
)

// BunWorkspaceRecord retains declarations recorded in a lockfile workspace.
// Location and scalar claims are opaque, not safe paths or installed attribution.
type BunWorkspaceRecord struct {
	Location      string
	Name, Version LockField[string]
	Requirements  []DependencyGroup
}

// BunWorkspaceProjection links owned typed claims to original Bun input bytes.
// Unknown/unsupported raw evidence remains in the caller-retained document.
type BunWorkspaceProjection struct {
	SourceSHA256 [32]byte
	Records      []BunWorkspaceRecord
}

// ProjectBunWorkspaces requires an unchanged successful ParseBunLock result and no
// concurrent mutation. Basic guards do not authenticate a forged document. The
// two allowances bound metadata work, not RSS, paths, producer support or coverage.
// Successful sensitive evidence is internal data, not public-log/report/IPC output.
func ProjectBunWorkspaces(doc BunLockDocument) (BunWorkspaceProjection, error) {
	if doc.Fields == nil || doc.Workspaces == nil {
		return BunWorkspaceProjection{}, &ParseError{Code: "invalid-shape"}
	}
	if len(doc.Workspaces) > maxProjectedRecords {
		return BunWorkspaceProjection{}, &ParseError{Code: "limit-exceeded"}
	}
	records := make([]BunWorkspaceRecord, 0, len(doc.Workspaces))
	remaining := maxLockedRequirements
	for _, location := range slices.Sorted(maps.Keys(doc.Workspaces)) {
		fields, err := rawObjectMembers(doc.Workspaces[location])
		if err != nil {
			return BunWorkspaceProjection{}, err
		}
		groups, used, err := projectDependencyGroups(fields, remaining)
		if err != nil {
			return BunWorkspaceProjection{}, err
		}
		remaining -= used
		records = append(records, BunWorkspaceRecord{
			Location:     location,
			Name:         projectField[string](fields, "name"),
			Version:      projectField[string](fields, "version"),
			Requirements: groups,
		})
	}
	return BunWorkspaceProjection{SourceSHA256: doc.SHA256, Records: records}, nil
}
