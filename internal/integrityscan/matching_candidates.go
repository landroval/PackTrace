package integrityscan

import (
	"strconv"
	"strings"

	"packtrace/internal/intel"
	lockinventory "packtrace/internal/inventory"
	"packtrace/internal/managerprofile"
	"packtrace/internal/projectinventory"
)

// This grants local index investigation only, never trust in a package's origin.
func candidateLookupPermission(plan Plan) bool {
	return plan.Policy.AdvisoryCandidates && ValidatePolicy(plan.Policy) == nil &&
		plan.Manager == plan.Policy.Manager && (strings.HasPrefix(plan.Manager, "npm@") || managerprofile.SupportsBun(plan.Manager)) &&
		supportedPolicyPin(plan.TrustedPolicyDigest)
}

func activeAdvisoryCandidate(d AdvisoryDecision) bool {
	return d.Origin == "unqualified" && d.Advisory > 0 && d.Affected >= 0 &&
		d.Category != "unknown" && d.Profile != "unknown" && d.Source == "qualified" &&
		d.Activity == "not-withdrawn" && d.VersionOutcome == "match"
}

// Raw qualification uses recorded identities, not selectors, alias resolution
// strings, or a lock-to-install correspondence. Every physical copy keeps its
// own endpoint and shares only the existing name/version evaluation templates.
func indexedMatchingCandidates(plan Plan, inv projectinventory.Result) map[uint32]bool {
	out := map[uint32]bool{}
	if !candidateLookupPermission(plan) || !oneOf(inv.Selection.Family, "npm", "bun") || inv.Selection.Family != strings.Split(plan.Manager, "@")[0] || inv.Selection.Profile != plan.Manager {
		return out
	}
	evidence := map[uint32]projectinventory.Evidence{}
	badSource := map[uint32]bool{}
	aliases := map[uint32]map[string]bool{}
	for _, e := range inv.Model.Evidence {
		evidence[e.ID] = e
	}
	for _, gap := range inv.Model.Gaps {
		if gap.Code == "requirement-limit" || gap.Code == "gap-list-truncated" {
			badSource[gap.Evidence] = true
		}
	}
	for _, o := range inv.Model.Observations {
		if o.Class != "locked" {
			continue
		}
		for _, group := range o.Requirements {
			if group.State != lockinventory.FieldValue && group.State != lockinventory.FieldAbsent {
				badSource[o.Source] = true
			}
			for _, entry := range group.Entries {
				if entry.State != lockinventory.FieldValue || strings.HasPrefix(strings.TrimSpace(entry.Requirement), "npm:") {
					if aliases[o.Source] == nil {
						aliases[o.Source] = map[string]bool{}
					}
					aliases[o.Source][entry.Name] = true
				}
			}
		}
	}
	for _, o := range inv.Model.Observations {
		versionField := "version-state"
		if inv.Selection.Family == "bun" && o.Class == "locked" {
			versionField = "resolution-state"
		}
		if o.Status != "complete" || !canonicalNPMName(o.Name) || o.Fields[versionField] != "value" {
			continue
		}
		if _, err := intel.ParseSemVer(o.Version); err != nil {
			continue
		}
		e := evidence[o.Source]
		if !e.Complete || e.Method != "native-input-lease" {
			continue
		}
		switch o.Class {
		case "locked":
			if inv.Selection.State != "usable" || e.Location != inv.Selection.File || e.Scope != 1 || badSource[0] || badSource[o.Source] || aliases[o.Source][o.Name] {
				continue
			}
			if inv.Selection.Family == "bun" {
				if o.Kind != "package" || o.Fields["name-state"] != "value" || o.Fields["registry-state"] != "value" || o.Fields["tuple-key"] != o.Location {
					continue
				}
			} else if !oneOf(o.Kind, "url", "package") || !oneOf(o.Fields["name-qualification"], "explicit-claim", "installation-claim") || o.Fields["installation-name"] != o.Name {
				continue
			}
			if link, exists := o.Fields["link"]; exists && link != "false" {
				continue
			}
			// Even a forged generic kind must not promote literal non-registry claims.
			if o.Origin != "" && !strings.HasPrefix(o.Origin, "http:") && !strings.HasPrefix(o.Origin, "https:") {
				continue
			}
			out[o.ID] = true
		case "installed":
			if o.Kind != "directory" || o.Fields["name-state"] != "value" || o.Fields["physical-target"] != o.Location || e.Location != o.Location+"/package.json" || e.Scope != o.Workspace {
				continue
			}
			id, err := strconv.ParseUint(o.Fields["metadata-evidence"], 10, 32)
			metadata := evidence[uint32(id)]
			if err == nil && metadata.Complete && metadata.Method == "native-metadata-lease" && metadata.Location == o.Location && metadata.Scope == o.Workspace {
				out[o.ID] = true
			}
		}
	}
	return out
}

// The parent checks transmitted structural witnesses, not redacted names or
// URLs. Base unassessed rows retain their historical endpoint requirements.
func publicCandidateEndpoint(inv projectinventory.PublicInventory, o projectinventory.PublicObservation) bool {
	if !oneOf(inv.Selection.Family, "npm", "bun") || o.Status != "complete" || o.Source == 0 || int(o.Source) > len(inv.Evidence) {
		return false
	}
	e := inv.Evidence[o.Source-1]
	if e.Status != "complete" || e.Method != "native-input-lease" {
		return false
	}
	switch o.Class {
	case "locked":
		if inv.Selection.Evidence == 0 || o.Source != inv.Selection.Evidence {
			return false
		}
		for _, gap := range inv.Gaps {
			if oneOf(gap.Code, "requirement-limit", "gap-list-truncated") && (gap.Evidence == 0 || gap.Evidence == o.Source) {
				return false
			}
		}
		return oneOf(o.Kind, "url", "package") && (inv.Selection.Family != "bun" || o.Kind == "package") && inv.Selection.State == "usable" && e.Scope == 1
	case "installed":
		if o.Kind != "directory" || e.Scope != o.Workspace || o.MetadataEvidence == 0 || int(o.MetadataEvidence) > len(inv.Evidence) {
			return false
		}
		metadata := inv.Evidence[o.MetadataEvidence-1]
		return e.MetadataEvidence == o.MetadataEvidence && metadata.Status == "complete" && metadata.Method == "native-metadata-lease" && metadata.Scope == o.Workspace
	}
	return false
}
