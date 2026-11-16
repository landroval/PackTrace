package integrityscan

import (
	"strconv"
	"strings"

	"packtrace/internal/intel"
	lockinventory "packtrace/internal/inventory"
	"packtrace/internal/projectinventory"
)

// A Bun rule binds exactly one locked tuple and at most one installed endpoint,
// even when several original advisories produce decisions for that endpoint.
func bunDecisionMultiplicity(rows []AdvisoryDecision) bool {
	if len(rows) > maxMatchingDecisions {
		return false
	}
	lockedRules := map[uint32]int{}
	rules := map[int]uint32{}
	installed := map[uint32]uint32{}
	for _, d := range rows {
		if d.Origin != "operator-bun-rule" {
			continue
		}
		locked := d.Observation
		if d.LockedObservation != 0 {
			locked = d.LockedObservation
		}
		if d.Rule < 1 || locked == 0 || rules[d.Rule] != 0 && rules[d.Rule] != locked || lockedRules[locked] != 0 && lockedRules[locked] != d.Rule {
			return false
		}
		rules[d.Rule], lockedRules[locked] = locked, d.Rule
		if d.LockedObservation != 0 {
			if installed[locked] != 0 && installed[locked] != d.Observation {
				return false
			}
			installed[locked] = d.Observation
		}
	}
	return true
}

// Shared own-manifest + directory evidence checks; metadata is not content proof.
func matchingInstalledWitness(o projectinventory.Observation, evidence map[uint32]projectinventory.Evidence) bool {
	_, err := intel.ParseSemVer(o.Version)
	mid, metaErr := strconv.ParseUint(o.Fields["metadata-evidence"], 10, 32)
	manifest, metadata := evidence[o.Source], evidence[uint32(mid)]
	return err == nil && metaErr == nil && manifest.Complete && manifest.Method == "native-input-lease" && manifest.Location == o.Location+"/package.json" && metadata.Complete && metadata.Method == "native-metadata-lease" && metadata.Location == o.Location && manifest.Scope == o.Workspace && metadata.Scope == o.Workspace
}

func indexedBunMatchingOrigins(plan Plan, inv projectinventory.Result) map[uint32]AdvisoryDecision {
	out := map[uint32]AdvisoryDecision{}
	if ValidatePolicy(plan.Policy) != nil || plan.Manager != plan.Policy.Manager || !supportedPolicyPin(plan.TrustedPolicyDigest) || inv.Selection.Family != "bun" || inv.Selection.Profile != plan.Manager || inv.Selection.State != "usable" || len(plan.Policy.BunOrigins) == 0 {
		return out
	}
	project, ok := BuildProjectEvidence(inv)
	if !ok {
		return out
	}
	// No workspace/context inference. Incomplete discovery/requirements cannot
	// hide a conflicting alias or tuple. Unrelated installed read gaps stay local.
	for _, s := range inv.Model.Scopes {
		if s.ID != 1 {
			return out
		}
	}
	for _, g := range inv.Model.Gaps {
		if oneOf(g.Code, "discovery-incomplete", "path-collision", "name-limit", "record-limit", "requirement-limit", "gap-list-truncated", "variant-invalid", "declaration-invalid", "declaration-group-invalid", "locked-requirements-invalid", "locked-requirement-invalid", "relation-limit", "locked-projection-invalid", "lock-invalid", "lock-unreadable") {
			return out
		}
	}
	evidence := map[uint32]projectinventory.Evidence{}
	for _, e := range inv.Model.Evidence {
		evidence[e.ID] = e
	}
	bad := map[string]bool{}
	counts := map[string]int{}
	for _, o := range inv.Model.Observations {
		if o.Workspace != 1 || o.Class == "locked" && o.Kind == "workspace" && o.Location != "" {
			return out
		}
		if o.Class == "locked" && o.Kind != "workspace" {
			counts[o.Name]++
		}
		if o.Class == "declared" {
			if o.Fields["requirement-state"] != "value" || strings.ContainsAny(o.Requirement, ":/@") {
				return out
			}
			if o.Kind == "peerDependencies" {
				bad[o.Name] = true
			}
		}
		for _, g := range o.Requirements {
			if g.State != lockinventory.FieldValue && g.State != lockinventory.FieldAbsent {
				return out
			}
			if g.Name == "peerDependencies" && len(g.Entries) != 0 {
				bad[o.Name] = true
			}
			for _, r := range g.Entries {
				if r.State != lockinventory.FieldValue || strings.ContainsAny(r.Requirement, ":/@") {
					return out
				}
				if g.Name == "peerDependencies" {
					bad[r.Name] = true
				}
			}
		}
	}
	for _, o := range inv.Model.Observations {
		e := evidence[o.Source]
		if o.Source != project.Lock || o.Class != "locked" || o.Kind != "package" || o.Status != "complete" || counts[o.Name] != 1 || bad[o.Name] || o.Location != o.Name || o.Fields["tuple-key"] != o.Name || o.Fields["matching-context"] != "supported" || o.Fields["name-state"] != "value" || o.Fields["resolution-state"] != "value" || o.Fields["registry-state"] != "value" || o.Fields["integrity-state"] != "value" || !strongSRI(o.Fields["integrity"]) || !e.Complete || e.Scope != 1 || e.Method != "native-input-lease" || e.Location != inv.Selection.File {
			continue
		}
		// INFO context is deliberately excluded, not interpreted as a grant.
		context := false
		for k, v := range o.Fields {
			if !oneOf(k, "tuple-key", "name-state", "resolution-state", "registry-state", "integrity-state", "integrity", "git-tag", "matching-context") || k == "git-tag" && v != "" {
				context = true
			}
		}
		if context {
			continue
		}
		for i, r := range plan.Policy.BunOrigins {
			if r.Location == o.Location && r.Name == o.Name && r.Version == o.Version && r.Registry == o.Origin {
				out[o.ID] = AdvisoryDecision{Rule: i + 1, Origin: "operator-bun-rule"}
				break
			}
		}
	}
	relations := map[uint32][]projectinventory.Relation{}
	outgoing := map[uint32]int{}
	for _, r := range inv.Model.Relations {
		if oneOf(r.Kind, "candidate-correspondence", "locked-correspondence") {
			relations[r.To] = append(relations[r.To], r)
			outgoing[r.From]++
		}
	}
	for _, o := range inv.Model.Observations {
		if o.Class != "installed" || o.Kind != "directory" || o.Status != "complete" || bad[o.Name] || o.Location != "node_modules/"+o.Name || o.Fields["installation-name"] != o.Name || o.Fields["physical-target"] != o.Location || o.Fields["name-state"] != "value" || o.Fields["version-state"] != "value" || !matchingInstalledWitness(o, evidence) {
			continue
		}
		rs := relations[o.ID]
		if len(rs) != 1 {
			continue
		}
		relation := rs[0]
		if relation.Kind != "candidate-correspondence" || relation.Status != "indeterminate" || relation.Evidence != o.Source {
			continue
		}
		d, ok := out[relation.From]
		if !ok {
			continue
		}
		r := plan.Policy.BunOrigins[d.Rule-1]
		if r.Name != o.Name || r.Version != o.Version {
			continue
		}
		if outgoing[relation.From] != 1 {
			continue
		}
		d.LockedObservation = relation.From
		out[o.ID] = d
	}
	return out
}
