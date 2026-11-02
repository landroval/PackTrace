package projectinventory

import (
	"sort"
	"strconv"

	"packtrace/internal/inventory"
)

// Reconcile appends evidence-labelled correspondences without rewriting a
// declaration, lock claim or physical instance. No source is authenticated here.
func Reconcile(m Model) Model {
	m.Relations = append([]Relation(nil), m.Relations...)
	byLocation := map[string][]Observation{}
	byIdentity := map[string][]Observation{}
	type requirementKey struct {
		scope       uint32
		group, name string
	}
	type requirementReceipt struct {
		id, source uint32
		claim      inventory.DeclaredDependency
	}
	requirements := map[requirementKey][]requirementReceipt{}
	evidence := map[uint32]Evidence{}
	scopeLocations := map[uint32]string{}
	for _, s := range m.Scopes {
		scopeLocations[s.ID] = s.Location
	}
	var enumeration uint32
	for _, e := range m.Evidence {
		evidence[e.ID] = e
		if e.Method == "native-metadata" && e.Complete {
			enumeration = e.ID
		}
	}
	for _, o := range m.Observations {
		if o.Class == "installed" {
			byLocation[o.Location] = append(byLocation[o.Location], o)
			if o.Name != "" && o.Version != "" {
				key := o.Name + "\x00" + o.Version
				byIdentity[key] = append(byIdentity[key], o)
			}
		}
		if location, known := scopeLocations[o.Workspace]; known && o.Location == location && o.Class == "locked" && (o.Kind == "project" || o.Kind == "workspace") {
			for _, g := range o.Requirements {
				for _, d := range g.Entries {
					key := requirementKey{o.Workspace, g.Name, d.Name}
					requirements[key] = append(requirements[key], requirementReceipt{o.ID, o.Source, d})
				}
			}
		}
	}
	seen := map[Relation]bool{}
	for _, r := range m.Relations {
		seen[r] = true
	}
	limited := false
	for _, g := range m.Gaps {
		limited = limited || g.Code == "relation-limit"
	}
	add := func(r Relation) bool {
		if seen[r] {
			return true
		}
		if len(m.Relations) >= maxRecords {
			if !limited && len(m.Gaps) < 256 {
				m.Gaps = append(m.Gaps, Gap{Code: "relation-limit"})
				limited = true
			}
			return false
		}
		seen[r] = true
		m.Relations = append(m.Relations, r)
		return true
	}
	for _, o := range m.Observations {
		switch o.Class {
		case "declared":
			for _, r := range requirements[requirementKey{o.Workspace, o.Kind, o.Name}] {
				status := "indeterminate"
				if r.claim.State == inventory.FieldValue && o.Fields["requirement-state"] == "value" {
					status = "conflict"
					if r.claim.Requirement == o.Requirement {
						status = "recorded-agreement"
					}
				}
				if !add(Relation{From: o.ID, To: r.id, Evidence: r.source, Kind: "declared-requirement", Status: status}) {
					break
				}
			}
		case "locked":
			if _, tuple := o.Fields["tuple-key"]; tuple {
				if o.Name != "" && o.Version != "" {
					for _, i := range byIdentity[o.Name+"\x00"+o.Version] {
						if !add(Relation{From: o.ID, To: i.ID, Evidence: i.Source, Kind: "candidate-correspondence", Status: "indeterminate"}) {
							break
						}
					}
				}
				continue
			}
			if o.Location == "" || o.Kind == "workspace" {
				continue
			}
			installed := byLocation[o.Location]
			if len(installed) == 0 {
				if enumeration != 0 {
					add(Relation{From: o.ID, Evidence: enumeration, Kind: "locked-correspondence", Status: "not-observed"})
				}
				continue
			}
			for _, i := range installed {
				status := "indeterminate"
				if o.Name != "" && i.Name != "" && o.Version != "" && i.Version != "" && i.Status == "complete" {
					status = "conflict"
					if o.Name == i.Name && o.Version == i.Version {
						status = "claim-agreement"
					}
				}
				if !add(Relation{From: o.ID, To: i.ID, Evidence: i.Source, Kind: "locked-correspondence", Status: status}) {
					break
				}
			}
		case "installed":
			if o.Kind == "link" && o.Status == "complete" && o.Fields["physical-target"] != "" {
				n, e := strconv.ParseUint(o.Fields["metadata-evidence"], 10, 32)
				if e == nil && evidence[uint32(n)].Complete && evidence[o.Source].Complete {
					add(Relation{From: o.ID, To: o.Source, Evidence: uint32(n), Kind: "physical-link", Status: "contained"})
				}
			}
		}
	}
	sort.Slice(m.Relations, func(i, j int) bool {
		a, b := m.Relations[i], m.Relations[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.Evidence != b.Evidence {
			return a.Evidence < b.Evidence
		}
		return a.Status < b.Status
	})
	return m
}
