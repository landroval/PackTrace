package projectinventory

import (
	"encoding/json"
	"sort"
	"strings"

	"packtrace/internal/inventory"
	"packtrace/internal/nativefs"
)

func cleanRelative(name string) bool {
	if name == "" || len(name) > 4096 || strings.ContainsAny(name, "\\\x00:") || strings.HasPrefix(name, "/") {
		return false
	}
	for _, p := range strings.Split(name, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}
func (c *collector) collectWorkspaces(doc *inventory.ManifestDocument) {
	if doc == nil {
		return
	}
	raw, ok := doc.Fields["workspaces"]
	if !ok {
		return
	}
	var patterns []string
	if json.Unmarshal(raw, &patterns) != nil || patterns == nil {
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil || json.Unmarshal(object["packages"], &patterns) != nil || patterns == nil {
			c.gap(1, 0, "workspace-declarations-invalid")
			return
		}
	}
	if len(patterns) > maxRecords {
		c.gap(1, 0, "workspace-limit")
		return
	}
	selected := map[string]int{}
	multiplicity := map[string]int{}
	for _, p := range patterns {
		multiplicity[p]++
	}
	orderedPatterns := make([]string, 0, len(multiplicity))
	for p := range multiplicity {
		orderedPatterns = append(orderedPatterns, p)
	}
	sort.Strings(orderedPatterns)
	for _, pattern := range orderedPatterns {
		count := multiplicity[pattern]
		if pattern == "packages/*" || pattern == "apps/*" {
			prefix := strings.TrimSuffix(pattern, "*")
			for name, e := range c.entries {
				if e.Kind == nativefs.KindDirectory && e.Status == nativefs.StatusComplete && strings.HasPrefix(name, prefix) && !strings.Contains(strings.TrimPrefix(name, prefix), "/") {
					selected[name] += count
				}
			}
		} else if cleanRelative(pattern) && !strings.ContainsAny(pattern, "*?[]{}!") {
			selected[pattern] += count
		} else {
			c.gap(1, 0, "workspace-pattern-unsupported")
		}
	}
	names := make([]string, 0, len(selected))
	for name := range selected {
		names = append(names, name)
	}
	sort.Strings(names)
	overlaps := map[string]bool{}
	for _, name := range names {
		for p := name; ; {
			i := strings.LastIndexByte(p, '/')
			if i < 0 {
				break
			}
			p = p[:i]
			if selected[p] > 0 {
				overlaps[name] = true
				overlaps[p] = true
			}
		}
	}
	for _, name := range names {
		if len(c.result.Model.Scopes) >= maxRecords {
			c.gap(1, 0, "workspace-limit")
			return
		}
		id := uint32(len(c.result.Model.Scopes) + 1)
		s := Scope{ID: id, Parent: 1, Location: name, Kind: "workspace", Status: "complete"}
		e, ok := c.entries[name]
		if !ok || e.Kind != nativefs.KindDirectory || e.Status != nativefs.StatusComplete {
			s.Status = "incomplete"
			c.gap(id, 0, "workspace-unavailable")
		}
		if selected[name] > 1 {
			s.Status = "incomplete"
			c.gap(id, 0, "workspace-overlap")
		}
		if overlaps[name] {
			s.Status = "incomplete"
			c.gap(id, 0, "workspace-overlap")
		}
		c.result.Model.Scopes = append(c.result.Model.Scopes, s)
		if ok && e.Kind == nativefs.KindDirectory && e.Status == nativefs.StatusComplete {
			c.collectManifest(id, name+"/package.json")
		}
	}
}
func (c *collector) scopeForLocation(name string) uint32 {
	for {
		if s, ok := c.workspaceScopes[name]; ok && s.Status == "complete" {
			return s.ID
		}
		i := strings.LastIndex(name, "/")
		if i < 0 {
			break
		}
		name = name[:i]
	}
	return 1
}
func (c *collector) chargeRequirements(scope, evidence uint32, groups []inventory.DependencyGroup) bool {
	for _, g := range groups {
		if g.State != inventory.FieldAbsent && g.State != inventory.FieldValue {
			c.gap(scope, evidence, "locked-requirements-invalid")
		}
		if len(g.Entries) > c.requirementsRemaining {
			c.gap(scope, evidence, "requirement-limit")
			return false
		}
		c.requirementsRemaining -= len(g.Entries)
		for _, d := range g.Entries {
			if d.State != inventory.FieldValue {
				c.gap(scope, evidence, "locked-requirement-invalid")
			}
		}
	}
	return true
}
