package projectinventory

import (
	"encoding/json"
	"path"
	"sort"
	"strconv"
	"strings"

	"packtrace/internal/inventory"
	"packtrace/internal/nativefs"
)

func installationName(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) > 1 && strings.HasPrefix(parts[len(parts)-2], "@") {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	return path.Base(name)
}

func containedLink(name, target string) (string, bool) {
	if target == "" || len(target) > 4096 || strings.ContainsAny(target, "\\\x00:") || strings.HasPrefix(target, "/") {
		return "", false
	}
	resolved := path.Clean(path.Join(path.Dir(name), target))
	return resolved, cleanRelative(resolved)
}
func slotContainer(name string) string {
	if strings.HasPrefix(path.Base(name), ".") || strings.HasPrefix(path.Base(name), "@") {
		return ""
	}
	parent := path.Dir(name)
	if strings.HasPrefix(path.Base(parent), "@") {
		if len(path.Base(parent)) == 1 {
			return ""
		}
		parent = path.Dir(parent)
	}
	if path.Base(parent) != "node_modules" {
		return ""
	}
	return parent
}

func (c *collector) collectInstalled() {
	byContainer := map[string][]string{}
	for name := range c.entries {
		if container := slotContainer(name); container != "" {
			byContainer[container] = append(byContainer[container], name)
		}
	}
	for _, names := range byContainer {
		sort.Strings(names)
	}
	type activeContainer struct {
		name  string
		scope uint32
		skip  string
	}
	seenContainers, seenSlots := map[string]bool{}, map[string]bool{}
	var walk func(activeContainer, int, func() bool)
	walk = func(current activeContainer, depth int, guard func() bool) {
		if c.ctx.Err() != nil || seenContainers[current.name] {
			return
		}
		if depth > maxDepth {
			c.gap(current.scope, 0, "link-depth-limit")
			return
		}
		seenContainers[current.name] = true
		for _, name := range byContainer[current.name] {
			if name == current.skip || seenSlots[name] {
				continue
			}
			if !guard() {
				c.gap(current.scope, 0, "installed-binding-unstable")
				return
			}
			seenSlots[name] = true
			if c.classCounts["installed"] >= maxRecords {
				c.gap(current.scope, 0, "record-limit")
				return
			}
			c.observeSlotVisiting(current.scope, name, func(physical string, linked bool, stable func() bool) {
				owner := current.scope
				if s, ok := c.workspaceScopes[physical]; ok && s.Status == "complete" {
					owner = s.ID
				}
				retained := func() bool { return guard() && stable() }
				walk(activeContainer{physical + "/node_modules", owner, ""}, depth+1, retained)
				container := slotContainer(physical)
				if linked && c.result.Selection.Family == "bun" && c.result.Selection.State == "usable" && strings.Contains(container, "node_modules/.bun/") && path.Base(path.Dir(path.Dir(container))) == ".bun" {
					walk(activeContainer{container, owner, physical}, depth+1, retained)
				}
			})
		}
	}
	// The original qualifying metadata leases stay alive throughout each child
	// visit; a changed link cannot activate a former/orphaned store container.
	walk(activeContainer{"node_modules", 1, ""}, 0, func() bool { return true })
	for _, s := range c.result.Model.Scopes {
		if s.Kind == "workspace" && s.Status == "complete" {
			walk(activeContainer{s.Location + "/node_modules", s.ID, ""}, 0, func() bool { return true })
		}
	}
	// Store presence is metadata evidence, never an additional installed package.
	for _, s := range c.result.Model.Scopes {
		prefix := ""
		if s.Location != "" {
			prefix = s.Location + "/"
		}
		if e, ok := c.entries[prefix+"node_modules/.bun"]; ok && e.Kind == nativefs.KindDirectory {
			id := c.evidence(s.ID, e.Name, "unreferenced-store-metadata")
			c.result.Model.Evidence[id-1].Complete = e.Status == nativefs.StatusComplete
		}
	}
}
func (c *collector) observeSlot(scope uint32, name string) (string, bool) {
	return c.observeSlotVisiting(scope, name, nil)
}

func (c *collector) observeSlotVisiting(scope uint32, name string, visit func(string, bool, func() bool)) (physicalRoot string, linked bool) {
	mid := c.evidence(scope, name, "native-metadata-lease")
	o := Observation{Workspace: scope, Source: mid, Class: "installed", Kind: "directory", Status: "complete", Location: name, Fields: map[string]string{"installation-name": installationName(name), "metadata-evidence": strconv.Itoa(int(mid))}}
	original, e := c.root.OpenMetadata(c.ctx, name)
	if e != nil {
		o.Status = "unreadable"
		c.gap(scope, mid, "installed-slot-unavailable")
		c.add(o)
		return
	}
	leases := []*nativefs.MetadataLease{original}
	defer func() {
		stable := true
		for i := len(leases) - 1; i >= 0; i-- {
			se, ce := leases[i].Stable(), leases[i].Close()
			if se != nil || ce != nil {
				stable = false
			}
		}
		if !stable {
			physicalRoot, linked = "", false
			o.Status = "unstable"
			c.gap(scope, mid, "installed-binding-unstable")
		} else {
			c.result.Model.Evidence[mid-1].Complete = true
		}
		c.add(o)
	}()
	entry := original.Entry()
	physical := name
	visited := map[string]bool{name: true}
	if entry.Kind == nativefs.KindLink {
		o.Kind = "link"
		o.Fields["link-target"] = entry.LinkTarget
	}
	for entry.Kind == nativefs.KindLink {
		if len(leases) >= 40 {
			o.Status = "unsupported"
			c.gap(scope, mid, "link-depth-limit")
			return
		}
		target, ok := containedLink(physical, entry.LinkTarget)
		if !ok || visited[target] {
			o.Status = "unsupported"
			c.gap(scope, mid, "link-boundary")
			return
		}
		visited[target] = true
		next, e := c.root.OpenMetadata(c.ctx, target)
		if e != nil {
			o.Status = "unreadable"
			c.gap(scope, mid, "link-target-unavailable")
			return
		}
		leases = append(leases, next)
		physical = target
		entry = next.Entry()
	}
	if entry.Kind != nativefs.KindDirectory {
		o.Kind = "slot-file"
		o.Status = "unsupported"
		c.gap(scope, mid, "installed-slot-type")
		return
	}
	o.Fields["physical-target"] = physical
	manifest := physical + "/package.json"
	data, source, e := c.read(scope, manifest, maxManifestBytes, &c.manifestRemaining)
	if e != nil {
		o.Status = "unreadable"
		c.gap(scope, source, "installed-manifest-unavailable")
		return
	}
	doc, e := inventory.ParseManifest(data)
	if e != nil {
		o.Status = "unsupported"
		c.gap(scope, source, "installed-manifest-invalid")
		return
	}
	o.Source = source
	o.Name, o.Fields["name-state"] = claimString(doc.Fields, "name")
	o.Version, o.Fields["version-state"] = claimString(doc.Fields, "version")
	groups, e := inventory.ProjectManifest(doc)
	if e != nil {
		o.Status = "unsupported"
		c.gap(scope, source, "installed-manifest-invalid")
		return
	}
	o.Requirements = groups.Groups
	if !c.chargeRequirements(scope, source, o.Requirements) {
		o.Requirements = nil
		o.Status = "unsupported"
	}
	if o.Fields["name-state"] == "invalid" || o.Fields["version-state"] == "invalid" {
		o.Status = "unsupported"
		c.gap(scope, source, "installed-identity-invalid")
	}
	if o.Status == "complete" {
		physicalRoot, linked = physical, o.Kind == "link"
		stable := func() bool {
			for _, lease := range leases {
				if lease.Stable() != nil {
					return false
				}
			}
			return true
		}
		if visit != nil && stable() {
			visit(physicalRoot, linked, stable)
		}
	}
	return
}
func claimString(fields map[string]json.RawMessage, name string) (string, string) {
	raw, ok := fields[name]
	if !ok {
		return "", "absent"
	}
	if string(raw) == "null" {
		return "", "null"
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", "invalid"
	}
	return value, "value"
}
