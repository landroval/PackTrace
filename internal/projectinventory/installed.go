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

// activeSlot recognizes only installation slots below a selected project/member,
// not every node_modules anywhere in the metadata tree or a Bun store directory.
func activeSlot(base, name string) bool {
	prefix := ""
	if base != "" {
		prefix = base + "/"
	}
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(name, prefix), "/")
	for i := 0; i < len(parts); {
		if parts[i] != "node_modules" || i+1 >= len(parts) {
			return false
		}
		i++
		if parts[i] == "" || strings.HasPrefix(parts[i], ".") {
			return false
		}
		if strings.HasPrefix(parts[i], "@") {
			if len(parts[i]) == 1 || i+1 >= len(parts) {
				return false
			}
			i++
			if parts[i] == "" || strings.HasPrefix(parts[i], ".") {
				return false
			}
		}
		i++
		if i == len(parts) {
			return true
		}
	}
	return false
}
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
func (c *collector) collectInstalled() {
	locations := map[string]uint32{}
	// Check bounded path ancestors, not every workspace against every entry.
	for name := range c.entries {
		if c.ctx.Err() != nil {
			return
		}
		owner := uint32(0)
		if activeSlot("", name) {
			owner = 1
		}
		prefix := name
		for {
			i := strings.LastIndex(prefix, "/")
			if i < 0 {
				break
			}
			prefix = prefix[:i]
			if s, ok := c.workspaceScopes[prefix]; ok && s.Status == "complete" && activeSlot(prefix, name) {
				owner = s.ID
				break
			}
		}
		if owner != 0 {
			locations[name] = owner
		}
	}
	names := make([]string, 0, len(locations))
	for name := range locations {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if c.ctx.Err() != nil {
			return
		}
		c.observeSlot(locations[name], name)
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
func (c *collector) observeSlot(scope uint32, name string) {
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
