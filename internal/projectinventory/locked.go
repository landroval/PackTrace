package projectinventory

import (
	"bytes"
	"encoding/json"
	"strings"

	"packtrace/internal/inventory"
)

func (c *collector) keepVariants(scope, source uint32, raw map[string]json.RawMessage, out map[string]string) {
	for _, name := range []string{"link", "optional", "dev", "devOptional", "inBundle", "hasInstallScript"} {
		if value, ok := raw[name]; ok {
			out[name] = string(value)
			var v bool
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &v) != nil {
				c.gap(scope, source, "variant-invalid")
			}
		}
	}
	for _, name := range []string{"os", "cpu"} {
		if value, ok := raw[name]; ok {
			out[name] = string(value)
			var v []string
			if json.Unmarshal(value, &v) != nil || v == nil {
				c.gap(scope, source, "variant-invalid")
			}
		}
	}
}

func (c *collector) projectNPM(doc inventory.Document, source uint32) error {
	p, e := inventory.ProjectNPMLock(doc)
	if e != nil {
		return e
	}
	names, e := inventory.ProjectNPMLockNames(p)
	if e != nil {
		return e
	}
	for i, r := range p.Records {
		scope := c.scopeForLocation(r.Location)
		if !c.chargeRequirements(scope, source, r.Requirements) {
			break
		}
		n := names.Entries[i]
		fields := map[string]string{"name-state": fieldState(r.Name.State), "version-state": fieldState(r.Version.State), "origin-state": fieldState(r.Resolved.State), "integrity-state": fieldState(r.Integrity.State), "integrity": r.Integrity.Value, "installation-name": n.InstallationName, "name-qualification": n.Qualification, "name-source": n.Source}
		c.keepVariants(scope, source, doc.Packages[r.Location], fields)
		kind := "package"
		switch {
		case r.Location == "":
			kind = "project"
		case r.Link.State == inventory.FieldValue && r.Link.Value:
			kind = "link"
		case strings.HasPrefix(r.Resolved.Value, "file:"):
			kind = "file"
		case strings.HasPrefix(r.Resolved.Value, "git:") || strings.HasPrefix(r.Resolved.Value, "git+") || strings.HasPrefix(r.Resolved.Value, "git@"):
			kind = "git"
		case strings.HasPrefix(r.Resolved.Value, "http:") || strings.HasPrefix(r.Resolved.Value, "https:"):
			kind = "url"
		}
		for _, s := range c.result.Model.Scopes {
			if s.Kind == "workspace" && s.Location == r.Location {
				kind = "workspace"
				break
			}
		}
		c.add(Observation{Workspace: scope, Source: source, Class: "locked", Kind: kind, Status: "complete", Location: r.Location, Name: n.SelectedName, Version: r.Version.Value, Origin: r.Resolved.Value, Fields: fields, Requirements: r.Requirements})
	}
	return nil
}
func (c *collector) projectBun(doc inventory.BunLockDocument, source uint32) error {
	p, e := inventory.ProjectBunLock(doc)
	if e != nil {
		return e
	}
	workspaces, e := inventory.ProjectBunWorkspaces(doc)
	if e != nil {
		return e
	}
	for _, r := range workspaces.Records {
		scope := c.scopeForLocation(r.Location)
		if !c.chargeRequirements(scope, source, r.Requirements) {
			return nil
		}
		c.add(Observation{Workspace: scope, Source: source, Class: "locked", Kind: "workspace", Status: "complete", Location: r.Location, Name: r.Name.Value, Version: r.Version.Value, Fields: map[string]string{"name-state": fieldState(r.Name.State), "version-state": fieldState(r.Version.State)}, Requirements: r.Requirements})
	}
	for _, r := range p.Records {
		if !c.chargeRequirements(1, source, r.Requirements) {
			return nil
		}
		kinds := []string{"unknown", "package", "git", "github", "tarball", "folder", "link", "workspace", "project"}
		kind := "unknown"
		if int(r.Kind) < len(kinds) {
			kind = kinds[r.Kind]
		}
		fields := map[string]string{"name-state": fieldState(r.Name.State), "resolution-state": fieldState(r.Resolution.State), "integrity-state": fieldState(r.Integrity.State), "integrity": r.Integrity.Value, "registry-state": fieldState(r.Registry.State), "git-tag": r.GitTag.Value, "tuple-key": r.Key}
		if r.Info != nil {
			var info map[string]json.RawMessage
			if json.Unmarshal(r.Info, &info) == nil {
				c.keepVariants(1, source, info, fields)
				if raw, ok := info["bin"]; ok {
					fields["bin"] = string(raw)
				}
			}
		}
		c.add(Observation{Workspace: 1, Source: source, Class: "locked", Kind: kind, Status: "complete", Location: r.Key, Name: r.Name.Value, Version: r.Resolution.Value, Origin: r.Registry.Value, Fields: fields, Requirements: r.Requirements})
		if kind == "unknown" {
			c.gap(1, source, "locked-tuple-unsupported")
		}
	}
	return nil
}
