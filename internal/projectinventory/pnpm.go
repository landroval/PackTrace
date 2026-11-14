package projectinventory

import (
	"errors"
	"packtrace/internal/inventory"
)

func (c *collector) inspectPNPM() bool {
	const limit = 1 << 20
	budget := int64(limit)
	data, source, err := c.read(1, "pnpm-lock.yaml", limit, &budget)
	if err != nil {
		c.gap(1, source, "lock-unreadable")
		return false
	}
	doc, err := inventory.ParsePNPMLock(data)
	if err != nil {
		code := "lock-invalid"
		var pe *inventory.ParseError
		if errors.As(err, &pe) && pe.Code == "unsupported-version" {
			code = "lock-version-unsupported"
		}
		c.gap(1, source, code)
		return false
	}
	p, err := inventory.ProjectPNPMLock(doc)
	if err != nil {
		c.gap(1, source, "locked-projection-invalid")
		return false
	}
	if p.Unsupported {
		c.gap(1, source, "locked-tuple-unsupported")
	}
	for _, importer := range p.Importers {
		if importer.Location != "." {
			c.gap(1, source, "pnpm-workspaces-unsupported")
		}
		requirements := importer.Requirements
		if !c.chargeRequirements(1, source, requirements) {
			requirements = nil
		}
		status := "complete"
		if importer.Unsupported {
			status = "unsupported"
			c.gap(1, source, "locked-tuple-unsupported")
		}
		// Importer requirements are locked claims, never manifest declarations.
		c.add(Observation{Workspace: 1, Source: source, Class: "locked", Kind: "project", Status: status, Location: importer.Location, Requirements: requirements})
	}
	for _, r := range p.Records {
		requirements := r.Requirements
		if !c.chargeRequirements(1, source, requirements) {
			requirements = nil
		}
		status, kind := "complete", "package"
		if r.Unsupported || r.Kind != "package" {
			status, kind = "unsupported", "unknown"
			c.gap(1, source, "locked-tuple-unsupported")
		}
		key := r.SnapshotKey
		if key == "" {
			key = r.PackageKey
		}
		c.add(Observation{Workspace: 1, Source: source, Class: "locked", Kind: kind, Status: status, Location: key, Name: r.Name.Value, Version: r.Version.Value, Fields: map[string]string{"name-state": fieldState(r.Name.State), "version-state": fieldState(r.Version.State)}, Requirements: requirements})
	}
	return true
}
