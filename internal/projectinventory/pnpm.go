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
		c.add(Observation{Workspace: 1, Source: source, Class: "locked", Kind: kind, Status: status, Location: key, Name: r.Name.Value, Version: r.Version.Value, Fields: map[string]string{"name-state": fieldState(r.Name.State), "version-state": fieldState(r.Version.State), "tuple-key": key}, Requirements: requirements})
	}
	return true
}

// A pnpm tuple location is a logical key, never an installed path. Reuse the
// bounded reconciler only for supported identities, and keep candidates only:
// neither absence nor unique/physical/declaration agreement is established.
func reconcilePNPM(m Model) Model {
	eligible := m
	eligible.Observations = nil
	eligible.Relations = nil
	for _, o := range m.Observations {
		if o.Status == "complete" && o.Name != "" && o.Version != "" &&
			(o.Class == "installed" || o.Class == "locked" && o.Kind == "package") {
			if o.Class == "installed" {
				// Candidate matching needs identity only. Do not generate discarded
				// physical-link edges or charge them against the candidate budget.
				o.Fields = nil
			}
			eligible.Observations = append(eligible.Observations, o)
		}
	}
	reconciled := Reconcile(eligible)
	m.Gaps = reconciled.Gaps // Preserve aggregate relation-limit accounting.
	for _, relation := range reconciled.Relations {
		if relation.Kind == "candidate-correspondence" {
			m.Relations = append(m.Relations, relation)
		}
	}
	return m
}
