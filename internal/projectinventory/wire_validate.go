package projectinventory

// ValidatePublic is the parent-side structural boundary. It rederives counters
// and completeness from closed labels and cross-referenced portable evidence.
func ValidatePublic(p PublicInventory) error {
	if len(p.Scopes) == 0 || len(p.Scopes) > maxRecords+1 || len(p.Evidence) == 0 || len(p.Evidence) > 100000 || len(p.Observations) > 3*maxRecords || len(p.Relations) > maxRecords || len(p.Gaps) > 257 || p.Counts != p.counts() {
		return ErrWire
	}
	if !allowed(p.Selection.Family, "npm", "bun", "unknown") || !allowed(p.Selection.State, "usable", "unusable", "absent", "indeterminate") || !allowed(p.Selection.Reason, selectionReasons...) {
		return ErrWire
	}
	complete := len(p.Gaps) == 0 && p.Selection.State == "usable" && p.Selection.Family != "unknown"
	for i, s := range p.Scopes {
		if s.ID != uint32(i+1) || !allowed(s.Status, "complete", "incomplete") {
			return ErrWire
		}
		if i == 0 {
			if s.Parent != 0 || s.Kind != "project" {
				return ErrWire
			}
		} else if s.Kind != "workspace" || s.Parent != 1 || s.Parent >= s.ID {
			return ErrWire
		}
		complete = complete && s.Status == "complete"
	}
	for i, e := range p.Evidence {
		if e.ID != uint32(i+1) || e.Scope == 0 || int(e.Scope) > len(p.Scopes) || !allowed(e.Method, evidenceMethods...) || !allowed(e.Status, "complete", "incomplete") {
			return ErrWire
		}
		complete = complete && e.Status == "complete"
	}
	for i, o := range p.Observations {
		if o.ID != uint32(i+1) || o.Workspace == 0 || int(o.Workspace) > len(p.Scopes) || o.Source == 0 || int(o.Source) > len(p.Evidence) || !allowed(o.Status, "complete", "unreadable", "unstable", "unsupported") {
			return ErrWire
		}
		switch o.Class {
		case "declared":
			if !allowed(o.Kind, "dependencies", "devDependencies", "optionalDependencies", "peerDependencies") {
				return ErrWire
			}
		case "locked":
			if !allowed(o.Kind, "unknown", "package", "project", "workspace", "link", "file", "git", "github", "url", "tarball", "folder") {
				return ErrWire
			}
		case "installed":
			if !allowed(o.Kind, "directory", "link", "slot-file") {
				return ErrWire
			}
		default:
			return ErrWire
		}
		if o.Class != "locked" && p.Evidence[o.Source-1].Scope != o.Workspace {
			return ErrWire
		}
		complete = complete && o.Status == "complete"
	}
	if p.Counts.Declared > maxRecords || p.Counts.Locked > maxRecords || p.Counts.Installed > maxRecords {
		return ErrWire
	}
	seen := map[struct {
		from, to uint32
		kind     string
	}]bool{}
	for _, r := range p.Relations {
		if r.From == 0 || int(r.From) > len(p.Observations) || r.Evidence == 0 || int(r.Evidence) > len(p.Evidence) {
			return ErrWire
		}
		key := struct {
			from, to uint32
			kind     string
		}{r.From, r.To, r.Kind}
		if seen[key] {
			return ErrWire
		}
		seen[key] = true
		from := p.Observations[r.From-1]
		witness := p.Evidence[r.Evidence-1]
		if r.Kind == "physical-link" {
			if from.Class != "installed" || from.Kind != "link" || from.Status != "complete" || r.Status != "contained" || r.To != from.Source || r.To == 0 || int(r.To) > len(p.Evidence) || witness.Method != "native-metadata-lease" || witness.Status != "complete" || p.Evidence[r.To-1].Method != "native-input-lease" || p.Evidence[r.To-1].Status != "complete" {
				return ErrWire
			}
			continue
		}
		if r.Kind == "locked-correspondence" && r.Status == "not-observed" {
			if from.Class != "locked" || allowed(from.Kind, "project", "workspace") || r.To != 0 || witness.Method != "native-metadata" || witness.Status != "complete" {
				return ErrWire
			}
			continue
		}
		if r.To == 0 || int(r.To) > len(p.Observations) {
			return ErrWire
		}
		to := p.Observations[r.To-1]
		if r.Evidence != to.Source {
			return ErrWire
		}
		switch r.Kind {
		case "declared-requirement":
			if from.Class != "declared" || to.Class != "locked" || from.Workspace != to.Workspace || !allowed(r.Status, "recorded-agreement", "conflict", "indeterminate") {
				return ErrWire
			}
		case "locked-correspondence":
			if from.Class != "locked" || to.Class != "installed" || !allowed(r.Status, "claim-agreement", "conflict", "indeterminate") {
				return ErrWire
			}
		case "candidate-correspondence":
			if from.Class != "locked" || to.Class != "installed" || r.Status != "indeterminate" {
				return ErrWire
			}
		default:
			return ErrWire
		}
	}
	for _, g := range p.Gaps {
		if int(g.Scope) > len(p.Scopes) || int(g.Evidence) > len(p.Evidence) || !allowed(g.Code, gapCodes...) {
			return ErrWire
		}
	}
	if p.Complete != complete {
		return ErrWire
	}
	return nil
}
