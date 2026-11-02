package projectinventory

import (
	"encoding/json"
	"errors"
	"strings"

	"packtrace/internal/inventory"
)

func (c *collector) selectInputs(opts Options) {
	s := &c.result.Selection
	n1, n2 := c.npmState("npm-shrinkwrap.json"), c.npmState("package-lock.json")
	b1, b2 := c.bunState("bun.lock"), c.bunState("bun.lockb")
	npmPresent := n1.Presence == inventory.NPMInputPresencePresent || n2.Presence == inventory.NPMInputPresencePresent
	bunPresent := b1.Presence == inventory.BunInputPresencePresent || b2.Presence == inventory.BunInputPresencePresent
	conflict := npmPresent && bunPresent
	if conflict && !opts.ExplicitManager {
		s.Reason = "manager-conflict"
		c.gap(1, 0, "selection-indeterminate")
		return
	}
	switch {
	case strings.HasPrefix(opts.Profile, "npm@"):
		s.Family = "npm"
		chosen, e := inventory.SelectNPMInput(opts.Profile, n1, n2)
		if e != nil {
			c.gap(1, 0, "selection-invalid")
			return
		}
		if chosen.ProfileQualified {
			name := ""
			if chosen.Candidate == inventory.NPMInputCandidateShrinkwrap {
				name = "npm-shrinkwrap.json"
			} else if chosen.Candidate == inventory.NPMInputCandidatePackageLock {
				name = "package-lock.json"
			}
			if name != "" {
				p, u := c.presence(name)
				if p == "present" && u == "unqualified" {
					state := c.inspectNPM(name)
					if name == "npm-shrinkwrap.json" {
						n1.Usability = state
					} else {
						n2.Usability = state
					}
					chosen, _ = inventory.SelectNPMInput(opts.Profile, n1, n2)
				}
			}
		}
		switch chosen.Candidate {
		case inventory.NPMInputCandidateShrinkwrap:
			s.File = "npm-shrinkwrap.json"
		case inventory.NPMInputCandidatePackageLock:
			s.File = "package-lock.json"
		}
		switch chosen.State {
		case inventory.NPMInputSelectionUsable:
			s.State = "usable"
		case inventory.NPMInputSelectionUnusable:
			s.State = "unusable"
		case inventory.NPMInputSelectionAbsent:
			s.State = "absent"
		default:
			s.State = "indeterminate"
		}
		switch chosen.Diagnostic {
		case inventory.NPMInputDiagnosticNone:
			s.Reason = "none"
		case inventory.NPMInputDiagnosticProfileUnqualified:
			s.Reason = "profile-unqualified"
		case inventory.NPMInputDiagnosticNoRootLock:
			s.Reason = "no-root-lock"
		case inventory.NPMInputDiagnosticCandidateUnusable:
			s.Reason = "candidate-unusable"
		case inventory.NPMInputDiagnosticShrinkwrapPresenceUnknown:
			s.Reason = "shrinkwrap-presence-unknown"
		case inventory.NPMInputDiagnosticPackageLockPresenceUnknown:
			s.Reason = "package-lock-presence-unknown"
		default:
			s.Reason = "usability-unqualified"
		}
	case strings.HasPrefix(opts.Profile, "bun@"):
		s.Family = "bun"
		chosen, e := inventory.SelectBunInput(opts.Profile, b1, b2)
		if e != nil {
			c.gap(1, 0, "selection-invalid")
			return
		}
		if chosen.ProfileQualified && chosen.Candidate == inventory.BunInputCandidateText {
			p, u := c.presence("bun.lock")
			if p == "present" && u == "unqualified" {
				b1.Usability = c.inspectBun("bun.lock")
				chosen, _ = inventory.SelectBunInput(opts.Profile, b1, b2)
			}
		}
		switch chosen.Candidate {
		case inventory.BunInputCandidateText:
			s.File = "bun.lock"
		case inventory.BunInputCandidateBinary:
			s.File = "bun.lockb"
		}
		switch chosen.State {
		case inventory.BunInputSelectionUsable:
			s.State = "usable"
		case inventory.BunInputSelectionUnusable:
			s.State = "unusable"
		case inventory.BunInputSelectionAbsent:
			s.State = "absent"
		default:
			s.State = "indeterminate"
		}
		switch chosen.Diagnostic {
		case inventory.BunInputDiagnosticNone:
			s.Reason = "none"
		case inventory.BunInputDiagnosticProfileUnqualified:
			s.Reason = "profile-unqualified"
		case inventory.BunInputDiagnosticConflictingInputs:
			s.Reason = "conflicting-inputs"
		case inventory.BunInputDiagnosticLegacyBinaryUnsupported:
			s.Reason = "binary-unsupported"
		case inventory.BunInputDiagnosticNoRootLock:
			s.Reason = "no-root-lock"
		case inventory.BunInputDiagnosticCandidateUnusable:
			s.Reason = "candidate-unusable"
		case inventory.BunInputDiagnosticTextPresenceUnknown:
			s.Reason = "text-presence-unknown"
		case inventory.BunInputDiagnosticBinaryPresenceUnknown:
			s.Reason = "binary-presence-unknown"
		default:
			s.Reason = "usability-unqualified"
		}
	}
	if s.State != "usable" {
		c.gap(1, 0, "selection-"+s.State)
	} else if conflict {
		s.Reason = "explicit-manager-conflict"
	}
}
func (c *collector) npmState(name string) inventory.NPMInputState {
	p, u := c.presence(name)
	s := inventory.NPMInputState{}
	switch p {
	case "present":
		s.Presence = inventory.NPMInputPresencePresent
	case "absent":
		s.Presence = inventory.NPMInputPresenceAbsent
	}
	switch u {
	case "unsafe":
		s.Usability = inventory.NPMInputUsabilityUnsafe
	case "unreadable":
		s.Usability = inventory.NPMInputUsabilityUnreadable
	}
	return s
}
func (c *collector) bunState(name string) inventory.BunInputState {
	p, u := c.presence(name)
	s := inventory.BunInputState{}
	switch p {
	case "present":
		s.Presence = inventory.BunInputPresencePresent
	case "absent":
		s.Presence = inventory.BunInputPresenceAbsent
	}
	switch u {
	case "unsafe":
		s.Usability = inventory.BunInputUsabilityUnsafe
	case "unreadable":
		s.Usability = inventory.BunInputUsabilityUnreadable
	}
	return s
}
func (c *collector) inspectNPM(name string) inventory.NPMInputUsability {
	budget := int64(maxLockBytes)
	data, id, e := c.read(1, name, maxLockBytes, &budget)
	if e != nil {
		c.gap(1, id, "lock-unreadable")
		return inventory.NPMInputUsabilityUnreadable
	}
	doc, e := inventory.ParseNPMLock(data)
	if e == nil {
		e = c.projectNPM(doc, id)
	}
	if e == nil {
		return inventory.NPMInputUsabilityUsable
	}
	c.gap(1, id, "lock-invalid")
	var pe *inventory.ParseError
	if errors.As(e, &pe) && pe.Code == "unsupported-version" {
		return inventory.NPMInputUsabilityUnsupported
	}
	return inventory.NPMInputUsabilityInvalid
}
func (c *collector) inspectBun(name string) inventory.BunInputUsability {
	budget := int64(maxLockBytes)
	data, id, e := c.read(1, name, maxLockBytes, &budget)
	if e != nil {
		c.gap(1, id, "lock-unreadable")
		return inventory.BunInputUsabilityUnreadable
	}
	doc, e := inventory.ParseBunLock(data)
	if e != nil {
		c.gap(1, id, "lock-invalid")
		var pe *inventory.ParseError
		if errors.As(e, &pe) && pe.Code == "unsupported-version" {
			return inventory.BunInputUsabilityUnsupported
		}
		return inventory.BunInputUsabilityInvalid
	}
	if raw, ok := doc.Fields["configVersion"]; ok {
		var v int
		if json.Unmarshal(raw, &v) != nil || string(raw) == "null" || v < 0 || v > 1 {
			c.gap(1, id, "config-version-unsupported")
			return inventory.BunInputUsabilityUnsupported
		}
	}
	if c.projectBun(doc, id) != nil {
		c.gap(1, id, "locked-projection-invalid")
		return inventory.BunInputUsabilityInvalid
	}
	return inventory.BunInputUsabilityUsable
}
