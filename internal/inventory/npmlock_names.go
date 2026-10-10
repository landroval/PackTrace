package inventory

import "strings"

type NPMLockName struct {
	Index                               int
	Location, InstallationName          string
	DeclaredName                        LockField[string]
	SelectedName, Source, Qualification string
}
type NPMLockNames struct {
	SourceSHA256 [32]byte
	Entries      []NPMLockName
}

// ProjectNPMLockNames interprets owned unchanged lock projections as metadata.
// Installation claims are not canonical identity or producer/origin proof.
func ProjectNPMLockNames(p NPMLockProjection) (NPMLockNames, error) {
	if p.Records == nil {
		return NPMLockNames{}, &ParseError{Code: "invalid-shape"}
	}
	if len(p.Records) > maxProjectedRecords {
		return NPMLockNames{}, &ParseError{Code: "limit-exceeded"}
	}
	// ponytail: same-key aliases block document-wide; qualified owner/hoist
	// resolution is the upgrade if unrelated contexts need separate attribution.
	aliases := map[string]bool{}
	uninspectable := false
	remaining := maxLockedRequirements
	for _, record := range p.Records {
		for _, group := range record.Requirements {
			if group.State == FieldNull || group.State == FieldInvalidType {
				uninspectable = true
			}
			if len(group.Entries) > remaining {
				return NPMLockNames{}, &ParseError{Code: "limit-exceeded"}
			}
			remaining -= len(group.Entries)
			for _, entry := range group.Entries {
				if entry.State != FieldValue || strings.HasPrefix(strings.TrimSpace(entry.Requirement), "npm:") {
					aliases[entry.Name] = true
				}
			}
		}
	}
	out := NPMLockNames{SourceSHA256: p.SourceSHA256, Entries: make([]NPMLockName, 0, len(p.Records))}
	for i, record := range p.Records {
		installation, valid := npmInstallationName(record.Location)
		n := NPMLockName{Index: i, Location: record.Location, InstallationName: installation, DeclaredName: record.Name, Source: "unavailable", Qualification: "locator-outside-profile"}
		switch {
		case record.Name.State == FieldValue && record.Name.Value != "":
			n.SelectedName, n.Source, n.Qualification = record.Name.Value, "record-name", "explicit-claim"
		case record.Name.State != FieldAbsent:
			n.Qualification = "explicit-unusable"
		case !valid:
		case record.Link.State != FieldAbsent && (record.Link.State != FieldValue || record.Link.Value):
			n.Qualification = "link-unqualified"
		case uninspectable:
			n.Qualification = "uninspectable-declarations"
		case aliases[installation]:
			n.Qualification = "alias-declaration"
		default:
			n.SelectedName, n.Source, n.Qualification = installation, "locator-profile", "installation-claim"
		}
		out.Entries = append(out.Entries, n)
	}
	return out, nil
}

// No locator is used for native filesystem access or URL normalization.
func npmInstallationName(locator string) (string, bool) {
	parts := strings.Split(locator, "/")
	selected := ""
	for i := 0; i < len(parts); {
		if parts[i] != "node_modules" || i+1 >= len(parts) {
			return "", false
		}
		name := parts[i+1]
		i += 2
		if strings.HasPrefix(name, "@") {
			if i >= len(parts) || !npmInstallationPart(name[1:]) || !npmInstallationPart(parts[i]) {
				return "", false
			}
			name += "/" + parts[i]
			i++
		} else if !npmInstallationPart(name) {
			return "", false
		}
		if len(name) > 214 {
			return "", false
		}
		selected = name
	}
	return selected, selected != ""
}

func npmInstallationPart(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
