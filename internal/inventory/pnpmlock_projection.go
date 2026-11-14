package inventory

import (
	"net/url"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
	"packtrace/internal/intel"
)

// PNPMDependencyReference is a lockfile claim, never a manifest declaration.
type PNPMDependencyReference struct {
	Group, InstallationName string
	Specifier, Reference    LockField[string]
}

type PNPMImporterRecord struct {
	Location     string // Opaque evidence, never authority for filesystem access.
	Requirements []DependencyGroup
	References   []PNPMDependencyReference
}

type PNPMLockedRecord struct {
	PackageKey, SnapshotKey           string
	Name, Version, Integrity, Tarball LockField[string]
	Requirements                      []DependencyGroup
	Kind                              string // Registry-shaped claim only; no origin or installation authority.
	Unsupported                       bool
	Problem                           string // Fixed privacy-safe code, not target text.
}

type PNPMLockProjection struct {
	SourceSHA256 [32]byte
	Importers    []PNPMImporterRecord
	Records      []PNPMLockedRecord
}

// ProjectPNPMLock projects owned, successfully parsed nodes. Output allocations
// are independent on every call. Snapshot contexts are not installed locations.
func ProjectPNPMLock(doc PNPMLockDocument) (PNPMLockProjection, error) {
	if !doc.valid || doc.root == nil || doc.SHA256 != doc.digest {
		return PNPMLockProjection{}, pnpmError("invalid-shape")
	}
	p := PNPMLockProjection{SourceSHA256: doc.digest, Importers: []PNPMImporterRecord{}, Records: []PNPMLockedRecord{}}
	importers := pnpmLookup(doc.root, "importers")
	packages := pnpmLookup(doc.root, "packages")
	snapshots := pnpmLookup(doc.root, "snapshots")
	if importers == nil || importers.Kind != yaml.MappingNode {
		return PNPMLockProjection{}, pnpmError("invalid-shape")
	}
	records := 0
	for _, section := range []*yaml.Node{importers, packages, snapshots} {
		if section == nil {
			continue
		}
		if section.Kind != yaml.MappingNode {
			return PNPMLockProjection{}, pnpmError("invalid-shape")
		}
		records += len(section.Content) / 2
		if records > maxProjectedRecords {
			return PNPMLockProjection{}, pnpmError("limit-exceeded")
		}
		for i := 1; i < len(section.Content); i += 2 {
			if section.Content[i].Kind != yaml.MappingNode {
				return PNPMLockProjection{}, pnpmError("invalid-shape")
			}
		}
	}
	if settings := pnpmLookup(doc.root, "settings"); settings != nil {
		if settings.Kind != yaml.MappingNode {
			return PNPMLockProjection{}, pnpmError("invalid-shape")
		}
		for _, key := range []string{"autoInstallPeers", "excludeLinksFromLockfile", "injectWorkspacePackages"} {
			if n := pnpmLookup(settings, key); n != nil && (n.Kind != yaml.ScalarNode || n.Tag != "!!bool") {
				return PNPMLockProjection{}, pnpmError("invalid-shape")
			}
		}
	}
	remaining := maxLockedRequirements
	for _, entry := range pnpmEntries(importers) {
		groups, refs, err := pnpmRequirements(entry.value, true, &remaining)
		if err != nil {
			return PNPMLockProjection{}, err
		}
		p.Importers = append(p.Importers, PNPMImporterRecord{Location: entry.key, Requirements: groups, References: refs})
	}
	outputRemaining := remaining
	metadata := map[string]PNPMLockedRecord{}
	for _, entry := range pnpmEntries(packages) {
		r := PNPMLockedRecord{PackageKey: entry.key, Kind: "unknown"}
		name, version, ok := pnpmIdentity(entry.key)
		if ok {
			r.Name = pnpmString(name)
			r.Version = pnpmString(version)
			r.Kind = "package"
		} else {
			pnpmUnsupported(&r, "unsupported-package-key")
		}
		var err error
		r.Requirements, _, err = pnpmRequirements(entry.value, false, &remaining)
		if err != nil {
			return PNPMLockProjection{}, err
		}
		if err = pnpmMetadataShape(entry.value); err != nil {
			return PNPMLockProjection{}, err
		}
		for _, claim := range []struct{ key, value string }{{"name", name}, {"version", version}} {
			if n := pnpmLookup(entry.value, claim.key); n != nil && (!ok || n.Value != claim.value) {
				pnpmUnsupported(&r, "conflicting-identity")
			}
		}
		if resolution := pnpmLookup(entry.value, "resolution"); resolution != nil {
			if resolution.Kind != yaml.MappingNode {
				return PNPMLockProjection{}, pnpmError("invalid-shape")
			}
			for _, field := range []struct {
				key  string
				dest *LockField[string]
			}{{"integrity", &r.Integrity}, {"tarball", &r.Tarball}} {
				if n := pnpmLookup(resolution, field.key); n != nil {
					if !pnpmIsString(n) {
						return PNPMLockProjection{}, pnpmError("invalid-shape")
					}
					*field.dest = pnpmString(n.Value)
				}
			}
			for _, field := range pnpmEntries(resolution) {
				if field.key != "integrity" && field.key != "tarball" {
					pnpmUnsupported(&r, "unsupported-resolution")
				}
			}
		}
		if r.Tarball.State == FieldValue && !pnpmTarball(r.Tarball.Value) {
			pnpmUnsupported(&r, "unsupported-resolution")
		}
		for _, key := range []string{"patched", "patchHash"} {
			if pnpmLookup(entry.value, key) != nil {
				pnpmUnsupported(&r, "unsupported-patch")
			}
		}
		metadata[entry.key] = r
	}
	joined := map[string]bool{}
	for _, entry := range pnpmEntries(snapshots) {
		base, ok := pnpmSnapshotBase(entry.key)
		r, found := metadata[base]
		if !ok || !found {
			r = PNPMLockedRecord{Kind: "unknown"}
			pnpmUnsupported(&r, "unmatched-snapshot")
			if !ok {
				r.Problem = "unsupported-snapshot-key"
			}
		} else {
			joined[base] = true
		}
		r.SnapshotKey = entry.key
		groups, _, err := pnpmRequirements(entry.value, false, &remaining)
		if err != nil {
			return PNPMLockProjection{}, err
		}
		if err = pnpmMetadataShape(entry.value); err != nil {
			return PNPMLockProjection{}, err
		}
		for _, key := range []string{"resolution", "patched", "patchHash"} {
			if pnpmLookup(entry.value, key) != nil {
				pnpmUnsupported(&r, "unsupported-snapshot-metadata")
			}
		}
		for _, claim := range []struct {
			key   string
			field LockField[string]
		}{{"name", r.Name}, {"version", r.Version}} {
			if n := pnpmLookup(entry.value, claim.key); n != nil && (claim.field.State != FieldValue || n.Value != claim.field.Value) {
				pnpmUnsupported(&r, "conflicting-identity")
			}
		}
		r.Requirements = pnpmMergeRequirements(r.Requirements, groups)
		for _, group := range r.Requirements {
			if err := pnpmCharge(&outputRemaining, len(group.Entries)); err != nil {
				return PNPMLockProjection{}, err
			}
		}
		pnpmCheckReferences(&r)
		p.Records = append(p.Records, r)
	}
	for _, entry := range pnpmEntries(packages) {
		if !joined[entry.key] {
			r := metadata[entry.key]
			for _, group := range r.Requirements {
				if err := pnpmCharge(&outputRemaining, len(group.Entries)); err != nil {
					return PNPMLockProjection{}, err
				}
			}
			pnpmCheckReferences(&r)
			p.Records = append(p.Records, r)
		}
	}
	slices.SortFunc(p.Records, func(a, b PNPMLockedRecord) int {
		if c := strings.Compare(a.PackageKey, b.PackageKey); c != 0 {
			return c
		}
		return strings.Compare(a.SnapshotKey, b.SnapshotKey)
	})
	return p, nil
}

type pnpmEntry struct {
	key   string
	value *yaml.Node
}

func pnpmEntries(n *yaml.Node) []pnpmEntry {
	if n == nil {
		return nil
	}
	entries := make([]pnpmEntry, 0, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		entries = append(entries, pnpmEntry{n.Content[i].Value, n.Content[i+1]})
	}
	slices.SortFunc(entries, func(a, b pnpmEntry) int { return strings.Compare(a.key, b.key) })
	return entries
}

func pnpmString(value string) LockField[string] {
	return LockField[string]{State: FieldValue, Value: value}
}
func pnpmIsString(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!str"
}
func pnpmUnsupported(r *PNPMLockedRecord, code string) {
	r.Unsupported = true
	if r.Problem == "" {
		r.Problem = code
	}
}
func pnpmCharge(remaining *int, n int) error {
	if n > *remaining {
		return pnpmError("limit-exceeded")
	}
	*remaining -= n
	return nil
}

func pnpmRequirements(n *yaml.Node, importer bool, remaining *int) ([]DependencyGroup, []PNPMDependencyReference, error) {
	groups := []DependencyGroup{}
	refs := []PNPMDependencyReference{}
	for _, name := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		group := DependencyGroup{Name: name}
		value := pnpmLookup(n, name)
		if value == nil {
			groups = append(groups, group)
			continue
		}
		if value.Kind != yaml.MappingNode {
			return nil, nil, pnpmError("invalid-shape")
		}
		group.State = FieldValue
		for _, entry := range pnpmEntries(value) {
			charge := 1
			if importer {
				charge = 2
			} // Both returned requirements and references.
			if err := pnpmCharge(remaining, charge); err != nil {
				return nil, nil, err
			}
			reference := entry.value
			if importer {
				if entry.value.Kind != yaml.MappingNode {
					return nil, nil, pnpmError("invalid-shape")
				}
				specifier := pnpmLookup(entry.value, "specifier")
				reference = pnpmLookup(entry.value, "version")
				if !pnpmIsString(specifier) || !pnpmIsString(reference) {
					return nil, nil, pnpmError("invalid-shape")
				}
				refs = append(refs, PNPMDependencyReference{Group: name, InstallationName: entry.key, Specifier: pnpmString(specifier.Value), Reference: pnpmString(reference.Value)})
			}
			if !pnpmIsString(reference) {
				return nil, nil, pnpmError("invalid-shape")
			}
			group.Entries = append(group.Entries, DeclaredDependency{Name: entry.key, Requirement: reference.Value, State: FieldValue})
		}
		groups = append(groups, group)
	}
	return groups, refs, nil
}

func pnpmMergeRequirements(a, b []DependencyGroup) []DependencyGroup {
	out := make([]DependencyGroup, len(b))
	for i, g := range b {
		out[i] = g
		if len(a) == len(b) {
			if a[i].State == FieldValue {
				out[i].State = FieldValue
			}
			out[i].Entries = append(slices.Clone(a[i].Entries), g.Entries...)
			slices.SortStableFunc(out[i].Entries, func(a, b DeclaredDependency) int {
				if c := strings.Compare(a.Name, b.Name); c != 0 {
					return c
				}
				return strings.Compare(a.Requirement, b.Requirement)
			})
		}
	}
	return out
}

// Known scalar/list metadata is typed even though it grants no execution,
// platform, bundled-installation or peer-resolution authority.
func pnpmMetadataShape(n *yaml.Node) error {
	for _, key := range []string{"optional", "hasBin", "requiresBuild", "dev"} {
		if v := pnpmLookup(n, key); v != nil && (v.Kind != yaml.ScalarNode || v.Tag != "!!bool") {
			return pnpmError("invalid-shape")
		}
	}
	for _, key := range []string{"name", "version", "deprecated", "id"} {
		if v := pnpmLookup(n, key); v != nil && !pnpmIsString(v) {
			return pnpmError("invalid-shape")
		}
	}
	for _, key := range []string{"cpu", "os", "libc", "bundledDependencies", "bundleDependencies", "transitivePeerDependencies"} {
		if v := pnpmLookup(n, key); v != nil {
			if v.Kind != yaml.SequenceNode {
				return pnpmError("invalid-shape")
			}
			for _, item := range v.Content {
				if !pnpmIsString(item) {
					return pnpmError("invalid-shape")
				}
			}
		}
	}
	if engines := pnpmLookup(n, "engines"); engines != nil {
		if engines.Kind != yaml.MappingNode {
			return pnpmError("invalid-shape")
		}
		for _, item := range pnpmEntries(engines) {
			if !pnpmIsString(item.value) {
				return pnpmError("invalid-shape")
			}
		}
	}
	if peers := pnpmLookup(n, "peerDependenciesMeta"); peers != nil {
		if peers.Kind != yaml.MappingNode {
			return pnpmError("invalid-shape")
		}
		for _, peer := range pnpmEntries(peers) {
			if peer.value.Kind != yaml.MappingNode {
				return pnpmError("invalid-shape")
			}
			if v := pnpmLookup(peer.value, "optional"); v != nil && (v.Kind != yaml.ScalarNode || v.Tag != "!!bool") {
				return pnpmError("invalid-shape")
			}
		}
	}
	return nil
}

// This is only a supported spelling check, never origin authentication or a
// grant to fetch the URL. Even accepted URLs remain untrusted recorded claims.
func pnpmTarball(text string) bool {
	u, err := url.Parse(text)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.Fragment == ""
}

func pnpmCheckReferences(r *PNPMLockedRecord) {
	for _, g := range r.Requirements {
		if g.Name == "peerDependencies" {
			continue
		} // Uninterpreted ranges, not resolved edges.
		for _, entry := range g.Entries {
			ref := strings.TrimPrefix(entry.Requirement, "npm:")
			_, direct := pnpmSnapshotBase(entry.Name + "@" + ref)
			_, alias := pnpmSnapshotBase(ref)
			if !pnpmName(entry.Name) || !direct && !alias {
				pnpmUnsupported(r, "unsupported-reference")
			}
		}
	}
}

func pnpmIdentity(key string) (string, string, bool) {
	if key == "" || len(key) > 4096 {
		return "", "", false
	}
	at := strings.IndexByte(key[1:], '@') + 1
	if at <= 0 {
		return "", "", false
	}
	name, version := key[:at], key[at+1:]
	if !pnpmName(name) || len(version) > 256 {
		return "", "", false
	}
	if _, err := intel.ParseSemVer(version); err != nil {
		return "", "", false
	}
	return name, version, true
}

func pnpmName(name string) bool {
	if name == "" || len(name) > 214 {
		return false
	}
	if name[0] == '@' {
		scope, part, ok := strings.Cut(name[1:], "/")
		return ok && npmInstallationPart(scope) && npmInstallationPart(part)
	}
	return npmInstallationPart(name)
}

// Validate every peer-qualified context before joining. A balanced suffix alone
// is insufficient: patch hashes, paths and arbitrary text are not peer claims.
func pnpmSnapshotBase(key string) (string, bool) {
	if key == "" || len(key) > 4096 {
		return "", false
	}
	base, _, _ := strings.Cut(key, "(")
	if _, _, ok := pnpmIdentity(base); !ok {
		return "", false
	}
	pos := 0
	if !pnpmContext(key, &pos, 0) || pos != len(key) {
		return "", false
	}
	return base, true
}

func pnpmContext(key string, pos *int, depth int) bool {
	if depth > 64 {
		return false
	}
	start := *pos
	for *pos < len(key) && key[*pos] != '(' && key[*pos] != ')' {
		*pos++
	}
	if _, _, ok := pnpmIdentity(key[start:*pos]); !ok {
		return false
	}
	for *pos < len(key) && key[*pos] == '(' {
		*pos++
		if !pnpmContext(key, pos, depth+1) || *pos >= len(key) || key[*pos] != ')' {
			return false
		}
		*pos++
	}
	return true
}
