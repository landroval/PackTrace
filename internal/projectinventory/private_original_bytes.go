package projectinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"sort"

	"packtrace/internal/inventory"
)

// A lower capture ceiling, not a protocol allowance increase. Base64 plus the
// semantic witness must still fit the existing single 1 MiB frame. Overflow
// discards the whole capture; no prefix can silently authorize omitted context.
const maxOriginalInputBytes = 512 << 10
const maxOriginalInputRows = 4096

func (c *collector) retainOriginal(source uint32, data []byte) {
	if c.originalOverflow {
		return
	}
	if len(data) > maxOriginalInputBytes-c.originalBytes || len(c.result.OriginalInputs) >= maxOriginalInputRows {
		c.result.OriginalInputs = nil
		c.originalOverflow = true
		return
	}
	c.result.OriginalInputs = append(c.result.OriginalInputs, OriginalInput{Source: source, Bytes: slices.Clone(data)})
	c.originalBytes += len(data)
}

// ValidateOriginalBytes binds semantic claims to the retained stable-read input
// receipts, not to a second child assertion. It does not authenticate a child
// fabricating BOTH bytes and receipts, nor authenticate mutable target identity.
// All failures are deliberately content-free at this private boundary.
func ValidateOriginalBytes(r Result) error {
	if r.Selection.Family != "bun" || r.Selection.State != "usable" || len(r.OriginalInputs) == 0 || len(r.OriginalInputs) > maxOriginalInputRows {
		return ErrWire
	}
	evidence := map[uint32]Evidence{}
	for _, e := range r.Model.Evidence {
		if e.ID == 0 {
			return ErrWire
		}
		if _, exists := evidence[e.ID]; exists {
			return ErrWire
		}
		evidence[e.ID] = e
	}
	raw := map[uint32][]byte{}
	total := 0
	for _, in := range r.OriginalInputs {
		total += len(in.Bytes)
		e, ok := evidence[in.Source]
		if total > maxOriginalInputBytes || len(in.Bytes) == 0 || !ok || !e.Complete || e.Method != "native-input-lease" || sha256.Sum256(in.Bytes) != e.SHA256 {
			return ErrWire
		}
		if _, duplicate := raw[in.Source]; duplicate {
			return ErrWire
		}
		raw[in.Source] = in.Bytes
	}
	// Reuse the actual collector projections, including BunMatchingContext on
	// the original document/INFO and every declaration group (aliases/peers too).
	c := collector{requirementsRemaining: maxRecords, classCounts: map[string]int{}, workspaceScopes: map[string]Scope{}}
	root, lock := uint32(0), uint32(0)
	used := map[uint32]bool{}
	for _, e := range r.Model.Evidence {
		if e.Scope != 1 || e.Method != "native-input-lease" {
			continue
		}
		if e.Location == "package.json" {
			if root != 0 {
				return ErrWire
			}
			root = e.ID
		}
		if e.Location == r.Selection.File {
			if lock != 0 {
				return ErrWire
			}
			lock = e.ID
		}
	}
	if root == 0 || lock == 0 || raw[root] == nil || raw[lock] == nil {
		return ErrWire
	}
	doc, err := inventory.ParseManifest(raw[root])
	if err != nil {
		return ErrWire
	}
	// Bun authority currently excludes workspaces, including hidden root hints.
	if _, ok := doc.Fields["workspaces"]; ok {
		return ErrWire
	}
	if c.projectManifest(1, root, "package.json", doc) != nil {
		return ErrWire
	}
	bun, err := inventory.ParseBunLock(raw[lock])
	if err != nil {
		return ErrWire
	}
	if !bunLockVersionSupported(bun, r.Selection.Profile) || !bunConfigSupported(bun) || c.projectBun(bun, lock) != nil || len(c.result.Model.Gaps) != 0 {
		return ErrWire
	}
	used[root], used[lock] = true, true
	var supplied []Observation
	for _, o := range r.Model.Observations {
		switch o.Class {
		case "declared", "locked":
			if o.Class == "declared" && o.Source != root || o.Class == "locked" && o.Source != lock {
				return ErrWire
			}
			o.ID = 0
			supplied = append(supplied, o)
		case "installed":
			e := evidence[o.Source]
			if o.Status != "complete" || e.Location != o.Fields["physical-target"]+"/package.json" || raw[o.Source] == nil {
				return ErrWire
			}
			own, err := inventory.ParseManifest(raw[o.Source])
			if err != nil {
				return ErrWire
			}
			name, ns := claimString(own.Fields, "name")
			version, vs := claimString(own.Fields, "version")
			groups, err := inventory.ProjectManifest(own)
			if err != nil || name != o.Name || version != o.Version || ns != o.Fields["name-state"] || vs != o.Fields["version-state"] || !sameOriginalGroups(groups.Groups, o.Requirements) {
				return ErrWire
			}
			used[o.Source] = true
		default:
			return ErrWire
		}
	}
	for i := range c.result.Model.Observations {
		c.result.Model.Observations[i].ID = 0
	}
	// Compare every projected row, independent of numeric ID assignment. The
	// separate public join still binds those IDs. No omitted obligation is allowed.
	a := PrivateOriginal(Result{Model: Model{Observations: supplied}})
	b := PrivateOriginal(c.result)
	rows := func(obs []Observation) []string {
		out := make([]string, len(obs))
		for i, o := range obs {
			encoded, _ := json.Marshal(o)
			out[i] = string(encoded)
		}
		sort.Strings(out)
		return out
	}
	if !slices.Equal(rows(a.Model.Observations), rows(b.Model.Observations)) || len(used) != len(raw) {
		return ErrWire
	}
	return nil
}

func sameOriginalGroups(a, b []inventory.DependencyGroup) bool {
	normalize := func(groups []inventory.DependencyGroup) []byte {
		r := PrivateOriginal(Result{Model: Model{Observations: []Observation{{Requirements: groups}}}})
		encoded, _ := json.Marshal(r.Model.Observations[0].Requirements)
		return encoded
	}
	return bytes.Equal(normalize(a), normalize(b))
}
