package projectinventory

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"strings"

	"packtrace/internal/inventory"
	"packtrace/internal/nativefs"
)

const (
	maxEntries       = 100000
	maxDepth         = 64
	maxNames         = 16 << 20
	maxRecords       = 20000
	maxLockBytes     = 64 << 20
	maxManifestBytes = 2 << 20
	maxManifestTotal = 64 << 20
)

var ErrCollection = errors.New("inventory: acquisition-unavailable")

type collector struct {
	ctx                   context.Context
	root                  *nativefs.Root
	result                Result
	metadata              nativefs.Snapshot
	entries               map[string]nativefs.Entry
	blocked               map[string]bool
	manifestRemaining     int64
	requirementsRemaining int
	classCounts           map[string]int
}

// Collect reads only governing metadata and necessary manifests from a retained
// explicit root. Neither source strings nor a lock claim create an installation.
func Collect(ctx context.Context, root *nativefs.Root, opts Options) (Result, error) {
	if ctx == nil || root == nil {
		return Result{}, ErrCollection
	}
	c := collector{ctx: ctx, root: root, entries: map[string]nativefs.Entry{}, blocked: map[string]bool{}, manifestRemaining: maxManifestTotal, requirementsRemaining: maxRecords, classCounts: map[string]int{}}
	c.result.Model.Scopes = []Scope{{ID: 1, Kind: "project", Status: "incomplete"}}
	c.result.Selection = Selection{Profile: opts.Profile, Explicit: opts.ExplicitManager, State: "indeterminate", Reason: "profile-unqualified"}
	if ctx.Err() != nil {
		return c.result, ErrCollection
	}
	snap, e := root.Metadata(ctx, nativefs.Limits{Entries: maxEntries, Depth: maxDepth})
	c.metadata = snap
	folded := map[string]string{}
	names := 0
	for _, entry := range snap.Entries {
		names += len(entry.Name)
		if names > maxNames {
			c.gap(1, 0, "name-limit")
			c.metadata.Complete = false
			c.metadata.Enumerated = false
			break
		}
		key := strings.ToLower(entry.Name)
		if old, ok := folded[key]; ok {
			c.blocked[key] = true
			c.gap(1, 0, "path-collision")
			if old == entry.Name {
				continue
			}
		}
		folded[key] = entry.Name
		c.entries[entry.Name] = entry
	}
	meta := c.evidence(1, "", "native-metadata")
	c.result.Model.Evidence[meta-1].Complete = e == nil && c.metadata.Enumerated
	if e != nil || !c.metadata.Complete {
		c.gap(1, meta, "discovery-incomplete")
	}
	if ctx.Err() != nil {
		return c.result, ErrCollection
	}
	c.collectManifest(1, "package.json")
	c.selectInputs(opts)
	if ctx.Err() != nil {
		return c.result, ErrCollection
	}
	// This stage attests selected inputs/declarations, not an installed inventory.
	return c.result, nil
}

func (c *collector) gap(scope, evidence uint32, code string) {
	if len(c.result.Model.Gaps) < 255 {
		c.result.Model.Gaps = append(c.result.Model.Gaps, Gap{scope, evidence, code})
	} else if len(c.result.Model.Gaps) == 255 {
		c.result.Model.Gaps = append(c.result.Model.Gaps, Gap{Code: "gap-list-truncated"})
	}
}
func (c *collector) evidence(scope uint32, name, method string) uint32 {
	id := uint32(len(c.result.Model.Evidence) + 1)
	c.result.Model.Evidence = append(c.result.Model.Evidence, Evidence{ID: id, Scope: scope, Location: name, Method: method})
	return id
}
func (c *collector) add(o Observation) bool {
	if c.classCounts[o.Class] >= maxRecords {
		c.gap(o.Workspace, o.Source, "record-limit")
		return false
	}
	o.ID = uint32(len(c.result.Model.Observations) + 1)
	c.result.Model.Observations = append(c.result.Model.Observations, o)
	c.classCounts[o.Class]++
	return true
}
func (c *collector) presence(name string) (string, string) {
	if c.blocked[strings.ToLower(name)] {
		return "unknown", "unsafe"
	}
	e, ok := c.entries[name]
	if !ok {
		if c.metadata.Enumerated {
			return "absent", "unqualified"
		}
		return "unknown", "unqualified"
	}
	if e.Status != nativefs.StatusComplete {
		return "unknown", "unreadable"
	}
	if e.Kind != nativefs.KindRegular {
		return "present", "unsafe"
	}
	return "present", "unqualified"
}
func (c *collector) read(scope uint32, name string, limit int64, budget *int64) ([]byte, uint32, error) {
	id := c.evidence(scope, name, "native-input-lease")
	presence, usability := c.presence(name)
	if presence != "present" || usability == "unsafe" {
		return nil, id, ErrCollection
	}
	if limit > *budget {
		limit = *budget
	}
	if limit <= 0 || c.entries[name].Size < 0 || c.entries[name].Size > limit {
		c.gap(scope, id, "byte-limit")
		return nil, id, ErrCollection
	}
	f, e := c.root.OpenInput(c.ctx, name, limit)
	if e != nil {
		return nil, id, ErrCollection
	}
	data, re := io.ReadAll(io.LimitReader(f, limit+1))
	*budget -= int64(len(data))
	se, ce := f.Stable(), f.Close()
	if re != nil || se != nil || ce != nil || int64(len(data)) > limit || c.ctx.Err() != nil {
		return nil, id, ErrCollection
	}
	ev := &c.result.Model.Evidence[id-1]
	ev.SHA256 = sha256.Sum256(data)
	ev.Complete = true
	return data, id, nil
}
func (c *collector) collectManifest(scope uint32, name string) *inventory.ManifestDocument {
	data, id, e := c.read(scope, name, maxManifestBytes, &c.manifestRemaining)
	if e != nil {
		c.gap(scope, id, "manifest-unavailable")
		return nil
	}
	doc, e := inventory.ParseManifest(data)
	if e != nil {
		c.gap(scope, id, "manifest-invalid")
		return nil
	}
	projection, e := inventory.ProjectManifest(doc)
	if e != nil {
		c.gap(scope, id, "manifest-invalid")
		return nil
	}
	for _, group := range projection.Groups {
		if group.State == inventory.FieldAbsent {
			continue
		}
		if group.State != inventory.FieldValue {
			c.gap(scope, id, "declaration-group-invalid")
			continue
		}
		for _, d := range group.Entries {
			if c.requirementsRemaining == 0 {
				c.gap(scope, id, "requirement-limit")
				return &doc
			}
			c.requirementsRemaining--
			c.add(Observation{Workspace: scope, Source: id, Class: "declared", Kind: group.Name, Status: "complete", Location: name, Name: d.Name, Requirement: d.Requirement, Fields: map[string]string{"requirement-state": fieldState(d.State)}})
			if d.State != inventory.FieldValue {
				c.gap(scope, id, "declaration-invalid")
			}
		}
	}
	return &doc
}
func fieldState(s inventory.FieldState) string {
	switch s {
	case inventory.FieldAbsent:
		return "absent"
	case inventory.FieldNull:
		return "null"
	case inventory.FieldValue:
		return "value"
	default:
		return "invalid"
	}
}
