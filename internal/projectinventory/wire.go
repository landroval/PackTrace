package projectinventory

import (
	"encoding/json"
	"errors"
	"slices"
)

var ErrWire = errors.New("inventory: invalid-public-data")

type PublicObservation struct {
	ID        uint32 `json:"id"`
	Workspace uint32 `json:"scope"`
	Source    uint32 `json:"evidence"`
	Class     string `json:"class"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
}
type PublicScope struct {
	ID     uint32 `json:"id"`
	Parent uint32 `json:"parent"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
}
type PublicEvidence struct {
	ID     uint32 `json:"id"`
	Scope  uint32 `json:"scope"`
	Method string `json:"method"`
	Status string `json:"status"`
}
type PublicSelection struct {
	Family   string `json:"family"`
	State    string `json:"state"`
	Reason   string `json:"reason"`
	Explicit bool   `json:"explicit"`
}
type InventoryBatch struct {
	Sequence     uint32              `json:"sequence"`
	Scopes       []PublicScope       `json:"scopes,omitempty"`
	Evidence     []PublicEvidence    `json:"evidence,omitempty"`
	Observations []PublicObservation `json:"observations,omitempty"`
	Relations    []Relation          `json:"relations,omitempty"`
	Gaps         []Gap               `json:"gaps,omitempty"`
}
type PublicInventory struct {
	Scopes       []PublicScope       `json:"scopes"`
	Evidence     []PublicEvidence    `json:"evidence"`
	Observations []PublicObservation `json:"observations"`
	Relations    []Relation          `json:"relations"`
	Gaps         []Gap               `json:"gaps"`
	Selection    PublicSelection     `json:"selection"`
	Counts       Counters            `json:"counts"`
	Complete     bool                `json:"complete"`
}

func allowed(s string, values ...string) bool { return slices.Contains(values, s) }
func safeLabel(s string, values ...string) string {
	if allowed(s, values...) {
		return s
	}
	return "unknown"
}
func Portable(r Result) PublicInventory {
	p := PublicInventory{Scopes: []PublicScope{}, Evidence: []PublicEvidence{}, Observations: []PublicObservation{}, Relations: []Relation{}, Gaps: []Gap{}, Complete: r.Complete}
	p.Selection = PublicSelection{Family: safeLabel(r.Selection.Family, "npm", "bun"), State: safeLabel(r.Selection.State, "usable", "unusable", "absent", "indeterminate"), Reason: safeLabel(r.Selection.Reason, selectionReasons...), Explicit: r.Selection.Explicit}
	for _, s := range r.Model.Scopes {
		p.Scopes = append(p.Scopes, PublicScope{ID: s.ID, Parent: s.Parent, Kind: safeLabel(s.Kind, "project", "workspace"), Status: safeLabel(s.Status, "complete", "incomplete")})
	}
	for _, e := range r.Model.Evidence {
		status := "incomplete"
		if e.Complete {
			status = "complete"
		}
		p.Evidence = append(p.Evidence, PublicEvidence{ID: e.ID, Scope: e.Scope, Method: safeLabel(e.Method, evidenceMethods...), Status: status})
	}
	for _, o := range r.Model.Observations {
		p.Observations = append(p.Observations, PublicObservation{ID: o.ID, Workspace: o.Workspace, Source: o.Source, Class: safeLabel(o.Class, "declared", "locked", "installed"), Kind: safeLabel(o.Kind, observationKinds...), Status: safeLabel(o.Status, "complete", "unreadable", "unstable", "unsupported")})
	}
	for _, x := range r.Model.Relations {
		x.Kind = safeLabel(x.Kind, "declared-requirement", "locked-correspondence", "candidate-correspondence", "physical-link")
		x.Status = safeLabel(x.Status, "recorded-agreement", "claim-agreement", "conflict", "indeterminate", "not-observed", "contained")
		p.Relations = append(p.Relations, x)
	}
	for _, g := range r.Model.Gaps {
		g.Code = safeLabel(g.Code, gapCodes...)
		p.Gaps = append(p.Gaps, g)
	}
	p.Counts = p.counts()
	return p
}
func (p PublicInventory) counts() Counters {
	c := Counters{Scopes: len(p.Scopes), Evidence: len(p.Evidence), Relations: len(p.Relations), Gaps: len(p.Gaps)}
	for _, o := range p.Observations {
		switch o.Class {
		case "declared":
			c.Declared++
		case "locked":
			c.Locked++
		case "installed":
			c.Installed++
		}
	}
	return c
}

var selectionReasons = []string{"none", "manager-conflict", "profile-unqualified", "no-root-lock", "candidate-unusable", "shrinkwrap-presence-unknown", "package-lock-presence-unknown", "usability-unqualified", "conflicting-inputs", "binary-unsupported", "text-presence-unknown", "binary-presence-unknown", "explicit-manager-conflict"}
var evidenceMethods = []string{"native-metadata", "native-input-lease", "native-metadata-lease", "unreferenced-store-metadata"}
var observationKinds = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "unknown", "package", "project", "workspace", "link", "file", "git", "github", "url", "tarball", "folder", "directory", "slot-file"}
var gapCodes = []string{"name-limit", "path-collision", "discovery-incomplete", "record-limit", "byte-limit", "manifest-unavailable", "manifest-invalid", "declaration-group-invalid", "requirement-limit", "declaration-invalid", "gap-list-truncated", "variant-invalid", "locked-tuple-unsupported", "workspace-declarations-invalid", "workspace-limit", "workspace-pattern-unsupported", "workspace-unavailable", "workspace-overlap", "locked-requirements-invalid", "locked-requirement-invalid", "installed-slot-unavailable", "installed-binding-unstable", "link-depth-limit", "link-boundary", "link-target-unavailable", "installed-slot-type", "installed-manifest-unavailable", "installed-manifest-invalid", "installed-identity-invalid", "selection-indeterminate", "selection-invalid", "selection-unusable", "selection-absent", "lock-unreadable", "lock-invalid", "config-version-unsupported", "locked-projection-invalid", "relation-limit", "execution-incomplete"}

// WalkBatches only serializes bounded, homogeneous portable fragments. Even a
// maximum inventory is never marshaled as one IPC frame.
func WalkBatches(p PublicInventory, emit func(InventoryBatch) error) error {
	if emit == nil || ValidatePublic(p) != nil {
		return ErrWire
	}
	sequence := uint32(0)
	sizes := []int{len(p.Scopes), len(p.Evidence), len(p.Observations), len(p.Relations), len(p.Gaps)}
	for kind, size := range sizes {
		for from := 0; from < size; from += 128 {
			end := min(from+128, size)
			b := InventoryBatch{Sequence: sequence}
			switch kind {
			case 0:
				b.Scopes = p.Scopes[from:end]
			case 1:
				b.Evidence = p.Evidence[from:end]
			case 2:
				b.Observations = p.Observations[from:end]
			case 3:
				b.Relations = p.Relations[from:end]
			case 4:
				b.Gaps = p.Gaps[from:end]
			}
			raw, e := json.Marshal(b)
			if e != nil || len(raw) > (1<<20)-4096 {
				return ErrWire
			}
			if e = emit(b); e != nil {
				return e
			}
			sequence++
		}
	}
	return nil
}
