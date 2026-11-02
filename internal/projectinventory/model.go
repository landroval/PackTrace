// Package projectinventory collects distinct project evidence through native
// capabilities. Claims never authenticate an origin or prove code execution.
package projectinventory

import (
	"packtrace/internal/inventory"
	"packtrace/internal/nativefs"
)

type Options struct {
	Profile         string
	ExplicitManager bool
}

type Observation struct {
	ID, Workspace, Source                        uint32
	Class, Kind, Status                          string
	Location, Name, Version, Origin, Requirement string
	Fields                                       map[string]string
	Requirements                                 []inventory.DependencyGroup
}
type Scope struct {
	ID, Parent             uint32
	Location, Kind, Status string
}
type Evidence struct {
	ID, Scope        uint32
	Location, Method string
	SHA256           [32]byte
	Complete         bool
}

// Relation endpoints are observation IDs, except physical-link.To which is a
// manifest evidence ID. not-observed uses To=0 and complete enumeration evidence.
// Kind is the closed discriminator; consumers must not mix ID namespaces.
type Relation struct {
	From     uint32 `json:"from"`
	To       uint32 `json:"to"`
	Evidence uint32 `json:"evidence"`
	Kind     string `json:"kind"`
	Status   string `json:"status"`
}
type Gap struct {
	Scope    uint32 `json:"scope"`
	Evidence uint32 `json:"evidence"`
	Code     string `json:"code"`
}
type Model struct {
	Scopes       []Scope
	Observations []Observation
	Evidence     []Evidence
	Relations    []Relation
	Gaps         []Gap
}
type Counters struct {
	Declared  int `json:"declared"`
	Locked    int `json:"locked"`
	Installed int `json:"installed"`
	Scopes    int `json:"scopes"`
	Relations int `json:"relations"`
	Evidence  int `json:"evidence"`
	Gaps      int `json:"gaps"`
}
type Selection struct {
	Profile, Family, File, State, Reason string
	Explicit                             bool
}
type Result struct {
	// Metadata is the same live discovery used by collection, never an IPC value.
	Metadata  nativefs.Snapshot `json:"-"`
	Model     Model
	Selection Selection
	Complete  bool
}

func (m Model) Counts() Counters {
	c := Counters{Scopes: len(m.Scopes), Evidence: len(m.Evidence), Relations: len(m.Relations), Gaps: len(m.Gaps)}
	for _, o := range m.Observations {
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
