// Package projectinventory collects distinct project evidence through native
// capabilities. Claims never authenticate an origin or prove code execution.
package projectinventory

import "packtrace/internal/inventory"

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
	From, To, Evidence uint32
	Kind, Status       string
}
type Gap struct {
	Scope, Evidence uint32
	Code            string
}
type Model struct {
	Scopes       []Scope
	Observations []Observation
	Evidence     []Evidence
	Relations    []Relation
	Gaps         []Gap
}
type Counters struct{ Declared, Locked, Installed, Scopes, Relations, Evidence, Gaps int }
type Selection struct {
	Profile, Family, File, State, Reason string
	Explicit                             bool
}
type Result struct {
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
