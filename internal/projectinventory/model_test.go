package projectinventory

import "testing"

func TestLockedRecordNeverCreatesInstalledObservation(t *testing.T) {
	m := Model{Observations: []Observation{{ID: 1, Class: "locked", Name: "owned", Version: "1.0.0"}}}
	c := m.Counts()
	if c.Locked != 1 || c.Installed != 0 {
		t.Fatal("locked claim became installation", c)
	}
}
func TestCountsRetainDuplicatePhysicalLocations(t *testing.T) {
	m := Model{Observations: []Observation{
		{ID: 1, Class: "installed", Name: "owned", Version: "1.0.0", Location: "node_modules/owned"},
		{ID: 2, Class: "installed", Name: "owned", Version: "1.0.0", Location: "node_modules/a/node_modules/owned"},
	}}
	if m.Counts().Installed != 2 {
		t.Fatal("distinct physical copies collapsed")
	}
}
func TestCountsKeepSourceAndScopeNamespaces(t *testing.T) {
	m := Model{Scopes: []Scope{{ID: 1}}, Evidence: []Evidence{{ID: 1, Scope: 1}}, Relations: []Relation{{From: 1, To: 2, Evidence: 1}}, Gaps: []Gap{{Scope: 1, Evidence: 1}}}
	c := m.Counts()
	if c.Scopes != 1 || c.Evidence != 1 || c.Relations != 1 || c.Gaps != 1 || c.Installed != 0 {
		t.Fatal("evidence counts lost", c)
	}
}
