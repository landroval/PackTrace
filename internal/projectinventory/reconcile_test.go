package projectinventory

import (
	"reflect"
	"testing"

	"packtrace/internal/inventory"
)

func TestReconciliationRetainsVersionConflictAndDuplicateCopies(t *testing.T) {
	m := Model{Scopes: []Scope{{ID: 1, Kind: "project", Status: "complete"}}, Evidence: []Evidence{{ID: 1, Scope: 1, Method: "native-metadata", Complete: true}}, Observations: []Observation{
		{ID: 1, Class: "declared", Workspace: 1, Source: 1, Kind: "dependencies", Name: "pkg", Requirement: "^1", Fields: map[string]string{"requirement-state": "value"}},
		{ID: 2, Class: "locked", Workspace: 1, Source: 1, Kind: "project", Requirements: []inventory.DependencyGroup{{Name: "dependencies", State: inventory.FieldValue, Entries: []inventory.DeclaredDependency{{Name: "pkg", Requirement: "^1", State: inventory.FieldValue}}}}},
		{ID: 3, Class: "locked", Workspace: 1, Source: 1, Location: "node_modules/pkg", Name: "pkg", Version: "1.0.0"},
		{ID: 4, Class: "installed", Workspace: 1, Source: 1, Status: "complete", Location: "node_modules/pkg", Name: "pkg", Version: "2.0.0"},
		{ID: 5, Class: "installed", Workspace: 1, Source: 1, Status: "complete", Location: "node_modules/a/node_modules/pkg", Name: "pkg", Version: "1.0.0"},
	}}
	original := append([]Observation(nil), m.Observations...)
	got := Reconcile(m)
	if !reflect.DeepEqual(got.Observations, original) || got.Counts().Installed != 2 {
		t.Fatal("evidence overwritten/merged", got)
	}
	declaration, conflict := false, false
	for _, r := range got.Relations {
		declaration = declaration || r.Kind == "declared-requirement" && r.From == 1 && r.To == 2 && r.Status == "recorded-agreement"
		conflict = conflict || r.Kind == "locked-correspondence" && r.From == 3 && r.To == 4 && r.Status == "conflict"
		if r.Kind == "locked-correspondence" && r.From == 3 && r.To == 5 {
			t.Fatal("same identity overrode physical locator")
		}
	}
	if !declaration || !conflict {
		t.Fatal("evidence relations lost", got.Relations)
	}
	if !reflect.DeepEqual(Reconcile(got).Relations, got.Relations) {
		t.Fatal("reconciliation duplicated relations")
	}
}
func TestRootDeclarationDoesNotBorrowUnselectedWorkspaceRequirements(t *testing.T) {
	groups := func(value string) []inventory.DependencyGroup {
		return []inventory.DependencyGroup{{Name: "dependencies", State: inventory.FieldValue, Entries: []inventory.DeclaredDependency{{Name: "pkg", Requirement: value, State: inventory.FieldValue}}}}
	}
	m := Model{Scopes: []Scope{{ID: 1, Kind: "project", Location: "", Status: "complete"}}, Observations: []Observation{
		{ID: 1, Class: "declared", Kind: "dependencies", Workspace: 1, Name: "pkg", Requirement: "^1", Fields: map[string]string{"requirement-state": "value"}},
		{ID: 2, Class: "locked", Kind: "workspace", Workspace: 1, Location: "", Requirements: groups("^1")},
		{ID: 3, Class: "locked", Kind: "workspace", Workspace: 1, Location: "packages/unselected", Requirements: groups("^9")},
	}}
	got := Reconcile(m)
	if len(got.Relations) != 1 || got.Relations[0].To != 2 {
		t.Fatal("foreign workspace attributed to root declaration", got.Relations)
	}
}

func TestBunIdentityCorrelationNeverBecomesResolution(t *testing.T) {
	m := Model{Observations: []Observation{{ID: 1, Class: "locked", Name: "pkg", Version: "1.0.0", Fields: map[string]string{"tuple-key": "pkg"}}, {ID: 2, Class: "installed", Name: "pkg", Version: "1.0.0", Location: "node_modules/alias"}}}
	got := Reconcile(m)
	if len(got.Relations) != 1 || got.Relations[0].Kind != "candidate-correspondence" || got.Relations[0].Status != "indeterminate" {
		t.Fatal("name/version gained actual resolution/origin", got.Relations)
	}
}
func TestUnobservedOptionalStaysLockedOnly(t *testing.T) {
	m := Model{Evidence: []Evidence{{ID: 1, Scope: 1, Method: "native-metadata", Complete: true}}, Observations: []Observation{{ID: 1, Class: "locked", Workspace: 1, Location: "node_modules/optional", Fields: map[string]string{"optional": "true"}}}}
	got := Reconcile(m)
	if got.Counts().Installed != 0 || len(got.Relations) != 1 || got.Relations[0].Status != "not-observed" || got.Relations[0].To != 0 {
		t.Fatal("optional absence became installation or inferred harmlessness", got)
	}
	m.Evidence[0].Complete = false
	got = Reconcile(m)
	if len(got.Relations) != 0 {
		t.Fatal("incomplete enumeration claimed absence", got.Relations)
	}
}
func TestCandidateRelationBudgetIsBoundedAndIdempotent(t *testing.T) {
	m := Model{Observations: []Observation{{ID: 1, Class: "locked", Name: "pkg", Version: "1", Fields: map[string]string{"tuple-key": "first"}}, {ID: 2, Class: "locked", Name: "pkg", Version: "1", Fields: map[string]string{"tuple-key": "second"}}}}
	for i := 0; i < maxRecords/2+1; i++ {
		m.Observations = append(m.Observations, Observation{ID: uint32(i + 3), Class: "installed", Name: "pkg", Version: "1", Location: "owned-candidate"})
	}
	got := Reconcile(m)
	if len(got.Relations) != maxRecords || len(got.Gaps) != 1 || got.Gaps[0].Code != "relation-limit" {
		t.Fatal("candidate Cartesian expansion escaped bound", len(got.Relations), got.Gaps)
	}
	again := Reconcile(got)
	if len(again.Relations) != maxRecords || len(again.Gaps) != 1 {
		t.Fatal("reconciliation duplicated limit evidence", len(again.Relations), again.Gaps)
	}
}

func TestPhysicalLinkRelationUsesEvidenceEndpoint(t *testing.T) {
	m := Model{Evidence: []Evidence{{ID: 1, Method: "native-metadata-lease", Complete: true}, {ID: 2, Method: "native-input-lease", Complete: true}}, Observations: []Observation{{ID: 1, Class: "installed", Kind: "link", Source: 2, Status: "complete", Fields: map[string]string{"metadata-evidence": "1", "physical-target": "packages/member"}}}}
	got := Reconcile(m)
	if len(got.Relations) != 1 || got.Relations[0].From != 1 || got.Relations[0].To != 2 || got.Relations[0].Evidence != 1 || got.Relations[0].Kind != "physical-link" {
		t.Fatal("physical link/evidence namespaces lost", got.Relations)
	}
}
