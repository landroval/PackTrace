package integrityscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"packtrace/internal/integrity"
)

func mappedBundleFixture(t *testing.T) (string, string, Policy) {
	t.Helper()
	root, policy, p := bundledFixture(t, true)
	child := p.References[0]
	child.Location = "node_modules/pkg/" + ownedBundle
	child.LockKey = child.Location
	child.Name = "@scope/bundled"
	p.References = append(p.References, child)
	lockPath := filepath.Join(root, "package-lock.json")
	data, e := os.ReadFile(lockPath)
	if e != nil {
		t.Fatal(e)
	}
	var lock map[string]any
	if json.Unmarshal(data, &lock) != nil {
		t.Fatal("lock")
	}
	lock["packages"].(map[string]any)[child.Location] = map[string]any{"name": child.Name, "version": child.Version, "resolved": child.Origin, "integrity": child.ExpectedSRI, "inBundle": true}
	data, _ = json.Marshal(lock)
	if os.WriteFile(lockPath, data, 0600) != nil {
		t.Fatal("owned lock")
	}
	return root, policy, p
}

func TestExplicitNestedReferenceWinsOverBundledClaim(t *testing.T) {
	root, policy, p := mappedBundleFixture(t)
	records, _ := acquireOwned(t, root, policy, p)
	parent, nested := records[0].Assessment, records[1].Assessment
	if parent.SuppliedComparisonComplete || len(parent.Gaps) == 0 {
		t.Fatal("parent claimed separate child scope")
	}
	for _, d := range parent.Differences {
		if d.EntryID == "4" || d.EntryID == "5" || d.EntryID == "6" {
			t.Fatal("parent consumed child's published evidence")
		}
	}
	modified := false
	for _, d := range nested.Differences {
		modified = modified || d.Kind == integrity.DifferenceModified
	}
	if !modified || nested.InstanceID == parent.InstanceID {
		t.Fatal("separate child drift/identity lost", records)
	}
}

func TestBundledClaimWithoutPublishedSubtreeRemainsUnknown(t *testing.T) {
	root, policy, p := bundledFixture(t, true)
	// Keep literal inBundle:true and a real physical nested directory, but bind
	// the parent to a valid archive that publishes no nested content.
	_, otherPolicy, other := ownedFixture(t)
	data, e := os.ReadFile(filepath.Join(filepath.Dir(otherPolicy), "pkg.tgz"))
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(filepath.Join(filepath.Dir(policy), "pkg.tgz"), data, 0600) != nil {
		t.Fatal("owned archive")
	}
	old := p.References[0].ExpectedSRI
	p.References[0].ExpectedSRI = other.References[0].ExpectedSRI
	data, e = os.ReadFile(filepath.Join(root, "package-lock.json"))
	if e != nil {
		t.Fatal(e)
	}
	var lock map[string]any
	if json.Unmarshal(data, &lock) != nil {
		t.Fatal("lock")
	}
	parent := lock["packages"].(map[string]any)["node_modules/pkg"].(map[string]any)
	if parent["integrity"] != old {
		t.Fatal("fixture")
	}
	parent["integrity"] = p.References[0].ExpectedSRI
	data, _ = json.Marshal(lock)
	if os.WriteFile(filepath.Join(root, "package-lock.json"), data, 0600) != nil {
		t.Fatal("owned lock")
	}
	records, _ := acquireOwned(t, root, policy, p)
	if records[0].Assessment.SuppliedComparisonComplete || len(records[0].Assessment.Gaps) == 0 {
		t.Fatal("bare inBundle flag authorized foreign subtree")
	}
}
