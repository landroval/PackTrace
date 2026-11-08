package projectinventory

import (
	"context"
	"testing"

	"packtrace/internal/nativefs"
)

func TestDroppedAliasRequirementKeepsLimitWitness(t *testing.T) {
	root, _ := ownedProject(t, map[string]string{"package.json": `{"name":"owned","version":"1.0.0","packageManager":"npm@10.9.4","dependencies":{"seed":"1.0.0"}}`, "package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"a":"npm:other@1.0.0"}},"node_modules/a":{"name":"a","version":"1.0.0","resolved":"https://private.invalid/a.tgz"}}}`})
	snap, e := root.Metadata(context.Background(), nativefs.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	entries := map[string]nativefs.Entry{}
	for _, entry := range snap.Entries {
		entries[entry.Name] = entry
	}
	c := collector{ctx: context.Background(), root: root, metadata: snap, entries: entries, blocked: map[string]bool{}, manifestRemaining: maxManifestTotal, requirementsRemaining: 1, classCounts: map[string]int{}}
	c.result.Model.Scopes = []Scope{{ID: 1, Kind: "project"}}
	c.collectManifest(1, "package.json")
	c.selectInputs(Options{Profile: "npm@10.9.4"}, nil)
	found, limited, droppedRoot := false, false, false
	for _, o := range c.result.Model.Observations {
		droppedRoot = droppedRoot || o.Class == "locked" && o.Kind == "project" && len(o.Requirements) == 0
		if o.Class == "locked" && o.Location == "node_modules/a" {
			found = o.Name == "a" && o.Fields["name-qualification"] == "explicit-claim"
			for _, g := range c.result.Model.Gaps {
				limited = limited || g.Code == "requirement-limit" && g.Evidence == o.Source
			}
		}
	}
	if !found || !limited || !droppedRoot {
		t.Fatal("actual collector did not retain explicit claim and lock-specific limit witness", found, limited, c.result.Model.Observations)
	}
}
