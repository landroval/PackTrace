package projectinventory

import (
	"context"
	"strings"
	"testing"

	"packtrace/internal/nativefs"
)

func TestInvalidVariantTypesRemainUnqualified(t *testing.T) {
	for _, field := range []string{`"optional":"true"`, `"inBundle":1`, `"os":"linux"`, `"cpu":[1]`, `"link":null`} {
		t.Run(field, func(t *testing.T) {
			r, _ := ownedProject(t, map[string]string{"package.json": `{}`, "package-lock.json": `{"lockfileVersion":3,"packages":{"":{},"node_modules/pkg":{"name":"pkg","version":"1.0.0",` + field + `}}}`})
			got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
			if e != nil || got.Model.Counts().Locked != 2 {
				t.Fatal("variant erased siblings", got, e)
			}
			invalid := false
			for _, g := range got.Model.Gaps {
				invalid = invalid || g.Code == "variant-invalid"
			}
			if !invalid {
				t.Fatal("wrong variant type silently qualified", field, got.Model.Gaps)
			}
		})
	}
}
func TestLockedAndDeclaredRequirementBudgetsAreShared(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": declaredRoot, "package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"a":"1"}},"node_modules/pkg":{"dependencies":{"b":"1"}}}}`})
	snap, e := r.Metadata(context.Background(), nativefs.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	entries := map[string]nativefs.Entry{}
	for _, entry := range snap.Entries {
		entries[entry.Name] = entry
	}
	c := collector{ctx: context.Background(), root: r, metadata: snap, entries: entries, blocked: map[string]bool{}, manifestRemaining: maxManifestTotal, requirementsRemaining: 1, classCounts: map[string]int{}}
	c.result.Model.Scopes = []Scope{{ID: 1, Kind: "project"}}
	c.collectManifest(1, "package.json")
	c.selectInputs(Options{Profile: "npm@10.9.4"})
	limited := false
	for _, g := range c.result.Model.Gaps {
		limited = limited || strings.Contains(g.Code, "requirement-limit")
	}
	if !limited {
		t.Fatal("requirement allowance reset at lock boundary")
	}
}
