package projectinventory

import (
	"context"
	"strings"
	"testing"

	"packtrace/internal/nativefs"
)

func TestBunConfigVersionIsIndependentlyQualified(t *testing.T) {
	for _, value := range []string{"null", " null ", "\"1\"", "1.0", "2", "-1"} {
		t.Run(value, func(t *testing.T) {
			r, _ := ownedProject(t, map[string]string{"package.json": declaredRoot, "bun.lock": `{"lockfileVersion":1,"configVersion":` + value + `,"workspaces":{"":{}},"packages":{}}`})
			got, e := Collect(context.Background(), r, Options{Profile: "bun@1.4.2"})
			if e != nil || got.Selection.State != "unusable" || got.Complete {
				t.Fatal("configVersion gained implied compatibility", got, e)
			}
		})
	}
}
func TestPartialManifestBudgetNeverProducesCompleteDigest(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": declaredRoot})
	snap, e := r.Metadata(context.Background(), nativefs.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	c := collector{ctx: context.Background(), root: r, metadata: snap, entries: map[string]nativefs.Entry{}, blocked: map[string]bool{}}
	for _, entry := range snap.Entries {
		c.entries[entry.Name] = entry
	}
	budget := int64(3)
	data, id, e := c.read(1, "package.json", maxManifestBytes, &budget)
	if e == nil || data != nil || id == 0 || c.result.Model.Evidence[id-1].Complete || c.result.Model.Evidence[id-1].SHA256 != [32]byte{} {
		t.Fatal("over-budget file obtained a full digest")
	}
}
func TestOversizedManifestKeepsOtherSourceSelection(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": strings.Repeat(" ", maxManifestBytes+1), "package-lock.json": emptyNPMLock})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil || got.Selection.State != "usable" || got.Complete || len(got.Model.Gaps) == 0 {
		t.Fatal("manifest limit erased lock selection or completed", got, e)
	}
}
