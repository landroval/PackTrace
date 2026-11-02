package projectinventory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestPortableInventoryHasNoPrivateMetadata(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": `{"dependencies":{"PRIVATE-dep":"PRIVATE-range"}}`, "package-lock.json": `{"lockfileVersion":3,"packages":{"":{},"node_modules/PRIVATE-pkg":{"name":"PRIVATE-pkg","version":"PRIVATE-version","resolved":"https://PRIVATE-origin/","integrity":"PRIVATE-digest"}}}`, "node_modules/PRIVATE-pkg/package.json": `{"name":"PRIVATE-pkg","version":"PRIVATE-version"}`})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil {
		t.Fatal(e)
	}
	p := Portable(got)
	if e := ValidatePublic(p); e != nil {
		t.Fatal("real inventory rejected", e)
	}
	data, e := json.Marshal(p)
	if e != nil || strings.Contains(string(data), "PRIVATE") {
		t.Fatal("private inventory leaked")
	}
	if p.Counts.Installed != 1 || p.Counts.Locked != 2 || p.Counts.Declared != 1 {
		t.Fatal("evidence classes lost", p.Counts)
	}
}
func TestPublicInventoryRejectsForgedCompletionsAndReferences(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": `{}`, "package-lock.json": emptyNPMLock, "node_modules/pkg/package.json": `{"name":"pkg","version":"1.0.0"}`})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil {
		t.Fatal(e)
	}
	good := Portable(got)
	for _, mutate := range []func(*PublicInventory){
		func(p *PublicInventory) { p.Counts.Installed++ },
		func(p *PublicInventory) { p.Observations[0].ID = 0 },
		func(p *PublicInventory) { p.Observations[0].Source = 9999 },
		func(p *PublicInventory) { p.Observations[0].Class = "PRIVATE-unknown" },
		func(p *PublicInventory) { p.Scopes[0].Parent = p.Scopes[0].ID },
		func(p *PublicInventory) {
			p.Gaps = append(p.Gaps, Gap{Scope: 1, Code: "manifest-invalid"})
			p.Counts.Gaps++
			p.Complete = true
		},
	} {
		b, _ := json.Marshal(good)
		var p PublicInventory
		_ = json.Unmarshal(b, &p)
		mutate(&p)
		if ValidatePublic(p) == nil {
			t.Fatal("forged inventory accepted")
		}
	}
}
func TestInventoryAccumulatorRejectsMixedOrReorderedArrays(t *testing.T) {
	p := PublicInventory{}
	if AppendBatch(&p, InventoryBatch{Scopes: []PublicScope{{ID: 1, Kind: "project", Status: "complete"}}}) != nil {
		t.Fatal("scope prefix")
	}
	if AppendBatch(&p, InventoryBatch{Evidence: []PublicEvidence{{ID: 1, Scope: 1, Method: "native-metadata", Status: "complete"}}, Gaps: []Gap{{Scope: 1, Code: "manifest-invalid"}}}) == nil {
		t.Fatal("mixed batch accepted")
	}
	if AppendBatch(&p, InventoryBatch{Evidence: []PublicEvidence{{ID: 1, Scope: 1, Method: "native-metadata", Status: "complete"}}}) != nil {
		t.Fatal("evidence prefix")
	}
	if AppendBatch(&p, InventoryBatch{Scopes: []PublicScope{{ID: 2, Kind: "workspace", Parent: 1, Status: "complete"}}}) == nil {
		t.Fatal("reordered scope accepted")
	}
}

func TestInventoryBatchStreamPreservesClosureCounts(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": `{}`, "package-lock.json": emptyNPMLock, "node_modules/pkg/package.json": `{"name":"pkg","version":"1.0.0"}`})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil {
		t.Fatal(e)
	}
	p := Portable(got)
	counts := Counters{}
	sequence := uint32(0)
	e = WalkBatches(p, func(b InventoryBatch) error {
		if b.Sequence != sequence {
			t.Fatal("sequence")
		}
		sequence++
		raw, _ := json.Marshal(b)
		if len(raw) > 1<<20 {
			t.Fatal("frame cap")
		}
		counts.Scopes += len(b.Scopes)
		counts.Evidence += len(b.Evidence)
		counts.Relations += len(b.Relations)
		counts.Gaps += len(b.Gaps)
		for _, o := range b.Observations {
			switch o.Class {
			case "declared":
				counts.Declared++
			case "locked":
				counts.Locked++
			case "installed":
				counts.Installed++
			}
		}
		return nil
	})
	if e != nil || sequence == 0 || counts != p.Counts {
		t.Fatal("batched data/closure counts diverged", counts, p.Counts, e)
	}
}
