//go:build linux && (amd64 || arm64)

package projectinventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"packtrace/internal/nativefs"
)

func TestActiveBunLinkDoesNotActivateOrReadOrphanStore(t *testing.T) {
	r, root := ownedProject(t, map[string]string{
		"package.json": `{}`,
		"bun.lock":     `{"lockfileVersion":1,"workspaces":{"":{}},"packages":{}}`,
		"node_modules/.bun/active@1/node_modules/active/package.json": `{"name":"active","version":"1.0.0"}`,
		"node_modules/.bun/orphan@1/node_modules/orphan/package.json": `{"name":"orphan","version":"1.0.0"}`,
		"node_modules/.bun/active@1/node_modules/active/index.js":     "owned must not read source",
	})
	if os.Symlink(".bun/active@1/node_modules/active", filepath.Join(root, "node_modules/active")) != nil {
		t.Fatal("owned link")
	}
	read := watchedContent(t, filepath.Join(root, "node_modules/.bun/orphan@1/node_modules/orphan/package.json"), filepath.Join(root, "node_modules/.bun/active@1/node_modules/active/index.js"))
	got, e := Collect(context.Background(), r, Options{Profile: "bun@1.4.2"})
	if e != nil || got.Model.Counts().Installed != 1 {
		t.Fatal("active link missing or orphan counted", got, e)
	}
	for _, o := range got.Model.Observations {
		if o.Class == "installed" && (o.Name != "active" || o.Kind != "link" || o.Location != "node_modules/active") {
			t.Fatal("physical alias/store evidence conflated", o)
		}
	}
	if read() {
		t.Fatal("purpose blocker: orphan manifest or dependency source read")
	}
}
func TestActiveStoreVisitRetainsOriginalLinkWitness(t *testing.T) {
	r, root := ownedProject(t, map[string]string{"node_modules/.bun/pkg@1/node_modules/pkg/package.json": `{"name":"pkg","version":"1.0.0"}`, "node_modules/.bun/other@1/node_modules/pkg/package.json": `{"name":"other","version":"1.0.0"}`})
	link := filepath.Join(root, "node_modules/pkg")
	if os.Symlink(".bun/pkg@1/node_modules/pkg", link) != nil {
		t.Fatal("owned active link")
	}
	snap, e := r.Metadata(context.Background(), nativefs.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	entries := map[string]nativefs.Entry{}
	for _, entry := range snap.Entries {
		entries[entry.Name] = entry
	}
	c := collector{ctx: context.Background(), root: r, entries: entries, blocked: map[string]bool{}, manifestRemaining: maxManifestTotal, requirementsRemaining: maxRecords, classCounts: map[string]int{}}
	visited := false
	c.observeSlotVisiting(1, "node_modules/pkg", func(physical string, linked bool, stable func() bool) {
		visited = true
		if physical != "node_modules/.bun/pkg@1/node_modules/pkg" || !linked || !stable() {
			t.Fatal("active witness absent")
		}
		if os.Remove(link) != nil || os.Symlink(".bun/other@1/node_modules/pkg", link) != nil {
			t.Fatal("owned retarget")
		}
		if stable() {
			t.Fatal("closed/reopened link authorized former store content")
		}
	})
	if !visited || c.result.Model.Observations[0].Status != "unstable" {
		t.Fatal("retargeted active observation qualified")
	}
}

func TestWorkspaceLinkIsDistinctFromWorkspaceDeclaration(t *testing.T) {
	r, root := ownedProject(t, map[string]string{"package.json": `{"workspaces":["packages/*"]}`, "packages/member/package.json": `{"name":"member","version":"1.0.0"}`, "package-lock.json": emptyNPMLock})
	if os.Mkdir(filepath.Join(root, "node_modules"), 0700) != nil || os.Symlink("../packages/member", filepath.Join(root, "node_modules/member")) != nil {
		t.Fatal("owned workspace link")
	}
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil || got.Model.Counts().Installed != 1 || len(got.Model.Scopes) != 2 {
		t.Fatal("workspace link lost", got, e)
	}
	for _, o := range got.Model.Observations {
		if o.Class == "installed" && (o.Kind != "link" || o.Name != "member" || o.Fields["physical-target"] != "packages/member") {
			t.Fatal("workspace link attribution invented", o)
		}
	}
}
func TestEscapingActiveLinkAndHardlinkedManifestNeverReadCanary(t *testing.T) {
	for _, mode := range []string{"escape", "hardlink"} {
		t.Run(mode, func(t *testing.T) {
			r, root := ownedProject(t, map[string]string{"package.json": `{}`, "package-lock.json": emptyNPMLock})
			external := t.TempDir()
			canary := filepath.Join(external, "package.json")
			if os.WriteFile(canary, []byte(`{"name":"owned-canary","version":"1.0.0"}`), 0600) != nil || os.MkdirAll(filepath.Join(root, "node_modules"), 0700) != nil {
				t.Fatal("owned fixture")
			}
			slot := filepath.Join(root, "node_modules/pkg")
			if mode == "escape" {
				if os.Symlink(external, slot) != nil {
					t.Fatal("owned link")
				}
			} else {
				if os.Mkdir(slot, 0700) != nil || os.Link(canary, filepath.Join(slot, "package.json")) != nil {
					t.Fatal("owned hardlink")
				}
			}
			read := watchedContent(t, canary)
			got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
			if e != nil || got.Complete || got.Model.Counts().Installed != 1 || len(got.Model.Gaps) == 0 {
				t.Fatal("unsafe installed input hidden/qualified", got, e)
			}
			if read() {
				t.Fatal("purpose blocker: unrelated canary read")
			}
		})
	}
}
