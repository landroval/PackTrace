//go:build linux && (amd64 || arm64)

package projectinventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
