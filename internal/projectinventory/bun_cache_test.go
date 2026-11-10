//go:build linux

package projectinventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBunPairedCacheInventory(t *testing.T) {
	for _, third := range []bool{false, true} {
		t.Run(map[bool]string{false: "closed-pair", true: "unapproved-third-alias"}[third], func(t *testing.T) {
			root, target := ownedProject(t, map[string]string{
				"package.json":                `{"name":"owned","dependencies":{"a":"1.0.0"}}`,
				"bun.lock":                    `{"lockfileVersion":1,"configVersion":1,"workspaces":{"":{"name":"owned","dependencies":{"a":"1.0.0"}}},"packages":{"a":["a@1.0.0","",{},"sha512-inert"]}}`,
				"node_modules/a/package.json": `{"name":"a","version":"1.0.0"}`,
			})
			cachePath := t.TempDir()
			if err := os.Mkdir(filepath.Join(cachePath, "a@1.0.0"), 0700); err != nil {
				t.Fatal(err)
			}
			installed := filepath.Join(target, "node_modules/a/package.json")
			if err := os.Link(installed, filepath.Join(cachePath, "a@1.0.0/package.json")); err != nil {
				t.Fatal(err)
			}
			if third {
				if err := os.Link(installed, filepath.Join(t.TempDir(), "outside")); err != nil {
					t.Fatal(err)
				}
			}
			cache, err := root.OpenExternalRoot(context.Background(), cachePath)
			if err != nil {
				t.Fatal(err)
			}
			defer cache.Close()
			without, err := Collect(context.Background(), root, Options{Profile: "auto"})
			if err != nil || without.Complete {
				t.Fatal("implicit cache admission", err)
			}
			got, err := Collect(context.Background(), root, Options{Profile: "auto", BunCache: cache})
			if err != nil || got.Selection.Profile != "bun@1.2-1.4" || got.Selection.State != "usable" || ValidatePublic(PortableMatching(got)) != nil {
				t.Fatal("Bun source/closure invalid", got, err)
			}
			installedOK := false
			for _, o := range got.Model.Observations {
				installedOK = installedOK || o.Class == "installed" && o.Name == "a" && o.Version == "1.0.0" && o.Status == "complete"
			}
			if got.Complete == third || installedOK == third {
				t.Fatalf("closed-pair qualification disagrees: complete=%v installed=%v gaps=%+v", got.Complete, installedOK, got.Model.Gaps)
			}
			if f, err := root.OpenInput(context.Background(), "node_modules/a/package.json", 1024); err == nil {
				f.Close()
				t.Fatal("generic input guard weakened")
			}
		})
	}
}
