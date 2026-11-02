package projectinventory

import (
	"context"
	"testing"
)

func TestInstalledCopiesAndExtraPackagesComeFromPhysicalManifests(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{
		"package.json":                                     `{}`,
		"package-lock.json":                                `{"lockfileVersion":3,"packages":{"":{},"node_modules/missing":{"name":"missing","version":"9.0.0"}}}`,
		"node_modules/pkg/package.json":                    `{"name":"pkg","version":"1.0.0"}`,
		"node_modules/a/package.json":                      `{"name":"a","version":"1.0.0"}`,
		"node_modules/a/node_modules/pkg/package.json":     `{"name":"pkg","version":"1.0.0"}`,
		"node_modules/extra/package.json":                  `{}`,
		"independent/node_modules/unselected/package.json": `{"name":"not-selected","version":"1.0.0"}`,
	})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil {
		t.Fatal(e)
	}
	copies := map[string]bool{}
	extra := false
	for _, o := range got.Model.Observations {
		if o.Class != "installed" {
			continue
		}
		if o.Name == "missing" || o.Name == "not-selected" {
			t.Fatal("locked or independent scope manufactured installation", o)
		}
		if o.Name == "pkg" {
			copies[o.Location] = true
		}
		if o.Location == "node_modules/extra" {
			extra = true
			if o.Name != "" || o.Version != "" {
				t.Fatal("manifest omissions inferred", o)
			}
		}
	}
	if len(copies) != 2 || !extra || got.Model.Counts().Installed != 4 {
		t.Fatalf("physical instances missing/collapsed: %+v", got)
	}
}
func TestInstalledObservationSurvivesMissingRootLock(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": `{}`, "node_modules/observed/package.json": `{"name":"observed","version":"2.0.0"}`})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil || got.Selection.State != "absent" || got.Model.Counts().Installed != 1 || got.Complete {
		t.Fatal("lock absence erased physical evidence", got, e)
	}
}
func TestOrdinaryFileAtInstalledSlotIsNotReadAsManifest(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": `{}`, "package-lock.json": emptyNPMLock, "node_modules/not-directory": "owned no content read"})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil || got.Model.Counts().Installed != 1 || got.Complete {
		t.Fatal("wrong installed slot type ignored or qualified", got, e)
	}
	for _, o := range got.Model.Observations {
		if o.Class == "installed" && o.Status != "unsupported" {
			t.Fatal("ordinary slot file granted package semantics", o)
		}
	}
}
func TestScopedInstallationSlotRetainsAliasKey(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": `{}`, "package-lock.json": emptyNPMLock, "node_modules/@scope/slot/package.json": `{"name":"actual","version":"1.0.0"}`})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil {
		t.Fatal(e)
	}
	for _, o := range got.Model.Observations {
		if o.Class == "installed" {
			if o.Name != "actual" || o.Fields["installation-name"] != "@scope/slot" {
				t.Fatal("scoped alias key/name conflated", o)
			}
			return
		}
	}
	t.Fatal("missing scoped physical slot")
}

func TestCompleteEmptyProjectInventoryScope(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": `{}`, "package-lock.json": emptyNPMLock})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil || !got.Complete || got.Model.Counts().Installed != 0 || got.Model.Counts().Locked != 1 {
		t.Fatal("known empty scope not completed precisely", got, e)
	}
}
