package projectinventory

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"packtrace/internal/nativefs"
)

const emptyNPMLock = `{"lockfileVersion":3,"packages":{"":{}}}`
const declaredRoot = `{"name":"owned-root","dependencies":{"owned-a":"^1"}}`

func ownedProject(t *testing.T, files map[string]string) (*nativefs.Root, string) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned supported native inventory")
	}
	root := t.TempDir()
	for name, body := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if os.MkdirAll(filepath.Dir(full), 0700) != nil || os.WriteFile(full, []byte(body), 0600) != nil {
			t.Fatal("owned fixture")
		}
	}
	r, e := nativefs.OpenRoot(context.Background(), root)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	return r, root
}

func TestInvalidShrinkwrapCannotFallBack(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": declaredRoot, "npm-shrinkwrap.json": "{", "package-lock.json": emptyNPMLock})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4", ExplicitManager: true})
	if e != nil || got.Selection.File != "npm-shrinkwrap.json" || got.Selection.State != "unusable" || got.Model.Counts().Declared != 1 || len(got.Model.Gaps) == 0 || got.Complete {
		t.Fatalf("invalid shrinkwrap replaced/hidden: %+v %v", got, e)
	}
}
func TestMissingLockStillRetainsDeclarations(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": declaredRoot})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil || got.Selection.State != "absent" || got.Model.Counts().Declared != 1 || got.Complete {
		t.Fatalf("missing lock erased manifest or completed: %+v %v", got, e)
	}
}
func TestCoexistingManagersNeedExplicitSelection(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": declaredRoot, "package-lock.json": emptyNPMLock, "bun.lock": "{}"})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil || got.Selection.State != "indeterminate" || got.Selection.Reason != "manager-conflict" || got.Complete {
		t.Fatal("mixed manager interpretation guessed", got, e)
	}
	got, e = Collect(context.Background(), r, Options{Profile: "npm@10.9.4", ExplicitManager: true})
	if e != nil || got.Selection.State != "usable" || got.Selection.File != "package-lock.json" || got.Selection.Reason != "explicit-manager-conflict" {
		t.Fatal("explicit interpretation not retained", got, e)
	}
}
func TestUsableShrinkwrapWinsAndUnknownProfileAbstains(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": declaredRoot, "npm-shrinkwrap.json": emptyNPMLock, "package-lock.json": "{invalid"})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil || got.Selection.State != "usable" || got.Selection.File != "npm-shrinkwrap.json" {
		t.Fatal("qualified precedence lost", got, e)
	}
	got, e = Collect(context.Background(), r, Options{Profile: "npm@12.1.0"})
	if e != nil || got.Selection.State != "indeterminate" || got.Selection.Reason != "profile-unqualified" || got.Model.Counts().Declared != 1 {
		t.Fatal("unknown profile gained support", got, e)
	}
}
func TestBunTextAndBinaryCoexistenceAbstains(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": declaredRoot, "bun.lock": "{}", "bun.lockb": "owned not executable"})
	got, e := Collect(context.Background(), r, Options{Profile: "bun@1.4.2", ExplicitManager: true})
	if e != nil || got.Selection.State != "indeterminate" || got.Selection.Reason != "conflicting-inputs" || got.Complete {
		t.Fatal("Bun conflict silently selected text", got, e)
	}
}
func TestInventoryCancellationCannotComplete(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": declaredRoot})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, e := Collect(ctx, r, Options{Profile: "npm@10.9.4"})
	if e == nil || got.Complete {
		t.Fatal("canceled inventory completed", got, e)
	}
}
func TestInvalidManifestRetainsFixedGap(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": `{"dependencies":{"x":"1","x":"2"}}`, "package-lock.json": emptyNPMLock})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil || len(got.Model.Gaps) == 0 || got.Complete || got.Model.Counts().Declared != 0 {
		t.Fatal("duplicate declarations accepted/hidden", got, e)
	}
}
