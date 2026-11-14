package projectinventory

import (
	"context"
	"testing"
)

func TestPNPMReviewUnsupportedImporterAndRootFeaturesAreVisible(t *testing.T) {
	for _, body := range []string{
		"importers:\n  .:\n    dependencies:\n      local:\n        specifier: workspace:*\n        version: link:../local\n",
		"importers:\n  .:\n    peerDependencies:\n      local:\n        specifier: '*'\n        version: link:../local\n",
		"importers: {.: {}}\npatchedDependencies: {'a@1.0.0': {path: patches/a.patch, hash: abc}}\npackages: {a@1.0.0: {}}\n",
		"importers: {}\npatchedDependencies: {'a@1.0.0': {path: patches/a.patch, hash: abc}}\n",
	} {
		root, _ := ownedProject(t, map[string]string{"package.json": "{}", "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" + body})
		got, err := Collect(context.Background(), root, Options{Profile: "pnpm", ExplicitManager: true})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, gap := range got.Model.Gaps {
			if gap.Code == "locked-tuple-unsupported" {
				found = true
			}
		}
		if !found {
			t.Fatalf("unsupported pnpm source/feature vanished: %+v", got.Model.Gaps)
		}
		if ValidatePublic(Portable(got)) != nil {
			t.Fatal("new gap broke parent validation")
		}
	}
}

func TestPNPMReviewParentRequiresWorkspaceGap(t *testing.T) {
	root, _ := ownedProject(t, map[string]string{"package.json": "{}", "pnpm-lock.yaml": ownedPNPMLock})
	result, err := Collect(context.Background(), root, Options{Profile: "pnpm", ExplicitManager: true})
	if err != nil {
		t.Fatal(err)
	}
	forged := Portable(result)
	gaps := make([]Gap, 0, len(forged.Gaps))
	for _, g := range forged.Gaps {
		if g.Code != "pnpm-workspaces-unsupported" {
			gaps = append(gaps, g)
		}
	}
	forged.Gaps = gaps
	forged.Counts = forged.counts()
	if ValidatePublic(forged) == nil {
		t.Fatal("parent accepted dropped workspace coverage gap")
	}
}
