package projectinventory

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

const ownedPNPMLock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      PRIVATE-a:\n        specifier: ^9\n        version: 1.0.0\npackages:\n  PRIVATE-a@1.0.0:\n    resolution: {integrity: sha512-inert}\nsnapshots:\n  PRIVATE-a@1.0.0: {}\n"

func TestPNPMSelectionAndNoInstalledAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, profile, hint, competing, state string
		explicit                              bool
	}{
		{"sole", "auto", "", "", "usable", false},
		{"explicit-auto-mixed", "auto", "pnpm@9.15.9", "package-lock.json", "indeterminate", true},
		{"hint", "auto", "pnpm@10.34.9", "", "usable", false},
		{"hint-11", "auto", "pnpm@11.28.9", "", "usable", false},
		{"mixed-11", "auto", "pnpm@11.28.9", "package-lock.json", "indeterminate", false},
		{"family", "pnpm", "", "", "usable", true},
		{"policy-isolated", "pnpm@lockfile-9", "npm@10.9.4", "", "usable", false},
		{"mixed-npm", "auto", "pnpm@9.15.9", "package-lock.json", "indeterminate", false},
		{"mixed-bun", "auto", "pnpm@10.34.9", "bun.lock", "indeterminate", false},
		{"explicit-mixed", "pnpm", "", "package-lock.json", "usable", true},
		{"invalid-hint", "auto", "pnpm@lockfile-9", "", "indeterminate", false},
		{"unknown-hint", "auto", "pnpm@12.18.0", "", "indeterminate", false},
		{"conflicting-hint", "pnpm", "npm@10.9.4", "", "indeterminate", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := `{"dependencies":{"PRIVATE-a":"^1"},"workspaces":["packages/*"]`
			if tc.hint != "" {
				manifest += `,"packageManager":"` + tc.hint + `"`
			}
			manifest += `}`
			files := map[string]string{"package.json": manifest, "pnpm-lock.yaml": ownedPNPMLock, "node_modules/PRIVATE-a/package.json": `{"name":"PRIVATE-a","version":"1.0.0"}`, "packages/PRIVATE-member/package.json": `{"dependencies":{"PRIVATE-secret":"1"}}`}
			if tc.competing != "" {
				files[tc.competing] = emptyNPMLock
			}
			root, _ := ownedProject(t, files)
			got, err := Collect(context.Background(), root, Options{Profile: tc.profile, ExplicitManager: tc.explicit})
			wantInstalled := 0
			if tc.state == "usable" {
				wantInstalled = 1
			}
			if err != nil || got.Selection.State != tc.state || got.Complete || got.Model.Counts().Installed != wantInstalled || got.Model.Counts().Declared != 1 || len(got.Model.Relations) != 0 || len(got.Model.Scopes) != 1 {
				t.Fatalf("pnpm boundary: %+v %v", got, err)
			}
			if tc.state == "usable" && (got.Selection.Family != "pnpm" || got.Model.Counts().Locked < 2) {
				t.Fatal("locked claims missing", got)
			}
			public := Portable(got)
			if ValidatePublic(public) != nil {
				t.Fatal("invalid portable inventory", public)
			}
			if public.Selection.Family == "pnpm" {
				forged := public
				forged.Complete = true
				if ValidatePublic(forged) == nil {
					t.Fatal("forged completion")
				}
				forged = public
				forged.Gaps = nil
				if ValidatePublic(forged) == nil {
					t.Fatal("missing installed gap")
				}
				forged = public
				forged.Observations = append([]PublicObservation(nil), public.Observations...)
				for i := range forged.Observations {
					if forged.Observations[i].Class == "locked" {
						forged.Observations[i].Class = "installed"
						forged.Observations[i].Kind = "directory"
						break
					}
				}
				forged.Counts = forged.counts()
				if ValidatePublic(forged) == nil {
					t.Fatal("forged installed observation")
				}
			}
		})
	}
}

func TestPNPMMandatoryGapsSurviveBudgetSaturation(t *testing.T) {
	var manifest strings.Builder
	manifest.WriteString(`{"dependencies":{`)
	for i := 0; i < 300; i++ {
		if i > 0 {
			manifest.WriteByte(',')
		}
		fmt.Fprintf(&manifest, `"PRIVATE-%d":null`, i)
	}
	manifest.WriteString(`}}`)
	root, _ := ownedProject(t, map[string]string{"package.json": manifest.String(), "pnpm-lock.yaml": ownedPNPMLock})
	got, err := Collect(context.Background(), root, Options{Profile: "pnpm", ExplicitManager: true})
	if err != nil || got.Complete || len(got.Model.Gaps) != 256 || ValidatePublic(Portable(got)) != nil {
		t.Fatalf("gap saturation became operational failure: %+v %v", got, err)
	}
}

func TestPNPMUnsupportedFormatIsInventoryGap(t *testing.T) {
	root, _ := ownedProject(t, map[string]string{"package.json": "{}", "pnpm-lock.yaml": "lockfileVersion: '8.0'\nimporters: {}\n"})
	got, err := Collect(context.Background(), root, Options{Profile: "pnpm", ExplicitManager: true})
	if err != nil || got.Selection.State != "unusable" || got.Complete || got.Model.Counts().Installed != 0 || ValidatePublic(Portable(got)) != nil {
		t.Fatal(got, err)
	}
}
