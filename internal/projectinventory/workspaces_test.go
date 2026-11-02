package projectinventory

import (
	"context"
	"testing"
)

func TestWorkspaceDeclarationsAndLockedClaimsStayDistinct(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{
		"package.json":                 `{"workspaces":["packages/*"],"dependencies":{"root-dep":"1"}}`,
		"packages/member/package.json": `{"name":"member","version":"1.0.0","dependencies":{"member-dep":"workspace:*"}}`,
		"independent/package.json":     `{"dependencies":{"not-a-member":"1"}}`,
		"package-lock.json":            `{"lockfileVersion":3,"packages":{"":{},"packages/member":{"name":"member","version":"1.0.0"},"node_modules/alias":{"name":"actual","version":"2.0.0","resolved":"file:owned.tgz","integrity":"sha256-AAAA","optional":true,"os":["linux"],"cpu":["arm64"]}}}`,
	})
	got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
	if e != nil {
		t.Fatal(e)
	}
	if got.Model.Counts().Declared != 2 || got.Model.Counts().Locked != 3 || got.Model.Counts().Installed != 0 || len(got.Model.Scopes) != 2 {
		t.Fatalf("workspace/claim classes lost: %+v", got)
	}
	member := got.Model.Scopes[1].ID
	seen := false
	for _, o := range got.Model.Observations {
		if o.Class == "declared" && o.Name == "not-a-member" {
			t.Fatal("independent project included")
		}
		if o.Class == "declared" && o.Name == "member-dep" && o.Workspace != member {
			t.Fatal("member attribution lost")
		}
		if o.Class == "locked" && o.Location == "node_modules/alias" {
			seen = true
			if o.Name != "actual" || o.Fields["installation-name"] != "alias" || o.Fields["optional"] != "true" || o.Fields["os"] != `["linux"]` || o.Fields["cpu"] != `["arm64"]` {
				t.Fatal("alias/platform claims discarded", o)
			}
		}
	}
	if !seen {
		t.Fatal("locked alias not retained")
	}
}
func TestWorkspaceOverlapAndUnsupportedPatternsKeepGaps(t *testing.T) {
	for _, declarations := range []string{`["packages/*","packages/member"]`, `["packages/**"]`, `["../outside"]`, `["packages/missing"]`} {
		t.Run(declarations, func(t *testing.T) {
			r, _ := ownedProject(t, map[string]string{"package.json": `{"workspaces":` + declarations + `}`, "packages/member/package.json": `{"dependencies":{"x":"1"}}`, "package-lock.json": emptyNPMLock})
			got, e := Collect(context.Background(), r, Options{Profile: "npm@10.9.4"})
			if e != nil || len(got.Model.Gaps) == 0 || got.Complete {
				t.Fatal("ambiguous/unavailable member qualified", got, e)
			}
		})
	}
}
func TestBunWorkspaceClaimsDoNotReplaceManifestDeclarations(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{
		"package.json":          `{"workspaces":["apps/*"]}`,
		"apps/web/package.json": `{"name":"web","dependencies":{"from-manifest":"1"}}`,
		"bun.lock":              `{"lockfileVersion":1,"workspaces":{"":{"name":"root"},"apps/web":{"name":"web","dependencies":{"from-lock":"2"}}},"packages":{"owned":["owned@1.0.0","https://registry.example/",{},"sha512-AAAA"]}}`,
	})
	got, e := Collect(context.Background(), r, Options{Profile: "bun@1.4.2"})
	if e != nil || got.Selection.State != "usable" {
		t.Fatal(got, e)
	}
	declared, locked := false, false
	for _, o := range got.Model.Observations {
		declared = declared || o.Class == "declared" && o.Name == "from-manifest"
		locked = locked || o.Class == "locked" && o.Kind == "workspace" && o.Location == "apps/web"
		if o.Class == "declared" && o.Name == "from-lock" {
			t.Fatal("lock workspace overwritten into manifest class")
		}
	}
	if !declared || !locked || got.Model.Counts().Installed != 0 {
		t.Fatal("Bun evidence classes conflated", got)
	}
}
