package projectinventory

import (
	"context"
	"testing"
)

func TestExpandedManagerSelectionKeepsFormatAndHintBoundaries(t *testing.T) {
	for _, tt := range []struct{ name, profile, manifest, lock, file, state string }{
		{"npm7-hint", "auto", `{"packageManager":"npm@7.24.2"}`, emptyNPMLock, "package-lock.json", "usable"},
		{"npm8-hint", "auto", `{"packageManager":"npm@8.0.0"}`, emptyNPMLock, "package-lock.json", "usable"},
		{"npm9-policy", "npm@9.9.4", `{}`, emptyNPMLock, "package-lock.json", "usable"},
		{"npm-family-policy", "npm@7-11", `{}`, emptyNPMLock, "package-lock.json", "usable"},
		{"npm-alias-not-hint", "auto", `{"packageManager":"npm@7-11"}`, emptyNPMLock, "package-lock.json", "indeterminate"},
		{"npm12-v2-refused", "npm@12.x", `{}`, `{"lockfileVersion":2,"packages":{"":{}}}`, "package-lock.json", "unusable"},
		{"npm-v1-refused", "npm@7.24.2", `{}`, `{"lockfileVersion":1,"dependencies":{}}`, "package-lock.json", "unusable"},
		{"bun12-hint", "auto", `{"packageManager":"bun@1.2.23"}`, `{"lockfileVersion":0,"workspaces":{"":{}},"packages":{}}`, "bun.lock", "usable"},
		{"bun12-v2-refused", "bun@1.2.x", `{}`, `{"lockfileVersion":2,"workspaces":{"":{}},"packages":{}}`, "bun.lock", "unusable"},
		{"bun14-family-v2", "bun@1.4.x", `{}`, `{"lockfileVersion":2,"workspaces":{"":{}},"packages":{}}`, "bun.lock", "usable"},
		{"bun14-hint-v2", "auto", `{"packageManager":"bun@1.4.3"}`, `{"lockfileVersion":2,"workspaces":{"":{}},"packages":{}}`, "bun.lock", "usable"},
		{"bun-auto-v2", "auto", `{}`, `{"lockfileVersion":2,"workspaces":{"":{}},"packages":{}}`, "bun.lock", "usable"},
		{"bun-alias-not-hint", "auto", `{"packageManager":"bun@1.4.x"}`, `{"lockfileVersion":2,"workspaces":{"":{}},"packages":{}}`, "bun.lock", "indeterminate"},
		{"bun-range-not-hint", "auto", `{"packageManager":"bun@1.2-1.4"}`, `{"lockfileVersion":1,"workspaces":{"":{}},"packages":{}}`, "bun.lock", "indeterminate"},
		{"bun-config2-refused", "bun@1.4.x", `{}`, `{"lockfileVersion":2,"configVersion":2,"workspaces":{"":{}},"packages":{}}`, "bun.lock", "unusable"},
		{"binary-refused", "bun@1.2.x", `{}`, "inert", "bun.lockb", "unusable"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root, _ := ownedProject(t, map[string]string{"package.json": tt.manifest, tt.file: tt.lock})
			got, e := Collect(context.Background(), root, Options{Profile: tt.profile})
			if e != nil || got.Selection.State != tt.state || ValidatePublic(Portable(got)) != nil {
				t.Fatalf("selection %+v gaps=%+v err=%v", got.Selection, got.Model.Gaps, e)
			}
			if tt.state != "usable" && got.Complete {
				t.Fatal("unsupported input became complete")
			}
		})
	}
}
