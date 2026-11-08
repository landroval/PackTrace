package projectinventory

import (
	"context"
	"encoding/json"
	"testing"

	"packtrace/internal/inventory"
)

func TestBuiltinSelectionExactHints(t *testing.T) {
	for _, hint := range []string{"npm@8.19.4", "npm@10.9.4", "npm@11.6.2", "npm@10.9.9", "npm@11.20.0", "npm@12.2.2", "bun@1.3.2", "bun@1.4.2"} {
		t.Run(hint, func(t *testing.T) {
			encoded, _ := json.Marshal(hint)
			doc, e := inventory.ParseManifest([]byte(`{"packageManager":` + string(encoded) + `}`))
			if e != nil {
				t.Fatal(e)
			}
			for _, requested := range []string{"auto", hint[:3]} {
				got := builtinSelectionOptions(Options{Profile: requested, ExplicitManager: true}, &doc, false)
				if got.Profile != hint || !SupportedSelectionProfile(got.Profile) || (requested == "auto" && got.ExplicitManager) {
					t.Fatalf("hint not resolved conservatively: %+v", got)
				}
			}
		})
	}
}

func TestBuiltinSelectionHintAbstentionAndConcreteIsolation(t *testing.T) {
	for _, raw := range []string{`null`, `42`, `{}`, `[]`, `"npm"`, `"npm@10"`, `"npm@10.9.4+sha512.abc"`, `"npm@13.0.0"`, `"npm@12.x"`, `"npm@10-11"`, `"bun@1.4.3"`, `" npm@10.9.4"`, `"npm@10.9.4 "`, `"yarn@4.0.0"`, `"npm@10.9.4\nbun@1.4.2"`} {
		t.Run(raw, func(t *testing.T) {
			doc, e := inventory.ParseManifest([]byte(`{"packageManager":` + raw + `}`))
			if e != nil {
				t.Fatal(e)
			}
			got := builtinSelectionOptions(Options{Profile: "auto"}, &doc, true)
			if got.Profile != "auto" {
				t.Fatalf("unsupported hint qualified: %+v", got)
			}
		})
	}
	doc, _ := inventory.ParseManifest([]byte(`{"packageManager":"bun@1.4.2"}`))
	if got := builtinSelectionOptions(Options{Profile: "npm"}, &doc, true); got.Profile != "npm" {
		t.Fatal("family mismatch accepted", got)
	}
	for _, profile := range []string{"npm@10.9.4", "npm@12.0.0"} {
		original := Options{Profile: profile, ExplicitManager: true}
		if got := builtinSelectionOptions(original, &doc, true); got != original {
			t.Fatal("concrete profile changed", got)
		}
	}
	if got := builtinSelectionOptions(Options{Profile: "auto"}, nil, true); got.Profile != "auto" {
		t.Fatal("missing manifest guessed", got)
	}
}

func TestBuiltinCollectionSelectionAndRetainedEvidence(t *testing.T) {
	const bunLock = `{"lockfileVersion":1,"workspaces":{"":{"name":"owned-root"}},"packages":{}}`
	for _, tt := range []struct {
		name, request, manifest, npm, shrinkwrap, bun, binary, profile, state, reason, file string
		explicit                                                                            bool
	}{
		{name: "npm-auto", request: "auto", manifest: `{"packageManager":"npm@10.9.4"}`, npm: emptyNPMLock, profile: "npm@10.9.4", state: "usable", reason: "none", file: "package-lock.json"},
		{name: "npm-family", request: "npm", manifest: `{"packageManager":"npm@11.6.2"}`, npm: emptyNPMLock, profile: "npm@11.6.2", state: "usable", reason: "none", file: "package-lock.json", explicit: true},
		{name: "bun-auto", request: "auto", manifest: `{"packageManager":"bun@1.4.2"}`, bun: bunLock, profile: "bun@1.4.2", state: "usable", reason: "none", file: "bun.lock"},
		{name: "bun-family", request: "bun", manifest: `{"packageManager":"bun@1.3.2"}`, bun: bunLock, profile: "bun@1.3.2", state: "usable", reason: "none", file: "bun.lock"},
		{name: "missing-hint", request: "auto", manifest: `{}`, npm: emptyNPMLock, profile: "npm@10-11", state: "usable", reason: "none", file: "package-lock.json"},
		{name: "npm-family-without-hint", request: "npm", manifest: `{}`, npm: emptyNPMLock, profile: "npm@10-11", state: "usable", reason: "none", file: "package-lock.json", explicit: true},
		{name: "current-lts-hint", request: "auto", manifest: `{"packageManager":"npm@11.20.0"}`, npm: emptyNPMLock, profile: "npm@11.20.0", state: "usable", reason: "none", file: "package-lock.json"},
		{name: "missing-hint-only-bun", request: "auto", manifest: `{}`, bun: bunLock, profile: "auto", state: "indeterminate", reason: "profile-unqualified"},
		{name: "missing-hint-mixed", request: "auto", manifest: `{}`, npm: emptyNPMLock, bun: bunLock, profile: "auto", state: "indeterminate", reason: "manager-conflict"},
		{name: "missing-hint-competing-npm-locks", request: "auto", manifest: `{}`, npm: emptyNPMLock, shrinkwrap: emptyNPMLock, profile: "auto", state: "indeterminate", reason: "profile-unqualified"},
		{name: "missing-hint-broken-shrinkwrap", request: "npm", manifest: `{}`, npm: emptyNPMLock, shrinkwrap: `{`, profile: "npm@10-11", state: "unusable", reason: "candidate-unusable", file: "npm-shrinkwrap.json", explicit: true},
		{name: "missing-hint-unknown-format", request: "auto", manifest: `{}`, npm: `{"lockfileVersion":99,"packages":{}}`, profile: "npm@10-11", state: "unusable", reason: "candidate-unusable", file: "package-lock.json"},
		{name: "missing-hint-no-lock", request: "auto", manifest: `{}`, profile: "auto", state: "indeterminate", reason: "profile-unqualified"},
		{name: "unsupported-hint", request: "auto", manifest: `{"packageManager":"npm@13.0.0"}`, npm: emptyNPMLock, profile: "auto", state: "indeterminate", reason: "profile-unqualified"},
		{name: "family-mismatch", request: "npm", manifest: `{"packageManager":"bun@1.4.2"}`, npm: emptyNPMLock, profile: "npm", state: "indeterminate", reason: "profile-unqualified"},
		{name: "invalid-manifest", request: "auto", manifest: `{"packageManager":"npm@10.9.4","packageManager":"bun@1.4.2"}`, npm: emptyNPMLock, profile: "auto", state: "indeterminate", reason: "profile-unqualified"},
		{name: "mixed-auto-even-explicit", request: "auto", manifest: `{"packageManager":"npm@10.9.4"}`, npm: emptyNPMLock, bun: bunLock, profile: "npm@10.9.4", state: "indeterminate", reason: "manager-conflict", explicit: true},
		{name: "broken-shrinkwrap-no-fallback", request: "auto", manifest: `{"packageManager":"npm@10.9.4"}`, npm: emptyNPMLock, shrinkwrap: `{`, profile: "npm@10.9.4", state: "unusable", reason: "candidate-unusable", file: "npm-shrinkwrap.json"},
		{name: "shrinkwrap-precedence", request: "auto", manifest: `{"packageManager":"npm@10.9.4"}`, npm: `{`, shrinkwrap: emptyNPMLock, profile: "npm@10.9.4", state: "usable", reason: "none", file: "npm-shrinkwrap.json"},
		{name: "binary-unsupported", request: "auto", manifest: `{"packageManager":"bun@1.4.2"}`, binary: "inert", profile: "bun@1.4.2", state: "unusable", reason: "binary-unsupported", file: "bun.lockb"},
		{name: "bun-conflict", request: "auto", manifest: `{"packageManager":"bun@1.4.2"}`, bun: bunLock, binary: "inert", profile: "bun@1.4.2", state: "indeterminate", reason: "conflicting-inputs"},
		{name: "no-lock", request: "auto", manifest: `{"packageManager":"npm@10.9.4"}`, profile: "npm@10.9.4", state: "absent", reason: "no-root-lock"},
		{name: "concrete-ignores-other-hint", request: "npm@10.9.4", manifest: `{"packageManager":"bun@1.4.2"}`, npm: emptyNPMLock, profile: "npm@10.9.4", state: "usable", reason: "none", file: "package-lock.json", explicit: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"package.json": tt.manifest, "node_modules/observed/package.json": `{"name":"observed","version":"1.0.0"}`}
			for file, body := range map[string]string{"package-lock.json": tt.npm, "npm-shrinkwrap.json": tt.shrinkwrap, "bun.lock": tt.bun, "bun.lockb": tt.binary} {
				if body != "" {
					files[file] = body
				}
			}
			r, _ := ownedProject(t, files)
			got, e := Collect(context.Background(), r, Options{Profile: tt.request, ExplicitManager: tt.explicit})
			s := got.Selection
			if e != nil || s.Profile != tt.profile || s.State != tt.state || s.Reason != tt.reason || s.File != tt.file || s.Explicit != tt.explicit {
				t.Fatalf("selection %+v, error %v", s, e)
			}
			if got.Model.Counts().Installed != 1 {
				t.Fatal("selection erased installed evidence")
			}
			if tt.state != "usable" && (got.Complete || len(got.Model.Gaps) == 0) {
				t.Fatal("unsupported selection lost gap")
			}
			manifestReads := 0
			for _, ev := range got.Model.Evidence {
				if ev.Location == "package.json" && ev.Method == "native-input-lease" {
					manifestReads++
				}
			}
			if manifestReads != 1 {
				t.Fatalf("root manifest reread: %d", manifestReads)
			}
			if e := ValidatePublic(Portable(got)); e != nil {
				t.Fatalf("portable evidence invalid: %v", e)
			}
		})
	}
}
