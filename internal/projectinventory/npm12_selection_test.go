package projectinventory

import (
	"context"
	"testing"
)

func TestNPM12SelectionAndVersionGaps(t *testing.T) {
	for _, tt := range []struct {
		name, profile, manifest, lock, shrinkwrap, state string
		unsupported                                      bool
	}{
		{"hint-ignores-broken-shrinkwrap", "auto", `{"packageManager":"npm@12.2.2"}`, emptyNPMLock, `{broken`, "usable", false},
		{"range-ignores-broken-shrinkwrap", "npm@12.x", `{}`, emptyNPMLock, `{broken`, "usable", false},
		{"no-fallback-to-shrinkwrap", "npm@12.2.2", `{}`, `{broken`, emptyNPMLock, "unusable", false},
		{"shrinkwrap-only", "npm@12.x", `{}`, "", emptyNPMLock, "absent", false},
		{"v4-explicitly-unsupported", "auto", `{"packageManager":"npm@12.2.2"}`, `{"lockfileVersion":4,"packages":{"":{}}}`, "", "unusable", true},
		{"v2-outside-npm12-slice", "npm@12.x", `{}`, `{"lockfileVersion":2,"packages":{"":{}}}`, "", "unusable", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"package.json": tt.manifest}
			if tt.lock != "" {
				files["package-lock.json"] = tt.lock
			}
			if tt.shrinkwrap != "" {
				files["npm-shrinkwrap.json"] = tt.shrinkwrap
			}
			root, _ := ownedProject(t, files)
			got, err := Collect(context.Background(), root, Options{Profile: tt.profile})
			if err != nil || got.Selection.State != tt.state || ValidatePublic(Portable(got)) != nil {
				t.Fatalf("npm12 selection invalid: %+v gaps=%+v error=%v", got.Selection, got.Model.Gaps, err)
			}
			for _, evidence := range got.Model.Evidence {
				if evidence.Location == "npm-shrinkwrap.json" && evidence.Method == "native-input-lease" {
					t.Fatal("ignored shrinkwrap was content-read")
				}
			}
			unsupported := false
			for _, gap := range got.Model.Gaps {
				unsupported = unsupported || gap.Code == "lock-version-unsupported"
			}
			if unsupported != tt.unsupported || tt.state != "usable" && (got.Complete || got.Model.Counts().Locked != 0) {
				t.Fatal("unsupported input gained inventory or lost its explicit limitation", got)
			}
		})
	}
}
