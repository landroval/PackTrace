//go:build linux && (amd64 || arm64)

package projectinventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPNPMReviewNestedOrphanActivation(t *testing.T) {
	r, root := ownedProject(t, map[string]string{
		"package.json": "{}", "pnpm-lock.yaml": ownedPNPMLock,
		"node_modules/.pnpm/orphan/node_modules/pkg/node_modules/.pnpm/inner/node_modules/a/package.json": `{"name":"a","version":"1.0.0"}`,
		"node_modules/.pnpm/orphan/node_modules/pkg/node_modules/.pnpm/inner/node_modules/b/package.json": `{"name":"b","version":"1.0.0"}`,
	})
	if os.Symlink(".pnpm/orphan/node_modules/pkg/node_modules/.pnpm/inner/node_modules/a", filepath.Join(root, "node_modules/a")) != nil {
		t.Fatal("owned nested link")
	}
	read := watchedContent(t, filepath.Join(root, "node_modules/.pnpm/orphan/node_modules/pkg/node_modules/.pnpm/inner/node_modules/b/package.json"))
	got, err := Collect(context.Background(), r, Options{Profile: "pnpm", ExplicitManager: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Model.Counts().Installed != 1 || read() {
		t.Fatal("nested orphan sibling activated", got.Model.Counts())
	}
}

func TestPNPMReviewDiscardedLinksDoNotConsumeCandidateLimit(t *testing.T) {
	m := Model{Evidence: []Evidence{{ID: 1, Complete: true}}}
	m.Observations = append(m.Observations, Observation{ID: 1, Class: "locked", Kind: "package", Status: "complete", Name: "a", Version: "1", Fields: map[string]string{"tuple-key": "a"}})
	for i := 0; i < maxRecords; i++ {
		m.Observations = append(m.Observations, Observation{ID: uint32(i + 2), Class: "installed", Kind: "link", Status: "complete", Name: "a", Version: "2", Source: 1, Fields: map[string]string{"physical-target": "x", "metadata-evidence": "1"}})
	}
	m.Observations[1].Version = "1"
	got := reconcilePNPM(m)
	if len(got.Relations) != 1 || len(got.Gaps) != 0 {
		t.Fatal("discarded physical links charged candidate budget", len(got.Relations), got.Gaps)
	}
}

func TestPNPMReviewCandidateRequiresSelectedLockWitness(t *testing.T) {
	r, _ := ownedProject(t, map[string]string{"package.json": "{}", "pnpm-lock.yaml": strings.ReplaceAll(ownedPNPMLock, "PRIVATE-a", "private-a"), "node_modules/private-a/package.json": `{"name":"private-a","version":"1.0.0"}`})
	got, err := Collect(context.Background(), r, Options{Profile: "pnpm", ExplicitManager: true})
	if err != nil {
		t.Fatal(err)
	}
	p := Portable(got)
	if len(p.Relations) != 1 || ValidatePublic(p) != nil {
		t.Fatal("positive witness fixture", p.Relations)
	}
	relation := p.Relations[0]
	p.Observations = append([]PublicObservation(nil), p.Observations...)
	p.Observations[relation.From-1].Source = p.Observations[relation.To-1].Source
	if ValidatePublic(p) == nil {
		t.Fatal("installed manifest substituted for selected lock evidence")
	}
}
