//go:build linux && (amd64 || arm64)

package projectinventory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"packtrace/internal/nativefs"
)

func TestPNPMInstalledOwnedProducerReplay(t *testing.T) {
	raw, err := os.ReadFile("testdata/producer/pnpm-installed.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema   string
		Captures []producerCapture
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Schema != "packtrace.owned-pnpm-installed.v1" || len(doc.Captures) != 6 {
		t.Fatal("owned corpus shape")
	}
	for i, capture := range doc.Captures {
		t.Run(capture.Case+string(rune('0'+i)), func(t *testing.T) {
			root := materializeProducer(t, capture)
			r, err := nativefs.OpenRoot(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got, err := Collect(context.Background(), r, Options{Profile: "pnpm@lockfile-9"})
			if err != nil {
				t.Fatal(err)
			}
			if got.Selection.State != "usable" || got.Complete || len(got.Model.Scopes) != 1 || got.Model.Counts().Installed == 0 {
				t.Fatalf("physical inventory unavailable: %+v %v", got.Model.Counts(), got.Model.Gaps)
			}
			if ValidatePublic(Portable(got)) != nil || ValidatePublic(PortableMatching(got)) != nil {
				t.Fatal("parent rejected installed evidence")
			}
			good, bad, candidates := 0, 0, 0
			versions := map[string]bool{}
			for _, o := range got.Model.Observations {
				if o.Class == "installed" {
					if o.Status == "complete" {
						good++
						versions[o.Name+"@"+o.Version] = true
					} else {
						bad++
					}
				}
			}
			for _, rel := range got.Model.Relations {
				if rel.Kind != "candidate-correspondence" || rel.Status != "indeterminate" {
					t.Fatal("physical/absence authority invented", rel)
				}
				candidates++
			}
			if capture.Case == "hardlinks-refused" {
				if bad == 0 {
					t.Fatal("hardlinked manifest qualified")
				}
			} else {
				if bad != 0 || good < 5 || candidates == 0 {
					t.Fatalf("copy/peer observations lost: good=%d bad=%d candidates=%d gaps=%+v", good, bad, candidates, got.Model.Gaps)
				}
				if capture.Case == "single-copy" && (!versions["fixture-common@1.0.0"] || !versions["fixture-common@2.0.0"] || !versions["fixture-bundle@1.0.0"]) {
					t.Fatal("distinct/bundled instances lost", versions)
				}
			}
			t.Logf("installed=%d complete=%d unreadable=%d candidateRelations=%d", got.Model.Counts().Installed, good, bad, candidates)
		})
	}
}

func TestPNPMInstalledActiveScopedAliasNotOrphans(t *testing.T) {
	r, root := ownedProject(t, map[string]string{
		"package.json": `{"dependencies":{"alias":"npm:private-a@1.0.0"}}`, "pnpm-lock.yaml": strings.ReplaceAll(ownedPNPMLock, "PRIVATE-a", "private-a"),
		"node_modules/.pnpm/opaque/node_modules/private-a/package.json":  `{"name":"private-a","version":"1.0.0"}`,
		"node_modules/.pnpm/opaque/node_modules/@owned/pkg/package.json": `{"name":"@owned/pkg","version":"2.0.0"}`,
		"node_modules/.pnpm/opaque/node_modules/dep/package.json":        `{"name":"dep","version":"1.0.0"}`,
		"node_modules/.pnpm/orphan/node_modules/orphan/package.json":     `{"name":"orphan","version":"1.0.0"}`,
		"node_modules/.pnpm/opaque/node_modules/private-a/index.js":      "owned source canary", ".npmrc": "owned credential canary",
	})
	if os.Symlink(".pnpm/opaque/node_modules/private-a", filepath.Join(root, "node_modules/alias")) != nil {
		t.Fatal("owned alias")
	}
	read := watchedContent(t, filepath.Join(root, "node_modules/.pnpm/orphan/node_modules/orphan/package.json"), filepath.Join(root, "node_modules/.pnpm/opaque/node_modules/private-a/index.js"), filepath.Join(root, ".npmrc"))
	got, err := Collect(context.Background(), r, Options{Profile: "pnpm", ExplicitManager: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Model.Counts().Installed != 3 || got.Complete || read() {
		t.Fatalf("active-only purpose boundary: %+v", got.Model.Counts())
	}
	found := false
	for _, o := range got.Model.Observations {
		if o.Class == "installed" && o.Location == "node_modules/alias" {
			found = o.Name == "private-a" && o.Fields["installation-name"] == "alias"
		}
	}
	if !found || len(got.Model.Relations) != 1 || got.Model.Relations[0].Kind != "candidate-correspondence" {
		t.Fatal("alias claim/indeterminate correspondence lost", got.Model.Relations)
	}
	p := Portable(got)
	if ValidatePublic(p) != nil {
		t.Fatal("valid public copy inventory")
	}
	for _, kind := range []string{"locked-correspondence", "physical-link", "declared-requirement"} {
		forged := p
		forged.Relations = append([]Relation(nil), p.Relations...)
		forged.Relations[0].Kind = kind
		if ValidatePublic(forged) == nil {
			t.Fatal("forged PNPM authority", kind)
		}
	}
	forged := p
	forged.Observations = append([]PublicObservation(nil), p.Observations...)
	for i := range forged.Observations {
		if forged.Observations[i].Class == "installed" {
			forged.Observations[i].MetadataEvidence = 0
			break
		}
	}
	if ValidatePublic(forged) == nil {
		t.Fatal("installed metadata witness dropped")
	}
}

func TestPNPMCandidateLimitAndUnsupportedTuples(t *testing.T) {
	m := Model{Evidence: []Evidence{{ID: 1, Scope: 1, Method: "native-input-lease", Complete: true}}}
	for i := 0; i < 150; i++ {
		m.Observations = append(m.Observations, Observation{ID: uint32(2*i + 1), Class: "locked", Kind: "package", Status: "complete", Name: "a", Version: "1.0.0", Source: 1, Fields: map[string]string{"tuple-key": "logical"}}, Observation{ID: uint32(2*i + 2), Class: "installed", Kind: "directory", Status: "complete", Name: "a", Version: "1.0.0", Source: 1})
	}
	got := reconcilePNPM(m)
	if len(got.Relations) != maxRecords || len(got.Gaps) != 1 || got.Gaps[0].Code != "relation-limit" {
		t.Fatal("candidate amplification lost its bounded coverage gap", len(got.Relations), got.Gaps)
	}
	m.Observations = m.Observations[:2]
	m.Observations[0].Status = "unsupported"
	m.Observations[0].Location = "node_modules/a"
	if len(reconcilePNPM(m).Relations) != 0 {
		t.Fatal("unsupported tuple became a physical or candidate join")
	}
}

func TestInstalledAncestorRetargetInvalidatesVisitedChildren(t *testing.T) {
	r, root := ownedProject(t, map[string]string{"node_modules/.bun/a/node_modules/a/package.json": `{"name":"a","version":"1.0.0"}`, "node_modules/.bun/a/node_modules/b/package.json": `{"name":"b","version":"1.0.0"}`, "node_modules/.bun/other/node_modules/a/package.json": `{"name":"other","version":"1.0.0"}`})
	link := filepath.Join(root, "node_modules/a")
	if os.Symlink(".bun/a/node_modules/a", link) != nil {
		t.Fatal("owned link")
	}
	snap, err := r.Metadata(context.Background(), nativefs.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]nativefs.Entry{}
	for _, e := range snap.Entries {
		entries[e.Name] = e
	}
	c := collector{ctx: context.Background(), root: r, entries: entries, blocked: map[string]bool{}, manifestRemaining: maxManifestTotal, requirementsRemaining: maxRecords, classCounts: map[string]int{}}
	c.observeSlotVisiting(1, "node_modules/a", func(_ string, _ bool, _ func() bool) {
		c.observeSlot(1, "node_modules/.bun/a/node_modules/b")
		if os.Remove(link) != nil || os.Symlink(".bun/other/node_modules/a", link) != nil {
			t.Fatal("retarget after child visit")
		}
	})
	if len(c.result.Model.Observations) != 2 {
		t.Fatal("child not observed")
	}
	for _, o := range c.result.Model.Observations {
		if o.Status != "unstable" || c.result.Model.Evidence[o.Source-1].Complete {
			t.Fatal("stale descendant activation retained", o)
		}
	}
}
