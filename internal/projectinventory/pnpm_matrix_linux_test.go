//go:build linux && (amd64 || arm64)

package projectinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"packtrace/internal/nativefs"
)

func TestPNPM11HintDoesNotAdmitOtherLockFormats(t *testing.T) {
	for _, hint := range []string{"pnpm@11.28.9", "pnpm@12.18.0"} {
		for _, format := range []string{"8.0", "10.0", "9", "9.00"} {
			t.Run(hint+"/"+format, func(t *testing.T) {
				root, _ := ownedProject(t, map[string]string{"package.json": `{"packageManager":"` + hint + `"}`, "pnpm-lock.yaml": strings.Replace(ownedPNPMLock, "'9.0'", "'"+format+"'", 1), "node_modules/a/package.json": `{"name":"a","version":"1.0.0"}`})
				got, err := Collect(context.Background(), root, Options{Profile: "auto"})
				if err != nil || got.Selection.State != "unusable" || got.Model.Counts().Installed != 0 || got.Complete || ValidatePublic(Portable(got)) != nil {
					t.Fatal("new hint broadened lock formats or installed access", format, got.Selection, err)
				}
			})
		}
	}
}

func TestPNPMVersionLayoutMatrixReplay(t *testing.T) {
	for _, fixture := range []struct {
		file, schema, digest      string
		size, producers, captures int
	}{
		{"pnpm-matrix.json", "packtrace.owned-pnpm-matrix.v1", "1002c957fe67456f82ae6c63592ca3dc994a1efadf9a7ebd45f14c6587327402", 245568, 6, 20},
		{"pnpm12-native.json", "packtrace.owned-pnpm12-native.v1", "fd714050d0b0ccde4ee936dd64a698e591dbe2b1dcff21f948ea04193791ceda", 50858, 0, 4},
	} {
		raw, err := os.ReadFile("testdata/producer/" + fixture.file)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		if len(raw) != fixture.size || hex.EncodeToString(digest[:]) != fixture.digest {
			t.Fatal("matrix original changed", fixture.file)
		}
		var doc struct {
			Schema    string
			Producers []struct {
				Version               string
				Cases                 []struct{ Status string }
				AdditionalDiagnostics []struct{ Status string }
			}
			Captures []struct {
				Producer string
				producerCapture
			}
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Schema != fixture.schema || len(doc.Producers) != fixture.producers || len(doc.Captures) != fixture.captures {
			t.Fatal("matrix shape")
		}
		for _, producer := range doc.Producers {
			if producer.Version == "12.18.0" {
				if len(producer.Cases) != 4 || len(producer.AdditionalDiagnostics) != 2 {
					t.Fatal("failed native12 evidence missing")
				}
				for _, c := range producer.Cases {
					if c.Status != "failed" {
						t.Fatal("native12 adapter failure relabeled as support")
					}
				}
			}
		}
		for _, capture := range doc.Captures {
			for _, profile := range []string{"pnpm@lockfile-9", "pnpm", "auto"} {
				modes := []string{""}
				if fixture.file == "pnpm12-native.json" {
					modes = append(modes, "/authored-hint")
				}
				for _, mode := range modes {
					t.Run(capture.Producer+"/"+capture.Case+"/"+profile+mode, func(t *testing.T) {
						path := materializeProducer(t, capture.producerCapture)
						if mode != "" {
							manifestPath := path + "/package.json"
							original, err := os.ReadFile(manifestPath)
							if err != nil {
								t.Fatal(err)
							}
							var manifest map[string]any
							if json.Unmarshal(original, &manifest) != nil {
								t.Fatal("owned manifest")
							}
							manifest["packageManager"] = capture.Producer
							modified, err := json.Marshal(manifest)
							if err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(manifestPath, modified, 0600); err != nil {
								t.Fatal(err)
							}
						}
						root, err := nativefs.OpenRoot(context.Background(), path)
						if err != nil {
							t.Fatal(err)
						}
						defer root.Close()
						got, err := Collect(context.Background(), root, Options{Profile: profile, ExplicitManager: profile == "pnpm"})
						if err != nil {
							t.Fatal(err)
						}
						if got.Selection.State != "usable" || got.Selection.Family != "pnpm" || got.Complete || len(got.Model.Scopes) != 1 || got.Model.Counts().Installed == 0 {
							t.Fatalf("version/layout not collected: %+v counts=%+v gaps=%+v", got.Selection, got.Model.Counts(), got.Model.Gaps)
						}
						good, bad := 0, 0
						versions := map[string]map[string]int{}
						parentLocations := map[string]bool{}
						alias := false
						for _, o := range got.Model.Observations {
							if o.Class == "installed" {
								if o.Status == "complete" {
									good++
									if versions[o.Name] == nil {
										versions[o.Name] = map[string]int{}
									}
									versions[o.Name][o.Version]++
									if o.Name == "fixture-parent" {
										parentLocations[o.Location] = true
									}
									alias = alias || o.Fields["installation-name"] == "fixture-alias" && o.Name == "fixture-common" && o.Version == "1.0.0"
								} else {
									if o.Status != "unreadable" {
										t.Fatal("unexpected installed instability", o.Status)
									}
									bad++
								}
							}
						}
						if capture.Case == "hardlinks-refused" || capture.Case == "hardlinks-requested" {
							if bad == 0 {
								t.Fatal("captured hardlinks became readable")
							}
						} else {
							if bad != 0 {
								t.Fatal("readable copy layout incomplete", got.Model.Gaps)
							}
							for name, want := range capture.Expected.Versions {
								for _, v := range want {
									if versions[name][v] == 0 {
										t.Fatal("expected physical identity missing", name, v, versions)
									}
								}
							}
							for _, name := range capture.Expected.OptionalAbsent {
								if len(versions[name]) != 0 {
									t.Fatal("optional absence manufactured installation")
								}
							}
							if capture.Case != "peer-contexts-copy" && !alias {
								t.Fatal("alias identity collapsed")
							}
						}
						want, known := map[string][3]int{"isolated-copy": {7, 0, 6}, "hoisted-copy": {6, 0, 5}, "peer-contexts-copy": {12, 0, 12}, "hardlinks-refused": {2, 5, 1}, "hardlinks-requested": {2, 5, 1}}[capture.Case]
						if !known || [3]int{good, bad, len(got.Model.Relations)} != want {
							t.Fatal("matrix multiplicity changed", good, bad, len(got.Model.Relations), want)
						}
						if capture.Case == "peer-contexts-copy" && len(parentLocations) < 2 {
							t.Fatal("distinct parent peer slots collapsed")
						}
						if len(got.Model.Relations) == 0 {
							t.Fatal("qualified claims lost indeterminate candidates")
						}
						for _, rel := range got.Model.Relations {
							if rel.Kind != "candidate-correspondence" || rel.Status != "indeterminate" {
								t.Fatal("matrix gained physical/absence authority", rel)
							}
						}
						for _, p := range []PublicInventory{Portable(got), PortableMatching(got)} {
							if ValidatePublic(p) != nil || p.Counts.Installed != good+bad {
								t.Fatal("parent rejected matrix closure")
							}
							bytes, _ := json.Marshal(p)
							if strings.Contains(string(bytes), "fixture-") || strings.Contains(string(bytes), path) {
								t.Fatal("portable identity/path leak")
							}
						}
						t.Logf("completeInstalled=%d unreadable=%d candidates=%d", good, bad, len(got.Model.Relations))
					})
				}
			}
		}
	}
}
