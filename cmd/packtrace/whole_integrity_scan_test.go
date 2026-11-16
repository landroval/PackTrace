package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"packtrace/internal/integrity"
	"packtrace/internal/integrityscan"
)

// These are actual supervised CLI tests, not qualification or a fabricated
// completion bit. Every child still exits 3 for the separate native/global gates.
func TestScanWholeInstalledIntegrity(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows subprocess fixtures")
	}
	for _, family := range []string{"npm", "bun"} {
		for _, mode := range []string{"equal", "modified", "extra-unmapped", "extra-with-drift", "wrong-reference", "missing-archive", "unavailable-manifest", "identity-conflict", "empty-mapping", "shared-owner", "package-shaped-file"} {
			t.Run(family+"/"+mode, func(t *testing.T) {
				if mode == "shared-owner" && runtime.GOOS != "linux" {
					t.Skip("owned symlink fixture; no Windows privilege changes")
				}
				target, policy, selected, originals := wholeIntegrityFixture(t, family, mode)
				before := wholeIntegrityTree(t, target)
				data, err := json.Marshal(selected)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(policy, data, 0600); err != nil {
					t.Fatal(err)
				}
				pin := sha256.Sum256(data)
				for _, privacy := range []string{"portable", "local"} {
					t.Run(privacy, func(t *testing.T) {
						args := []string{"--policy", policy, "--trusted-policy-digest", "sha256-" + base64.StdEncoding.EncodeToString(pin[:]), "--checks", "integrity", "--format", "json"}
						// Deliberately omit --privacy for the default/no-exception path.
						if privacy == "local" {
							args = append(args, "--privacy", "local")
						}
						r, raw := runPolicyAcceptanceJSON(t, append(args, target)...)
						if r.Privacy != privacy || r.NativeQualification != "not-run" || len(r.Policy.Exceptions) != 0 {
							t.Fatalf("privacy/qualification/exception contract: %s", raw)
						}
						inv := r.Inventory
						wantInstalled := 1
						if mode == "extra-unmapped" || mode == "extra-with-drift" || mode == "shared-owner" || mode == "package-shaped-file" {
							wantInstalled = 2
						}
						if inv == nil || inv.Selection.Family != family || inv.Selection.State != "usable" || inv.Counts.Installed != wantInstalled || r.Instances != len(selected.References) {
							t.Fatalf("physical inventory/reference count mismatch: %s", raw)
						}
						inventoryComplete := mode != "unavailable-manifest" && mode != "package-shaped-file" && mode != "shared-owner"
						// shared-owner enumeration succeeds, but a link is not its own
						// native directory witness for closed integrity accounting.
						if mode != "shared-owner" && inv.Complete != inventoryComplete {
							t.Errorf("inventory completeness: %s", raw)
						}
						wantInventory := "incomplete"
						if inventoryComplete {
							wantInventory = "completed"
						}
						wholeIntegrityCoverage(t, r, "inventory", wantInventory)
						// Authored observation order: declaration 1, root lock 2,
						// package lock 3, then physical slots PRIVATE-pkg (4) and
						// PRIVATE-zcopy (5). Nested children precede their parent.
						// The extra physical copy is NEVER merged by identity.
						for slot := 0; slot < wantInstalled; slot++ {
							id := uint32(4 + slot)
							if int(id) > len(inv.Observations) {
								t.Fatalf("missing authored physical slot %d: %s", id, raw)
							}
							o := inv.Observations[id-1]
							kind, status := "directory", "complete"
							if slot == 0 && mode == "unavailable-manifest" {
								status = "unreadable"
							}
							if slot == 1 && mode == "shared-owner" {
								kind = "link"
							}
							if slot == 0 && mode == "package-shaped-file" {
								kind, status = "slot-file", "unsupported"
							}
							if o.ID != id || o.Class != "installed" || o.Workspace != 1 || o.Kind != kind || o.Status != status {
								t.Fatalf("authored slot %d changed identity/status: %s", id, raw)
							}
							if kind == "directory" && status == "complete" {
								if o.Source == 0 || o.MetadataEvidence == 0 || o.Source == o.MetadataEvidence {
									t.Fatalf("slot %d lacks actual manifest/directory association: %s", id, raw)
								}
								source, metadata := inv.Evidence[o.Source-1], inv.Evidence[o.MetadataEvidence-1]
								if source.MetadataEvidence != metadata.ID || source.Method != "native-input-lease" || metadata.Method != "native-metadata-lease" || source.Status != "complete" || metadata.Status != "complete" || source.Scope != 1 || metadata.Scope != 1 {
									t.Fatalf("slot %d lost numeric native join: %s", id, raw)
								}
							}
						}
						primaryID := uint32(4)
						if mode == "package-shaped-file" {
							primaryID = 5
						}
						wantRelations := map[uint32]string{primaryID: "claim-agreement"}
						relationKind := "locked-correspondence"
						if family == "bun" {
							relationKind = "candidate-correspondence"
							wantRelations[primaryID] = "indeterminate"
							if mode == "extra-unmapped" || mode == "extra-with-drift" || mode == "shared-owner" {
								wantRelations[5] = "indeterminate"
							}
							if mode == "identity-conflict" || mode == "unavailable-manifest" {
								delete(wantRelations, primaryID)
							}
						} else if mode == "identity-conflict" {
							wantRelations[primaryID] = "conflict"
						} else if mode == "unavailable-manifest" {
							wantRelations[primaryID] = "indeterminate"
						}
						for _, relation := range inv.Relations {
							if relation.Kind != relationKind {
								continue
							}
							if relation.From != 3 || relation.Status != wantRelations[relation.To] || relation.To == 0 || relation.Evidence != inv.Observations[relation.To-1].Source {
								t.Fatalf("lock/physical-slot association differs from authored mapping: %s", raw)
							}
							delete(wantRelations, relation.To)
						}
						if len(wantRelations) != 0 {
							t.Fatalf("missing authored lock/physical-slot association: %s", raw)
						}
						wantFindings := 0
						wantPath, wantKind := "index.js", integrity.DifferenceModified
						if mode == "modified" || mode == "extra-with-drift" || mode == "identity-conflict" || mode == "unavailable-manifest" {
							wantFindings = 1
						}
						if mode == "identity-conflict" || mode == "unavailable-manifest" {
							wantPath = "package.json"
						}
						if mode == "unavailable-manifest" {
							wantKind = integrity.DifferenceMissing
						}
						if mode == "package-shaped-file" {
							wantFindings, wantKind = 2, integrity.DifferenceAdded // directory + ordinary file
						}
						if r.Findings != wantFindings || len(r.Policy.Findings) != wantFindings || r.Policy.EnforcedUnaccepted != wantFindings {
							t.Fatalf("actual drift lost or invented: %s", raw)
						}
						localPaths := map[string]bool{}
						for _, f := range r.Policy.Findings {
							if f.Category != "integrity" || f.Record != 0 || f.Accepted || !f.Enforced || r.Comparison.Differences[f.Difference].Kind != wantKind || r.Comparison.Differences[f.Difference].Instance != 1 {
								t.Fatalf("finding detached from first physical reference: %s", raw)
							}
							if privacy == "local" && mode != "unavailable-manifest" && mode != "identity-conflict" {
								if mode == "package-shaped-file" {
									wantPath = "node_modules"
									if f.Review != nil && f.Review.Observed != nil && f.Review.Observed.Type == "file" {
										wantPath += "/PRIVATE-file"
									}
								}
								if f.Instance != "node_modules/PRIVATE-pkg" || f.Path != wantPath || f.Package != "PRIVATE-pkg" || f.Review == nil || localPaths[f.Path] {
									t.Fatalf("local finding not bound to authored path: %s", raw)
								}
								localPaths[f.Path] = true
								if mode == "modified" || mode == "extra-with-drift" {
									expected, observed := sha256.Sum256([]byte("expected")), sha256.Sum256([]byte("owned inert modification"))
									if f.Review.Expected == nil || f.Review.Observed == nil || f.Review.Expected.SHA256 != hex.EncodeToString(expected[:]) || f.Review.Observed.SHA256 != hex.EncodeToString(observed[:]) || f.Review.ReferenceObservedSRI != selected.References[0].ExpectedSRI {
										t.Fatalf("drift review differs from actual authored original bytes: %s", raw)
									}
								}
							}
							// Entry 1 is the authored package.json; entry 2 is index.js.
							// Invalid installed identity must not fabricate local review.
							if mode == "unavailable-manifest" || mode == "identity-conflict" {
								if r.Comparison.Differences[f.Difference].Entry != 1 {
									t.Fatalf("manifest drift attached to wrong archive entry: %s", raw)
								}
							} else if mode != "package-shaped-file" && r.Comparison.Differences[f.Difference].Entry != 2 {
								t.Fatalf("content drift attached to wrong archive entry: %s", raw)
							}
						}
						if privacy == "local" && mode == "package-shaped-file" && (!localPaths["node_modules"] || !localPaths["node_modules/PRIVATE-file"]) {
							t.Fatalf("ordinary file hidden as a pruned dependency: %s", raw)
						}
						if privacy == "portable" {
							for _, secret := range append(originals, target, policy, "PRIVATE", "registry.npmjs.org", "sha256-") {
								if strings.Contains(string(raw), secret) {
									t.Errorf("portable report leaked %q", secret)
								}
							}
						}
						if after := wholeIntegrityTree(t, target); !reflect.DeepEqual(before, after) {
							t.Fatal("scan changed owned target entries, modes, links or original bytes")
						}
						if mode == "wrong-reference" || mode == "missing-archive" {
							if r.Comparison.SuppliedComparisonComplete || len(r.Comparison.Gaps) == 0 || r.ObservedEntries != 0 {
								t.Errorf("bad reference granted comparison/traversal: %s", raw)
							}
						}
						if mode == "equal" || mode == "modified" || mode == "extra-unmapped" || mode == "extra-with-drift" {
							if r.ObservedEntries != 3 || !r.Comparison.SuppliedComparisonComplete || len(r.Comparison.Gaps) != 0 {
								t.Errorf("exact mapped two-file comparison changed: %s", raw)
							}
						}
						wantIntegrity := "incomplete"
						if mode == "equal" || mode == "modified" {
							wantIntegrity = "completed"
							if !r.Comparison.SuppliedComparisonComplete || len(r.Comparison.Gaps) != 0 {
								t.Errorf("valid authored comparison incomplete: %s", raw)
							}
						}
						wholeIntegrityCoverage(t, r, "integrity", wantIntegrity)
						wholeIntegrityCoverage(t, r, "native-qualification", "incomplete")
						wholeIntegrityCoverage(t, r, "resident-observation", "incomplete")
					})
				}
			})
		}
	}
}

func wholeIntegrityCoverage(t *testing.T, r integrityscan.Report, check, outcome string) {
	t.Helper()
	for _, c := range r.Coverage {
		if c.Check == check {
			if !c.Required || c.Outcome != outcome {
				t.Errorf("%s coverage: got required=%v %q, want required=true %q (%s)", check, c.Required, c.Outcome, outcome, c.Reason)
			}
			return
		}
	}
	t.Errorf("missing required %s coverage", check)
}

func wholeIntegrityFixture(t *testing.T, family, mode string) (string, string, integrityscan.Policy, []string) {
	t.Helper()
	target, policy := scanFixture(t)
	manifest := []byte(`{"name":"PRIVATE-pkg","version":"1.0.0"}`)
	// Independent fixture oracle: the archive contains exactly these original
	// bytes in this order. Never derive its expected SRI/content from scan output.
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, file := range []struct{ name, body string }{{"package.json", string(manifest)}, {"index.js", "expected"}} {
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + file.name, Mode: 0600, Size: int64(len(file.body)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(file.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(archive.Bytes())
	sri := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	origin, manager, lockKey := "https://registry.npmjs.org", "npm@10.9.4", "node_modules/PRIVATE-pkg"
	if family == "bun" {
		manager, lockKey = "bun@1.3.x", "PRIVATE-pkg"
	}
	selected := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "owned inert whole-scope comparison", Provenance: "authored two-file archive; original bytes and explicit instance mapping", Manager: manager, RequiredChecks: []string{"integrity"}, FailOn: []string{"integrity"}, MinimumAssurance: "independently-anchored", References: []integrityscan.Reference{{Location: "node_modules/PRIVATE-pkg", LockKey: lockKey, Name: "PRIVATE-pkg", Version: "1.0.0", Origin: origin, Classification: "unknown", ExpectedSRI: sri, Archive: "reference.tgz", Context: "none"}}}
	files := map[string][]byte{
		"package.json":                          []byte(`{"name":"PRIVATE-root","version":"1.0.0","packageManager":"` + strings.ReplaceAll(manager, "x", "2") + `","dependencies":{"PRIVATE-pkg":"1.0.0"}}`),
		"node_modules/PRIVATE-pkg/package.json": manifest,
		"node_modules/PRIVATE-pkg/index.js":     []byte("expected"),
	}
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"PRIVATE-root","version":"1.0.0","dependencies":{"PRIVATE-pkg":"1.0.0"}},"node_modules/PRIVATE-pkg":{"name":"PRIVATE-pkg","version":"1.0.0","resolved":"` + origin + `","integrity":"` + sri + `"}}}`
	files["package-lock.json"] = []byte(lock)
	if family == "bun" {
		if err := os.Remove(filepath.Join(target, "package-lock.json")); err != nil {
			t.Fatal(err)
		}
		delete(files, "package-lock.json")
		files["bun.lock"] = []byte(`{"lockfileVersion":1,"configVersion":1,"workspaces":{"":{"name":"PRIVATE-root","dependencies":{"PRIVATE-pkg":"1.0.0"}}},"packages":{"PRIVATE-pkg":["PRIVATE-pkg@1.0.0","` + origin + `",{},"` + sri + `"]}}`)
	}
	switch mode {
	case "modified", "extra-with-drift":
		files["node_modules/PRIVATE-pkg/index.js"] = []byte("owned inert modification")
	case "identity-conflict":
		files["node_modules/PRIVATE-pkg/package.json"] = []byte(`{"name":"PRIVATE-pkg","version":"2.0.0"}`)
	case "wrong-reference":
		selected.References[0].Version = "2.0.0"
	case "empty-mapping":
		selected.References = []integrityscan.Reference{}
	case "shared-owner":
		if err := os.Symlink("PRIVATE-pkg", filepath.Join(target, "node_modules/PRIVATE-zcopy")); err != nil {
			t.Fatal(err)
		}
		copy := selected.References[0]
		copy.Location = "node_modules/PRIVATE-zcopy"
		selected.References = append(selected.References, copy)
	case "package-shaped-file":
		files["node_modules/PRIVATE-pkg/node_modules/PRIVATE-file"] = []byte("ordinary inert file, not a package directory")
	}
	if mode == "extra-unmapped" || mode == "extra-with-drift" {
		files["node_modules/PRIVATE-zcopy/package.json"] = manifest
		files["node_modules/PRIVATE-zcopy/index.js"] = []byte("expected")
	}
	if mode == "unavailable-manifest" {
		delete(files, "node_modules/PRIVATE-pkg/package.json")
	}
	for name, data := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(target, name)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if mode != "missing-archive" {
		if err := os.WriteFile(filepath.Join(filepath.Dir(policy), "reference.tgz"), archive.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Remove(filepath.Join(filepath.Dir(policy), "reference.tgz")); err != nil {
		t.Fatal(err)
	}
	originals := []string{sri, hex.EncodeToString(sum[:])}
	for _, data := range files {
		h := sha256.Sum256(data)
		originals = append(originals, hex.EncodeToString(h[:]))
	}
	return target, policy, selected, originals
}

func wholeIntegrityTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String() + "\x00"
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			value += string(data)
		} else if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(name)
			if err != nil {
				return err
			}
			value += link
		}
		rel, err := filepath.Rel(root, name)
		out[rel] = value
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
