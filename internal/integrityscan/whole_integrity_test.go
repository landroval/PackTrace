package integrityscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/projectinventory"
)

func wholeFixture(t *testing.T, locations []string, drift bool) (Plan, string, string, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("owned Linux fixture, not qualification")
	}
	base := t.TempDir()
	root := filepath.Join(base, "target")
	prepared := filepath.Join(base, "prepared")
	for _, dir := range []string{root, prepared} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := []byte(`{"name":"pkg","version":"1.0.0"}`)
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		data []byte
	}{{"package.json", manifest}, {"index.js", []byte("original")}} {
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + f.name, Size: int64(len(f.data)), Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if tw.Close() != nil || gz.Close() != nil {
		t.Fatal("archive")
	}
	sum := sha256.Sum256(archive.Bytes())
	sri := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	write(filepath.Join(prepared, "pkg.tgz"), archive.Bytes())
	var p Policy
	if json.Unmarshal([]byte(policyJSON), &p) != nil {
		t.Fatal("policy")
	}
	template := p.References[0]
	p.References = []Reference{}
	packages := map[string]any{"": map[string]any{}}
	for _, location := range locations {
		ref := template
		ref.Location = location
		ref.LockKey = location
		ref.ExpectedSRI = sri
		p.References = append(p.References, ref)
		packages[location] = map[string]any{"name": "pkg", "version": "1.0.0", "resolved": "fixture:private", "integrity": sri}
		write(filepath.Join(root, filepath.FromSlash(location), "package.json"), manifest)
		body := []byte("original")
		if drift {
			body = []byte("changed")
		}
		write(filepath.Join(root, filepath.FromSlash(location), "index.js"), body)
	}
	lock, _ := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": packages})
	write(filepath.Join(root, "package-lock.json"), lock)
	write(filepath.Join(root, "package.json"), []byte(`{"name":"fixture"}`))
	policy := filepath.Join(prepared, "policy.json")
	plan, hash := fixturePlan(t, policy, p)
	return plan, hash, root, prepared
}

func wholeAcquire(t *testing.T, plan Plan, hash, root, prepared string) ([]Record, projectinventory.PublicInventory, Summary) {
	t.Helper()
	var records []Record
	var inventory projectinventory.PublicInventory
	summary, err := AcquireWithInventory(context.Background(), root, prepared, hash, plan, func(r Record) error { records = append(records, r); return nil }, func(r projectinventory.Result) error { inventory = projectinventory.PortableMatching(r); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return records, inventory, summary
}
func wholeReport(plan Plan, records []Record, inventory projectinventory.PublicInventory, summary Summary) Report {
	return BuildReportWithPolicy(plan, records, summary, Resources{}, false, false, &inventory, nil, nil, nil, false, time.Now().UTC())
}

func TestWholeIntegrityOwnedCoverage(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(map[bool]string{false: "equal", true: "drift"}[drift], func(t *testing.T) {
			for _, locations := range [][]string{{"node_modules/pkg"}, {"node_modules/pkg", "node_modules/pkg/node_modules/pkg"}, {}} {
				t.Run(strings.Join(locations, "+"), func(t *testing.T) {
					plan, hash, root, prepared := wholeFixture(t, locations, drift)
					records, inventory, summary := wholeAcquire(t, plan, hash, root, prepared)
					report := wholeReport(plan, records, inventory, summary)
					if coverageRow(t, report, "integrity").Outcome != "completed" {
						t.Fatalf("whole comparison incomplete: %+v records=%+v", report.Coverage, records)
					}
					if !drift && report.Findings != 0 || drift && len(locations) > 0 && report.Findings == 0 {
						t.Fatalf("wrong findings: %d", report.Findings)
					}
					if coverageRow(t, report, "native-qualification").Outcome != "incomplete" || report.ExitCode != 3 {
						t.Fatal("scope granted native qualification")
					}
					for _, format := range []string{"json", "terminal", "sarif"} {
						data, err := Render(report, format)
						if err != nil {
							t.Fatal(err)
						}
						if bytes.Contains(data, []byte("fixture:private")) || bytes.Contains(data, []byte("catalogSRI")) || bytes.Contains(data, []byte("/package.json")) {
							t.Fatal("private accounting leaked")
						}
					}
				})
			}
		})
	}
}

func TestWholeIntegrityMissingOwnersAndReferences(t *testing.T) {
	for _, mode := range []string{"extra", "no-references", "absent", "bad-reference", "plain-file", "nested-extra", "link", "bun-store", "pnpm-store", "bun-store-link", "pnpm-store-file"} {
		t.Run(mode, func(t *testing.T) {
			plan, _, root, prepared := wholeFixture(t, []string{"node_modules/pkg"}, true)
			switch mode {
			case "extra", "nested-extra":
				loc := "node_modules/extra"
				if mode == "nested-extra" {
					loc = "node_modules/pkg/node_modules/extra"
				}
				if err := os.MkdirAll(filepath.Join(root, loc), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, loc, "package.json"), []byte(`{"name":"extra","version":"1.0.0"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "no-references":
				plan.Policy.References = []Reference{}
			case "absent":
				plan.Policy.References[0].Location = "node_modules/absent"
			case "bad-reference":
				plan.Policy.References[0].ExpectedSRI = sourceSRI([]byte("wrong"))
			case "plain-file":
				if err := os.MkdirAll(filepath.Join(root, "node_modules/pkg/node_modules"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "node_modules/pkg/node_modules/unmapped"), []byte("content"), 0600); err != nil {
					t.Fatal(err)
				}
			case "bun-store", "pnpm-store":
				store := ".bun"
				if mode == "pnpm-store" {
					store = ".pnpm"
				}
				if err := os.MkdirAll(filepath.Join(root, "node_modules", store, "orphan"), 0700); err != nil {
					t.Fatal(err)
				}
			case "bun-store-link":
				if err := os.Symlink("pkg", filepath.Join(root, "node_modules/.bun")); err != nil {
					t.Fatal(err)
				}
			case "pnpm-store-file":
				if err := os.WriteFile(filepath.Join(root, "node_modules/.pnpm"), []byte("unsupported store marker"), 0600); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := os.Symlink("pkg", filepath.Join(root, "node_modules/linked")); err != nil {
					t.Fatal(err)
				}
			}
			plan, hash := fixturePlan(t, filepath.Join(prepared, "policy.json"), plan.Policy)
			records, inv, summary := wholeAcquire(t, plan, hash, root, prepared)
			r := wholeReport(plan, records, inv, summary)
			want := "incomplete"
			// A slot-file remains an unsupported inventory boundary, but its
			// ordinary bytes must still be compared as parent package content.
			if coverageRow(t, r, "integrity").Outcome != want {
				t.Fatalf("%s: %+v", mode, r.Coverage)
			}
			if mode != "no-references" && mode != "absent" && mode != "bad-reference" && r.Findings == 0 {
				t.Fatal("lost existing drift")
			}
		})
	}
}

func TestWholeIntegrityReceiptJoins(t *testing.T) {
	plan, hash, root, prepared := wholeFixture(t, []string{"node_modules/pkg", "node_modules/other"}, true)
	records, inv, summary := wholeAcquire(t, plan, hash, root, prepared)
	if !wholeIntegrityComplete(plan, records, &inv) {
		t.Fatal("fixture incomplete")
	}
	for name, mutate := range map[string]func(*Plan, []Record, *projectinventory.PublicInventory){
		"missing-record":  func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) { r[0] = Record{} },
		"missing-receipt": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) { r[0].IntegrityScope = nil },
		"wrong-reference": func(p *Plan, _ []Record, _ *projectinventory.PublicInventory) {
			p.Policy.References[0].Archive = "other.tgz"
		},
		"wrong-endpoint": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) {
			r[0].IntegrityScope.Reference.Location = "node_modules/other"
		},
		"catalog-swap": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) {
			r[0].IntegrityScope.Catalog.ObservedSRI = sourceSRI([]byte("other catalog"))
		},
		"equal-digest-catalog-swap": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) {
			r[0].IntegrityScope.Catalog = r[1].IntegrityScope.Catalog
		},
		"policy-source-swap": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) {
			r[0].IntegrityScope.PolicySourceHash = sourceSRI([]byte("different policy"))
		},
		"instance-swap": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) {
			r[0].IntegrityScope, r[1].IntegrityScope = r[1].IntegrityScope, r[0].IntegrityScope
		},
		"source-swap": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) {
			r[0].IntegrityScope.Manifest = r[1].IntegrityScope.Manifest
		},
		"metadata-swap": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) {
			r[0].IntegrityScope.Directory = r[1].IntegrityScope.Directory
		},
		"record-swap": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) { r[0], r[1] = r[1], r[0] },
		"manifest-observation-swap": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) {
			r[0].IntegrityScope.ManifestEntry = r[1].IntegrityScope.ManifestEntry
		},
		"manifest-size": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) {
			r[0].IntegrityScope.ManifestEntry.Size++
		},
		"manifest-content": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) {
			r[0].IntegrityScope.ManifestEntry.SHA256 = [32]byte{1}
		},
		"missing-inventory": func(_ *Plan, _ []Record, p *projectinventory.PublicInventory) { p.OriginalClaims = nil },
		"original-change": func(_ *Plan, _ []Record, p *projectinventory.PublicInventory) {
			p.OriginalClaims.OriginalInputs[0].Bytes[0] = '!'
		},
		"inventory-incomplete": func(_ *Plan, _ []Record, p *projectinventory.PublicInventory) { p.Complete = false },
		"observation-index-only": func(_ *Plan, r []Record, _ *projectinventory.PublicInventory) {
			r[0].IntegrityScope.Comparison = [32]byte{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			data, _ := json.Marshal(struct {
				Plan      Plan
				Records   []Record
				Original  *projectinventory.Result
				Inventory projectinventory.PublicInventory
			}{plan, records, inv.OriginalClaims, inv})
			var copy struct {
				Plan      Plan
				Records   []Record
				Original  *projectinventory.Result
				Inventory projectinventory.PublicInventory
			}
			if err := json.Unmarshal(data, &copy); err != nil {
				t.Fatal(err)
			}
			copy.Inventory.OriginalClaims = copy.Original
			mutate(&copy.Plan, copy.Records, &copy.Inventory)
			r := wholeReport(copy.Plan, copy.Records, copy.Inventory, summary)
			if coverageRow(t, r, "integrity").Outcome != "incomplete" {
				t.Fatal("forged accounting completed")
			}
		})
	}
	// Both inventory original bytes and records are frozen before output. Later
	// caller mutations cannot change the valid comparison snapshot.
	report := wholeReport(plan, records, inv, summary)
	inv.OriginalClaims.OriginalInputs[0].Bytes[0] = '!'
	records[0].IntegrityScope.Reference.Location = "wrong"
	if _, err := Render(report, "json"); err != nil {
		t.Fatal("frozen report changed", err)
	}
	report.Coverage[1].Outcome = "incomplete"
	if _, err := Render(report, "json"); err == nil {
		t.Fatal("tampered coverage rendered")
	}
}

func TestWholeIntegrityBunOwnedCoverage(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(map[bool]string{false: "equal", true: "drift"}[drift], func(t *testing.T) {
			plan, _, root, prepared := wholeFixture(t, []string{"node_modules/pkg"}, drift)
			plan.Policy.Manager = "bun@1.3.x"
			plan.Policy.References[0].LockKey = "pkg"
			ref := plan.Policy.References[0]
			raw := []byte(`{"lockfileVersion":1,"configVersion":1,"workspaces":{"":{}},"packages":{"pkg":["pkg@1.0.0","` + ref.Origin + `",{},"` + ref.ExpectedSRI + `"]}}`)
			if err := os.Remove(filepath.Join(root, "package-lock.json")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "bun.lock"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			plan, hash := fixturePlan(t, filepath.Join(prepared, "policy.json"), plan.Policy)
			records, inv, summary := wholeAcquire(t, plan, hash, root, prepared)
			r := wholeReport(plan, records, inv, summary)
			if coverageRow(t, r, "integrity").Outcome != "completed" || (!drift && r.Findings != 0) || (drift && r.Findings != 1) {
				t.Fatalf("Bun receipt comparison failed: %+v", r)
			}
		})
	}
}

func TestWholeIntegrityManifestChangesAfterInventory(t *testing.T) {
	plan, hash, root, prepared := wholeFixture(t, []string{"node_modules/pkg"}, false)
	var records []Record
	var inv projectinventory.PublicInventory
	summary, err := AcquireWithInventory(context.Background(), root, prepared, hash, plan, func(r Record) error { records = append(records, r); return nil }, func(original projectinventory.Result) error {
		inv = projectinventory.PortableMatching(original)
		// Owned test fault between the retained original read and content snapshot.
		return os.WriteFile(filepath.Join(root, "node_modules/pkg/package.json"), []byte(`{"name":"pkg","version":"2.0.0"}`), 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	r := wholeReport(plan, records, inv, summary)
	if coverageRow(t, r, "integrity").Outcome != "incomplete" || r.Findings != 1 || records[0].IntegrityScope != nil {
		t.Fatalf("changed source granted whole accounting or lost drift: %+v", r)
	}
}
