package execution

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/integrity"
	"packtrace/internal/integrityscan"
	"packtrace/internal/nativefs"
	"packtrace/internal/projectinventory"
)

func TestWholeIntegrityProtocolChild(t *testing.T) {
	if len(os.Args) != 3 || os.Args[1] != "-test.run=^TestWholeIntegrityProtocolChild$" {
		return
	}
	os.Exit(wholeIntegrityProtocolChild(os.Args[2]))
}
func wholeIntegrityProtocolChild(mode string) int {
	c := newChannel(os.Stdin, os.Stdout, &traffic{})
	identity, err := buildIdentity()
	if err != nil || c.send("hello", hello{identity}) != nil {
		return 98
	}
	var h hello
	var cfg scanConfig
	if c.expect("hello", &h) != nil || c.expect("config", &cfg) != nil {
		return 97
	}
	if _, err = c.receive(); err != io.EOF {
		return 96
	}
	_ = c.send("start", scanStart{cfg.Stage})
	rss, err := nativefs.OwnResidentBytes()
	if err != nil {
		return 95
	}
	_ = c.send("resident", residentSample{Bytes: rss, Valid: true})
	b := scanPolicyMaterialBuffer{}
	summary, err := integrityscan.AcquireWithInventory(context.Background(), cfg.Target, filepath.Dir(cfg.PolicyPath), cfg.PolicyHash, *cfg.Plan, func(r integrityscan.Record) error {
		switch mode {
		case "missing-receipt":
			r.IntegrityScope = nil
		case "endpoint":
			r.IntegrityScope.Reference.Location = "node_modules/other"
		case "catalog":
			r.IntegrityScope.Catalog.ObservedSRI = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		case "source":
			r.IntegrityScope.Manifest.SHA256 = [32]byte{1}
		case "metadata":
			r.IntegrityScope.Directory.Location = "node_modules/other"
		}
		if b.addIntegrityScope(r.IntegrityScope) != nil {
			return errScanProtocol
		}
		if r.Assessment.Differences == nil {
			r.Assessment.Differences = []integrity.Difference{}
		}
		if r.Assessment.Gaps == nil {
			r.Assessment.Gaps = []integrity.Gap{}
		}
		if r.Assessment.Contexts == nil {
			r.Assessment.Contexts = []integrity.ScopedContext{}
		}
		if err := c.send("instance", r); err != nil {
			return err
		}
		return c.send("closure", scanClosure{r.Index, len(r.Assessment.Differences), len(r.Assessment.Gaps)})
	}, func(original projectinventory.Result) error {
		if mode == "missing-native-receipt" || mode == "swapped-native-receipt" {
			v, ok := projectinventory.CompactNPMOriginal(original)
			if !ok {
				return errScanProtocol
			}
			if mode == "missing-native-receipt" {
				v.Receipts = v.Receipts[:len(v.Receipts)-1]
			} else {
				v.Receipts[1].SHA256, v.Receipts[len(v.Receipts)-1].SHA256 = v.Receipts[len(v.Receipts)-1].SHA256, v.Receipts[1].SHA256
			}
			return c.send("npm-root-original", v)
		}
		if mode != "missing-original" {
			ok, err := b.emitOriginal(c.send, original)
			if err != nil {
				return err
			}
			if !ok {
				return errScanProtocol
			}
		}
		p := projectinventory.PortableMatching(original)
		batches := uint32(0)
		if err := projectinventory.WalkBatches(p, func(v projectinventory.InventoryBatch) error { batches++; return c.send("inventory-batch", v) }); err != nil {
			return err
		}
		return c.send("inventory-closure", scanInventoryClosure{Batches: batches, Selection: p.Selection, Counts: p.Counts, Complete: p.Complete})
	})
	if err != nil {
		return 94
	}
	_ = c.send("done", scanDone{Records: summary.Records, Summary: summary})
	return 0
}

// Actual owned native collection through the private protocol, without a policy
// exception/local-detail path. This is receipt admission, not platform acceptance.
func TestWholeIntegrityProtocolAccounting(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned Linux protocol fixture")
	}
	for _, origin := range []string{"fixture:private", "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"} {
		t.Run(origin, func(t *testing.T) { testWholeIntegrityProtocolAccounting(t, origin) })
	}
}

func testWholeIntegrityProtocolAccounting(t *testing.T, origin string) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	prepared := filepath.Join(base, "prepared")
	for _, d := range []string{filepath.Join(target, "node_modules/pkg"), prepared} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	own := []byte(`{"name":"pkg","version":"1.0.0"}`)
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "package/package.json", Size: int64(len(own)), Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(own); err != nil {
		t.Fatal(err)
	}
	if tw.Close() != nil || gz.Close() != nil {
		t.Fatal("archive")
	}
	sum := sha256.Sum256(archive.Bytes())
	sri := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "owned", Provenance: "owned", Manager: "npm@10.9.4", RequiredChecks: []string{"integrity"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{{Location: "node_modules/pkg", LockKey: "node_modules/pkg", Name: "pkg", Version: "1.0.0", Origin: origin, Classification: "unknown", ExpectedSRI: sri, Archive: "pkg.tgz", Context: "none"}}}
	policy, _ := json.Marshal(p)
	sum = sha256.Sum256(policy)
	hash := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	policyPath := filepath.Join(prepared, "policy.json")
	for name, data := range map[string][]byte{policyPath: policy, filepath.Join(prepared, "pkg.tgz"): archive.Bytes(), filepath.Join(target, "package.json"): []byte(`{}`), filepath.Join(target, "node_modules/pkg/package.json"): own, filepath.Join(target, "package-lock.json"): []byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/pkg":{"name":"pkg","version":"1.0.0","resolved":"` + origin + `","integrity":"` + sri + `"}}}`)} {
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	modes := []string{"equal", "missing-original", "missing-receipt", "endpoint", "catalog", "source", "metadata"}
	if strings.HasPrefix(origin, "https:") {
		modes = append(modes, "missing-native-receipt", "swapped-native-receipt")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			plan := integrityscan.Plan{Manager: p.Manager, Policy: p, PolicyFile: "policy.json", Checks: 4}
			run := ScanRun{Plan: plan, Usable: true, output: BatchRun{state: newRunState(ctx)}}
			identity, err := buildIdentity()
			if err != nil {
				t.Fatal(err)
			}
			cfg := scanConfig{Stage: "acquire", Target: target, PolicyPath: policyPath, PolicyHash: hash, Plan: &plan}
			_, err = run.superviseScanPhase(ctx, cfg, exec.Command(os.Args[0], "-test.run=^TestWholeIntegrityProtocolChild$", mode), identity)
			if mode == "endpoint" || mode == "catalog" || mode == "missing-native-receipt" || mode == "swapped-native-receipt" {
				if err == nil {
					t.Fatal("wrong catalog/reference receipt admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "equal" && strings.HasPrefix(origin, "https:") {
				if run.Inventory == nil || run.Inventory.OriginalClaims == nil {
					t.Fatal("compact originals absent")
				}
				v, ok := projectinventory.CompactNPMOriginal(*run.Inventory.OriginalClaims)
				if !ok || len(v.Inputs) != 3 {
					t.Fatal("compact fixture not admitted")
				}
				t.Logf("compact supervised comparisons=%d originals=%d", len(run.Records), len(v.Inputs))
				testCompactNPMSharedBudget(t, v, run.Records[0].IntegrityScope)
			}
			report := integrityscan.BuildReportWithPolicy(plan, run.Records, run.Summary, run.Resources, false, false, run.Inventory, nil, nil, nil, false, time.Now().UTC())
			outcome := ""
			for _, row := range report.Coverage {
				if row.Check == "integrity" {
					outcome = row.Outcome
				}
			}
			want := "incomplete"
			if mode == "equal" {
				want = "completed"
			}
			if outcome != want || report.Findings != 0 || report.ExitCode != 3 {
				t.Fatalf("mode=%s outcome=%s report=%+v", mode, outcome, report)
			}
		})
	}
}

func TestWholeIntegrityReceiptSharesPrivateBudget(t *testing.T) {
	w := &integrityscan.IntegrityScopeWitness{}
	encoded, _ := json.Marshal(w)
	b := scanPolicyMaterialBuffer{bytes: integrityscan.MaxPolicyMaterialBytes - len(encoded)}
	if b.addIntegrityScope(w) != nil || b.bytes != integrityscan.MaxPolicyMaterialBytes || b.addIntegrityScope(w) == nil {
		t.Fatal("byte ceiling")
	}
	b = scanPolicyMaterialBuffer{originalRows: integrityscan.MaxPolicyMaterials - 1}
	if b.addIntegrityScope(w) != nil || b.addIntegrityScope(w) == nil {
		t.Fatal("row ceiling")
	}
	b = scanPolicyMaterialBuffer{closed: true}
	if b.addIntegrityScope(w) == nil {
		t.Fatal("late receipt")
	}
	for _, frameOverflow := range []bool{false, true} {
		r := integrityscan.Record{IntegrityScope: w, Assessment: integrity.InstanceAssessment{Differences: []integrity.Difference{{Kind: integrity.DifferenceModified}}}}
		b = scanPolicyMaterialBuffer{bytes: integrityscan.MaxPolicyMaterialBytes}
		if frameOverflow {
			b = scanPolicyMaterialBuffer{}
			r.Lock.SourceLocator = strings.Repeat("x", maxMessage)
		}
		b.retainIntegrityScope(&r)
		if r.IntegrityScope != nil || len(r.Assessment.Differences) != 1 || b.originalRows != 0 {
			t.Fatal("overflow retained proof or lost findings")
		}
	}
}
