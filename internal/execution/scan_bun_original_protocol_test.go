package execution

import (
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/integrityscan"
	"packtrace/internal/nativefs"
	"packtrace/internal/projectinventory"
)

// Owned synthetic acquisition claims exercise IPC admission, not native truth.
func bunProtocolOriginal() projectinventory.Result {
	return projectinventory.Result{
		Complete:  true,
		Selection: projectinventory.Selection{Family: "bun", Profile: "bun@1.3.x", File: "bun.lock", State: "usable", Reason: "none"},
		Model: projectinventory.Model{
			Scopes: []projectinventory.Scope{{ID: 1, Kind: "project", Status: "complete"}},
			Evidence: []projectinventory.Evidence{
				{ID: 1, Scope: 1, Location: "package.json", Method: "native-input-lease", Complete: true, SHA256: [32]byte{1}},
				{ID: 2, Scope: 1, Location: "bun.lock", Method: "native-input-lease", Complete: true, SHA256: [32]byte{2}},
			},
			Observations: []projectinventory.Observation{{ID: 1, Workspace: 1, Source: 2, Class: "locked", Kind: "package", Status: "complete", Location: "left-pad", Name: "left-pad", Version: "1.0.0", Fields: map[string]string{
				"tuple-key": "left-pad", "matching-context": "supported", "name-state": "value", "resolution-state": "value", "registry-state": "value", "integrity-state": "value", "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
			}}},
		},
	}
}

func TestBunOriginalProtocolChild(t *testing.T) {
	if len(os.Args) != 3 || os.Args[1] != "-test.run=^TestBunOriginalProtocolChild$" {
		return
	}
	os.Exit(bunOriginalProtocolChild(os.Args[2]))
}

func bunOriginalProtocolChild(mode string) int {
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
	if _, err := c.receive(); err != io.EOF {
		return 96
	}
	_ = c.send("start", scanStart{cfg.Stage})
	rss, err := nativefs.OwnResidentBytes()
	if err != nil {
		return 95
	}
	_ = c.send("resident", residentSample{Bytes: rss, Valid: true})
	info := integrityscan.UnavailableIntelligence()
	_ = c.send("intel-state", info)
	_ = c.send("intel-closure", scanIntelligenceClosure{1})
	original := bunProtocolOriginal()
	b := scanPolicyMaterialBuffer{}
	if mode != "missing" {
		if _, err := b.emitOriginal(c.send, original); err != nil {
			return 94
		}
	}
	if mode == "duplicate" {
		_ = c.send("bun-original", original)
	}
	p := projectinventory.PortableMatching(original)
	if mode == "projection" {
		p.Selection.Evidence = 1
	}
	batches := uint32(0)
	if projectinventory.WalkBatches(p, func(v projectinventory.InventoryBatch) error { batches++; return c.send("inventory-batch", v) }) != nil {
		return 93
	}
	_ = c.send("inventory-closure", scanInventoryClosure{Batches: batches, Selection: p.Selection, Counts: p.Counts, Complete: p.Complete})
	if mode == "late" {
		_ = c.send("bun-original", original)
	}
	summary, err := integrityscan.MatchInventory(context.Background(), *cfg.Plan, original, nil, info, time.Now(), func(d integrityscan.AdvisoryDecision) error {
		if mode == "cross-grant" {
			d.Rule = 2
		}
		return c.send("matching-decision", d)
	})
	if err != nil {
		return 92
	}
	_ = c.send("matching-closure", summary)
	_ = c.send("done", scanDone{Summary: integrityscan.Summary{InventoryComplete: original.Complete, AuthorityComplete: integrityscan.OperatorReferenceAuthorityComplete(*cfg.Plan, nil)}})
	return 0
}

func TestBunOriginalProtocolAdmission(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned local process controls")
	}
	for _, mode := range []string{"valid", "missing", "duplicate", "projection", "late", "cross-grant"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			policy := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "owned", Provenance: "owned", Manager: "bun@1.3.x", RequiredChecks: []string{"malicious"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{}, BunOrigins: []integrityscan.BunOriginRule{
				{Location: "left-pad", Name: "left-pad", Version: "1.0.0", Origin: "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz"},
				{Location: "other", Name: "other", Version: "1.0.0", Origin: "https://registry.npmjs.org/other/-/other-1.0.0.tgz"},
			}}
			plan := integrityscan.Plan{Manager: policy.Manager, Policy: policy, Checks: cli.ArgumentCheckMalicious, TrustedPolicyDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
			run := ScanRun{Plan: plan, Usable: true, output: BatchRun{state: newRunState(ctx)}}
			cmd := exec.Command(os.Args[0], "-test.run=^TestBunOriginalProtocolChild$", mode)
			identity, err := buildIdentity()
			if err != nil {
				t.Fatal(err)
			}
			cfg := scanConfig{Stage: "acquire", Target: t.TempDir(), PolicyPath: t.TempDir() + "/p.json", PolicyHash: plan.TrustedPolicyDigest, Plan: &plan, Intelligence: &scanIntelligenceConfig{}}
			_, err = run.superviseScanPhase(ctx, cfg, cmd, identity)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("protocol outcome: %v process=%v inventory=%+v advisories=%+v", err, cmd.ProcessState, run.Inventory, run.Advisories)
			}
			if mode == "valid" && (run.Inventory == nil || run.Inventory.OriginalClaims == nil || run.Advisories == nil || run.Advisories.Decisions[0].Origin != "operator-bun-rule") {
				t.Fatal("positive bound tuple lost")
			}
		})
	}
}
