package execution

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"packtrace/internal/integrityscan"
	"packtrace/internal/projectinventory"
)

// Owned protocol-only evidence stays explicitly incomplete. It is never a
// fixture claiming that a native scan or producer qualification occurred.
func sendFaultInventory(c *channel, mode string) {
	scopes := []projectinventory.PublicScope{{ID: 1, Kind: "project", Status: "incomplete"}}
	if mode == "inventory-duplicate-id" {
		scopes = append(scopes, scopes[0])
	}
	bs := []projectinventory.InventoryBatch{{Scopes: scopes}, {Evidence: []projectinventory.PublicEvidence{{ID: 1, Scope: 1, Method: "native-metadata", Status: "incomplete"}}}}
	counts := projectinventory.Counters{Scopes: len(scopes), Evidence: 1, Gaps: 1}
	if mode == "inventory-orphan" || mode == "inventory-class" {
		o := projectinventory.PublicObservation{ID: 1, Workspace: 1, Source: 1, Class: "installed", Kind: "directory", Status: "unreadable"}
		if mode == "inventory-orphan" {
			o.Source = 9999
		} else {
			o.Class = "PRIVATE-invalid-class"
		}
		bs = append(bs, projectinventory.InventoryBatch{Observations: []projectinventory.PublicObservation{o}})
		counts.Installed = 1
	}
	bs = append(bs, projectinventory.InventoryBatch{Gaps: []projectinventory.Gap{{Scope: 1, Evidence: 1, Code: "discovery-incomplete"}}})
	for i := range bs {
		bs[i].Sequence = uint32(i)
	}
	if mode == "inventory-sequence" {
		bs[0].Sequence = 1
	}
	for _, b := range bs {
		_ = c.send("inventory-batch", b)
	}
	if mode == "inventory-no-closure" {
		return
	}
	if mode == "inventory-count" {
		counts.Installed++
	}
	closure := struct {
		Batches   uint32                           `json:"batches"`
		Selection projectinventory.PublicSelection `json:"selection"`
		Counts    projectinventory.Counters        `json:"counts"`
		Complete  bool                             `json:"complete"`
	}{Batches: uint32(len(bs)), Selection: projectinventory.PublicSelection{Family: "npm", State: "unusable", Reason: "candidate-unusable"}, Counts: counts, Complete: mode == "inventory-forged-completion"}
	_ = c.send("inventory-closure", closure)
	if mode == "inventory-double-closure" {
		_ = c.send("inventory-closure", closure)
	}
	if mode == "inventory-late-batch" {
		bs[0].Sequence = uint32(len(bs))
		_ = c.send("inventory-batch", bs[0])
	}
}
func TestInventoryProtocolCannotAuthorizeForgedClosures(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned native test process")
	}
	p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "fixture", Provenance: "fixture", Manager: "npm@10.9.4", RequiredChecks: []string{"integrity"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{{Location: "node_modules/p", LockKey: "node_modules/p", Name: "p", Version: "1.0.0", Origin: "fixture:p", Classification: "unknown", ExpectedSRI: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Archive: "p.tgz", Context: "none"}}}
	plan := integrityscan.Plan{Manager: p.Manager, Policy: p, Checks: 4}
	for _, mode := range []string{"inventory-duplicate-id", "inventory-orphan", "inventory-class", "inventory-count", "inventory-sequence", "inventory-no-closure", "inventory-double-closure", "inventory-late-batch", "inventory-forged-completion"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			s := newRunState(ctx)
			run := ScanRun{Plan: plan, Usable: true, output: BatchRun{state: s}}
			cmd := exec.Command(os.Args[0], "--scan-fault-driver", mode)
			identity, e := buildIdentity()
			if e != nil {
				t.Fatal(e)
			}
			cfg := scanConfig{Stage: "acquire", Target: t.TempDir(), PolicyPath: t.TempDir() + "/p.json", PolicyHash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Plan: &plan}
			_, e = run.superviseScanPhase(ctx, cfg, cmd, identity)
			if e == nil || len(run.Records) != 0 || cmd.ProcessState == nil || run.Summary.InventoryComplete {
				t.Fatal("forged/early inventory accepted", mode, e)
			}
		})
	}
}
