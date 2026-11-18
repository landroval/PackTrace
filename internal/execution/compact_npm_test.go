package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"packtrace/internal/integrityscan"
	"packtrace/internal/nativefs"
	"packtrace/internal/projectinventory"
)

func testCompactNPMSharedBudget(t *testing.T, v projectinventory.CompactNPMRoot, witness *integrityscan.IntegrityScopeWitness) {
	t.Helper()
	encoded, _ := json.Marshal(v)
	rows := len(v.Inputs) + len(v.Receipts) + 1
	b := scanPolicyMaterialBuffer{rows: make([]integrityscan.PolicyMaterial, integrityscan.MaxPolicyMaterials-rows)}
	if _, err := b.addCompactNPM(v); err != nil || b.addIntegrityScope(witness) == nil {
		t.Fatal("shared row ceiling")
	}
	b = scanPolicyMaterialBuffer{bytes: integrityscan.MaxPolicyMaterialBytes - len(encoded)}
	if _, err := b.addCompactNPM(v); err != nil || b.bytes != integrityscan.MaxPolicyMaterialBytes || b.addIntegrityScope(witness) == nil {
		t.Fatal("shared byte ceiling")
	}
	for _, b := range []scanPolicyMaterialBuffer{{closed: true}, {originalRows: 1}, {bytes: integrityscan.MaxPolicyMaterialBytes - len(encoded) + 1}, {rows: make([]integrityscan.PolicyMaterial, integrityscan.MaxPolicyMaterials-rows+1)}} {
		oldRows, oldBytes := b.originalRows, b.bytes
		if _, err := b.addCompactNPM(v); err == nil || b.originalRows != oldRows || b.bytes != oldBytes {
			t.Fatal("failed admission mutated budget")
		}
	}
}

// Same retained 1000-package metadata fixture; actual supervised acquisition,
// without pretending that metadata admission compares installed payloads.
func TestOfflineCompactNPMParentAdmission(t *testing.T) {
	base := os.Getenv("PACKTRACE_COMPACT_NPM_FIXTURE")
	if base == "" {
		t.Skip("requires frozen owned metadata target")
	}
	target := filepath.Join(base, "checked-1000", "target")
	root, err := nativefs.OpenRoot(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := projectinventory.Collect(context.Background(), root, projectinventory.Options{Profile: "npm@10.9.4", ExplicitManager: true, RetainIntegrityOriginals: true})
	ce := root.Close()
	if err != nil || ce != nil {
		t.Fatal(err, ce)
	}
	v, ok := projectinventory.CompactNPMOriginal(inv)
	if !ok {
		t.Fatalf("profile unsupported: selection=%+v observations=%d evidence=%d inputs=%d", inv.Selection, len(inv.Model.Observations), len(inv.Model.Evidence), len(inv.OriginalInputs))
	}
	var wireBytes int
	var b scanPolicyMaterialBuffer
	sent, err := b.emitOriginal(func(kind string, data any) error {
		raw, _ := json.Marshal(data)
		wireBytes = len(raw)
		if kind != "npm-root-original" {
			t.Fatal(kind)
		}
		return nil
	}, inv)
	if !sent || err != nil {
		t.Fatal(sent, err)
	}
	t.Logf("worker rows=%d bytes=%d", b.originalRows, b.bytes)
	if len(v.Inputs) != 1002 || b.originalRows != 3006 {
		t.Fatal("primitive accounting", len(v.Inputs), b.originalRows)
	}
	var frame bytes.Buffer
	if e := newChannel(bytes.NewReader(nil), &frame, &traffic{}).send("npm-root-original", v); e != nil {
		t.Fatal(e)
	}
	env, e := newChannel(bytes.NewReader(frame.Bytes()), &bytes.Buffer{}, &traffic{}).receive()
	if e != nil {
		t.Fatal("receive", e)
	}
	var decoded projectinventory.CompactNPMRoot
	if e := decodeCheckedObject(env.Data, &decoded); e != nil {
		t.Fatal("decode", e)
	}
	var parent scanPolicyMaterialBuffer
	if _, e := parent.addCompactNPM(decoded); e != nil {
		t.Fatal("parent material", e)
	}
	p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "owned", Provenance: "owned", Manager: inv.Selection.Profile, RequiredChecks: []string{"integrity"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{}}
	plan := integrityscan.Plan{Manager: p.Manager, ExplicitManager: true, Policy: p, PolicyFile: "policy.json", Checks: 4}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := ScanRun{Plan: plan, Usable: true, output: BatchRun{state: newRunState(ctx)}}
	identity, err := buildIdentity()
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	policyBytes, _ := json.Marshal(p)
	if err := os.WriteFile(policyPath, policyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(policyBytes)
	cfg := scanConfig{Stage: "acquire", Target: target, PolicyPath: policyPath, PolicyHash: "sha256-" + base64.StdEncoding.EncodeToString(sum[:]), Plan: &plan}
	_, err = run.superviseScanPhase(ctx, cfg, exec.Command(os.Args[0], "-test.run=^TestWholeIntegrityProtocolChild$", "equal"), identity)
	if err != nil {
		t.Fatalf("supervised parent %v inventory=%v resources=%+v", err, run.Inventory != nil, run.Resources)
	}
	if run.Inventory == nil || run.Inventory.OriginalClaims == nil || len(run.Inventory.OriginalClaims.OriginalInputs) != 1002 || projectinventory.ValidateOriginalClaims(*run.Inventory) != nil {
		t.Fatal("parent original admission absent")
	}
	if len(run.Records) != 0 {
		t.Fatal("metadata milestone fabricated comparisons")
	}
	t.Logf("supervised parent admitted originals=%d privateRows=%d privateBytes=%d payloadBytes=%d graph=%d records=%d", len(v.Inputs), b.originalRows, b.bytes, wireBytes, len(inv.Model.Observations)+len(inv.Model.Evidence)+len(inv.Model.Relations), len(run.Records))
}
