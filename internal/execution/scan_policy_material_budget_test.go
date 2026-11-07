package execution

import (
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/integrityscan"
)

func TestPolicyMaterialEmitterAndReceiverEnforceExactCeilings(t *testing.T) {
	p := integrityscan.ProjectEvidence{Scope: 1, Manifest: 1, Lock: 2, ManifestSHA256: strings.Repeat("1", 64), LockSHA256: strings.Repeat("2", 64), Profile: "npm@10.9.4", LockFile: "package-lock.json"}
	m := integrityscan.PolicyMaterial{Project: p, Scope: integrityscan.FindingScope{Project: integrityscan.ProjectFingerprint(p), Category: "malicious", Rule: "osv-npm", Class: "locked", Package: "pkg", Version: "1.0.0", Origin: "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", Instance: "node_modules/pkg", Advisory: "MAL-2026-1"}, Observation: 1, Advisory: 1, SourceSHA256: p.LockSHA256, LockSourceSHA256: p.LockSHA256, OriginalSHA256: strings.Repeat("3", 64), Profile: "openssf-malicious-v1"}
	encoded, err := json.Marshal(m)
	if err != nil || integrityscan.ValidatePolicyMaterialShape(m) != nil {
		t.Fatal("valid private material fixture")
	}
	for _, tc := range []struct {
		name   string
		buffer scanPolicyMaterialBuffer
	}{
		{"rows", scanPolicyMaterialBuffer{rows: make([]integrityscan.PolicyMaterial, integrityscan.MaxPolicyMaterials)}},
		{"bytes", scanPolicyMaterialBuffer{bytes: integrityscan.MaxPolicyMaterialBytes - len(encoded) + 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.buffer
			rows, bytes := len(b.rows), b.bytes
			calls := 0
			if b.emit(func(string, any) error { calls++; return nil }, m) != nil || !b.limited || calls != 0 || len(b.rows) != rows || b.bytes != bytes {
				t.Fatal("emitter exceeded ceiling or hid limit")
			}
			b = tc.buffer
			if b.accept(m) == nil || len(b.rows) != rows || b.bytes != bytes {
				t.Fatal("receiver accepted over-limit row")
			}
		})
	}
	b := scanPolicyMaterialBuffer{bytes: integrityscan.MaxPolicyMaterialBytes - len(encoded)}
	calls := 0
	if b.emit(func(string, any) error { calls++; return nil }, m) != nil || b.bytes != integrityscan.MaxPolicyMaterialBytes || len(b.rows) != 1 || b.limited || calls != 1 {
		t.Fatal("exact ceiling refused or miscounted")
	}
	if b.emit(func(string, any) error { calls++; return nil }, m) != nil || !b.limited || calls != 1 || len(b.rows) != 1 {
		t.Fatal("work continued beyond exact byte ceiling")
	}
}
