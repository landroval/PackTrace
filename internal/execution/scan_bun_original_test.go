package execution

import (
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/integrityscan"
	"packtrace/internal/projectinventory"
)

func TestBunOriginalSharesPrivateMaterialBudget(t *testing.T) {
	original := projectinventory.Result{
		Selection: projectinventory.Selection{Family: "bun"},
		Model:     projectinventory.Model{Observations: []projectinventory.Observation{{ID: 1, Name: "private-name"}}, Evidence: []projectinventory.Evidence{{ID: 1}}},
	}
	var sent []string
	send := func(kind string, v any) error { sent = append(sent, kind); return nil }
	b := scanPolicyMaterialBuffer{}
	ok, err := b.emitOriginal(send, original)
	encoded, _ := json.Marshal(projectinventory.PrivateOriginal(original))
	if err != nil || !ok || len(sent) != 1 || sent[0] != "bun-original" || b.bytes != len(encoded) || b.originalRows != 2 {
		t.Fatal("original admission", ok, err, b)
	}
	if b.addOriginal(original) == nil {
		t.Fatal("duplicate acquisition admitted")
	}
	if b.finish(scanPolicyMaterialClosure{Bytes: 0}) == nil {
		t.Fatal("closure renewed private byte budget")
	}
	if b.finish(scanPolicyMaterialClosure{Bytes: len(encoded)}) != nil {
		t.Fatal("closed cumulative witness budget")
	}
	for _, tc := range []struct {
		name     string
		buffer   scanPolicyMaterialBuffer
		original projectinventory.Result
	}{
		{"bytes", scanPolicyMaterialBuffer{bytes: integrityscan.MaxPolicyMaterialBytes - 1}, original},
		{"rows", scanPolicyMaterialBuffer{rows: make([]integrityscan.PolicyMaterial, integrityscan.MaxPolicyMaterials-1)}, original},
		{"frame", scanPolicyMaterialBuffer{}, projectinventory.Result{Selection: projectinventory.Selection{Family: "bun"}, Model: projectinventory.Model{Observations: []projectinventory.Observation{{Name: strings.Repeat("x", maxMessage)}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			ok, err := tc.buffer.emitOriginal(func(string, any) error { called = true; return nil }, tc.original)
			if err != nil || ok || called {
				t.Fatal("oversize acquisition gained authority", ok, err)
			}
		})
	}
}
