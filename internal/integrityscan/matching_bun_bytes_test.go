package integrityscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/inventory"
	"packtrace/internal/projectinventory"
)

func TestBunOriginalBytesRejectSameReceiptContext(t *testing.T) {
	snap, info := matchingSnapshot(t)
	for _, kind := range []string{"document", "info", "root-alias", "root-peer", "manifest-name", "manifest-version", "manifest-peer"} {
		t.Run(kind, func(t *testing.T) {
			p, f := bunEligibleFixture(t, info)
			p.Privacy = "local"
			var ds []AdvisoryDecision
			var ms []PolicyMaterial
			_, err := MatchInventoryWithPolicyEvidence(context.Background(), p, f.inv, snap, info, matchingNow, func(d AdvisoryDecision) error { ds = append(ds, d); return nil }, nil, func(m PolicyMaterial) error { ms = append(ms, m); return nil })
			if err != nil || len(ms) != 2 {
				t.Fatal("positive fixture", err, len(ms))
			}
			// Keep the actual retained bytes and their receipt fixed while replacing
			// only semantic claims that the public numeric inventory deliberately hides.
			source := uint32(1)
			raw := string(f.inv.OriginalInputs[0].Bytes)
			switch kind {
			case "document":
				raw = strings.Replace(raw, `"lockfileVersion":1`, `"lockfileVersion":1,"patchedDependencies":{}`, 1)
			case "info":
				raw = strings.Replace(raw, `"",{}`, `"",{"unknown-context":true}`, 1)
			case "root-alias":
				source = 4
				raw = `{"dependencies":{"left-pad":"npm:other@1.0.0"}}`
			case "root-peer":
				source = 4
				raw = `{"peerDependencies":{"left-pad":"1.0.0"}}`
			case "manifest-name":
				source = 3
				raw = `{"name":"other","version":"1.0.0"}`
			case "manifest-version":
				source = 3
				raw = `{"name":"left-pad","version":"2.0.0"}`
			case "manifest-peer":
				source = 3
				raw = `{"name":"left-pad","version":"1.0.0","peerDependencies":{"left-pad":"1.0.0"}}`
			}
			for i := range f.inv.OriginalInputs {
				if f.inv.OriginalInputs[i].Source == source {
					f.inv.OriginalInputs[i].Bytes = []byte(raw)
				}
			}
			f.inv.Model.Evidence[source-1].SHA256 = sha256.Sum256([]byte(raw))
			if kind == "root-alias" || kind == "root-peer" {
				group, requirement := "dependencies", "1.0.0"
				if kind == "root-peer" {
					group = "peerDependencies"
				}
				f.inv.Model.Observations = append(f.inv.Model.Observations, projectinventory.Observation{ID: 4, Workspace: 1, Source: 4, Class: "declared", Kind: group, Status: "complete", Location: "package.json", Name: "unrelated", Requirement: requirement, Fields: map[string]string{"requirement-state": "value"}})
			}
			forged := projectinventory.PrivateOriginal(f.inv)
			ds, ms = nil, nil
			_, err = MatchInventoryWithPolicyEvidence(context.Background(), p, forged, snap, info, matchingNow, func(d AdvisoryDecision) error { ds = append(ds, d); return nil }, nil, func(m PolicyMaterial) error { ms = append(ms, m); return nil })
			if err != nil || len(ms) != 2 {
				t.Fatal("forged child proposal did not exercise eligibility", err, len(ms))
			}
			honest := projectinventory.PrivateOriginal(f.inv)
			switch kind {
			case "document", "info":
				honest.Model.Observations[0].Fields["matching-context"] = "unsupported"
			case "root-alias":
				honest.Model.Observations[3].Name = "left-pad"
				honest.Model.Observations[3].Requirement = "npm:other@1.0.0"
			case "root-peer":
				honest.Model.Observations[3].Name = "left-pad"
			case "manifest-name":
				honest.Model.Observations[1].Name = "other"
			case "manifest-version":
				honest.Model.Observations[1].Version = "2.0.0"
			case "manifest-peer":
				doc, err := inventory.ParseManifest([]byte(raw))
				if err != nil {
					t.Fatal(err)
				}
				groups, err := inventory.ProjectManifest(doc)
				if err != nil {
					t.Fatal(err)
				}
				honest.Model.Observations[1].Requirements = groups.Groups
			}
			a := projectinventory.PortableMatching(honest)
			b := projectinventory.PortableMatching(forged)
			aj, _ := json.Marshal(a)
			bj, _ := json.Marshal(b)
			if !bytes.Equal(aj, bj) {
				t.Fatal("public projection or claimed receipt changed")
			}
			if projectinventory.ValidateOriginalBytes(honest) != nil || projectinventory.ValidateOriginalClaims(a) != nil {
				t.Fatal("honest original does not match actual retained bytes")
			}
			if projectinventory.ValidateOriginalBytes(forged) == nil || projectinventory.ValidateOriginalClaims(b) == nil {
				t.Fatal("original admission accepted semantic substitution")
			}
			for _, d := range ds {
				if d.Origin == "operator-bun-rule" && ValidateAdvisoryDecision(p, b, info, d) == nil {
					t.Fatal("parent decision accepted semantic substitution")
				}
			}
			if ValidatePolicyMaterials(p, b, nil, ds, ms) == nil {
				t.Fatal("parent material accepted semantic substitution")
			}
		})
	}
}
