package projectinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"testing"
)

func compactNPMFixture() CompactNPMRoot {
	v := CompactNPMRoot{Selection: Selection{Profile: "npm@10.9.4", Family: "npm", File: "package-lock.json", State: "usable", Reason: "none", Explicit: true}, Inputs: []OriginalInput{
		{Source: 2, Bytes: []byte(`{"dependencies":{"pkg":"1.0.0"}}`)},
		{Source: 3, Bytes: []byte(`{"lockfileVersion":3,"packages":{"":{"dependencies":{"pkg":"1.0.0"}},"node_modules/pkg":{"name":"pkg","version":"1.0.0","resolved":"https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"}}}`)},
		{Source: 5, Bytes: []byte(`{"name":"pkg","version":"1.0.0"}`)},
	}, Receipts: []NPMRootReceipt{{Source: 1, Method: "native-metadata"}, {Source: 2, Method: "native-input-lease", Location: "package.json"}, {Source: 3, Method: "native-input-lease", Location: "package-lock.json"}, {Source: 4, Method: "native-metadata-lease", Location: "node_modules/pkg"}, {Source: 5, Method: "native-input-lease", Location: "node_modules/pkg/package.json"}}}
	for _, in := range v.Inputs {
		v.Receipts[in.Source-1].SHA256 = sha256.Sum256(in.Bytes)
	}
	return v
}

func TestCompactNPMOriginalValidation(t *testing.T) {
	v := compactNPMFixture()
	r, err := ExpandCompactNPM(v)
	if err != nil {
		t.Fatal(err)
	}
	p := PortableMatching(r)
	if ValidateOriginalClaims(p) != nil {
		t.Fatal("public/private join")
	}
	compact, ok := CompactNPMOriginal(r)
	if !ok {
		t.Fatal("lossless profile")
	}
	compact.Inputs[0].Bytes[0] = '!'
	if !bytes.Equal(r.OriginalInputs[0].Bytes, v.Inputs[0].Bytes) {
		t.Fatal("profile aliases original bytes")
	}
	v.Inputs[0].Bytes[0] = '!'
	if ValidateOriginalBytes(r) != nil {
		t.Fatal("expanded originals alias input")
	}
	for name, mutate := range map[string]func(*CompactNPMRoot){
		"missing-input":     func(v *CompactNPMRoot) { v.Inputs = v.Inputs[:2] },
		"missing-receipt":   func(v *CompactNPMRoot) { v.Receipts = v.Receipts[:4] },
		"duplicate-input":   func(v *CompactNPMRoot) { v.Inputs[2] = v.Inputs[0] },
		"duplicate-receipt": func(v *CompactNPMRoot) { v.Receipts[4] = v.Receipts[1] },
		"swapped-receipts": func(v *CompactNPMRoot) {
			v.Receipts[1].SHA256, v.Receipts[4].SHA256 = v.Receipts[4].SHA256, v.Receipts[1].SHA256
		},
		"corrupt-input":       func(v *CompactNPMRoot) { v.Inputs[2].Bytes[0] = '!' },
		"metadata-hash":       func(v *CompactNPMRoot) { v.Receipts[3].SHA256[0] = 1 },
		"wrong-method":        func(v *CompactNPMRoot) { v.Receipts[4].Method = "native-metadata" },
		"unsupported-profile": func(v *CompactNPMRoot) { v.Selection.Profile = "npm@999" },
		"nested":              func(v *CompactNPMRoot) { v.Receipts[3].Location = "node_modules/pkg/node_modules/nested" },
		"byte-limit":          func(v *CompactNPMRoot) { v.Inputs[0].Bytes = bytes.Repeat([]byte(" "), maxOriginalInputBytes) },
		"instance-limit":      func(v *CompactNPMRoot) { v.Inputs = make([]OriginalInput, maxCompactNPMInstances+3) },
		"hidden-workspace": func(v *CompactNPMRoot) {
			v.Inputs[0].Bytes = []byte(`{"workspaces":[]}`)
			v.Receipts[1].SHA256 = sha256.Sum256(v.Inputs[0].Bytes)
		},
		"reconstructed-observation-limit": func(v *CompactNPMRoot) {
			deps := map[string]string{}
			for i := 0; i < 4096; i++ {
				deps["pkg"+strconv.Itoa(i)] = "1.0.0"
			}
			v.Inputs[0].Bytes, _ = json.Marshal(map[string]any{"dependencies": deps})
			v.Receipts[1].SHA256 = sha256.Sum256(v.Inputs[0].Bytes)
		},
		"reconstruction-requirement-limit": func(v *CompactNPMRoot) {
			deps := map[string]string{}
			for i := 0; i < 4097; i++ {
				deps["pkg"+strconv.Itoa(i)] = "1.0.0"
			}
			v.Inputs[2].Bytes, _ = json.Marshal(map[string]any{"name": "pkg", "version": "1.0.0", "dependencies": deps})
			v.Receipts[4].SHA256 = sha256.Sum256(v.Inputs[2].Bytes)
		},
		"too-many-lock-records": func(v *CompactNPMRoot) {
			p := map[string]any{}
			for i := 0; i < maxCompactNPMInstances+2; i++ {
				p[string(rune(i+256))] = map[string]any{}
			}
			v.Inputs[1].Bytes, _ = json.Marshal(map[string]any{"lockfileVersion": 3, "packages": p})
			v.Receipts[2].SHA256 = sha256.Sum256(v.Inputs[1].Bytes)
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := compactNPMFixture()
			mutate(&v)
			if _, err := ExpandCompactNPM(v); err == nil {
				t.Fatal("invalid profile admitted")
			}
		})
	}
	p.Observations[0].Source = 5
	if ValidateOriginalClaims(p) == nil {
		t.Fatal("public claims granted private authority")
	}
	r.Model.Evidence[0].Complete = false
	if _, ok := CompactNPMOriginal(r); ok {
		t.Fatal("unsupported acquisition bypassed legacy")
	}
}
