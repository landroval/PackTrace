package execution

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"packtrace/internal/integrityscan"
	"packtrace/internal/projectinventory"
)

func TestBunOriginalInputAdmission(t *testing.T) {
	for _, kind := range []string{"absent", "corrupt", "receipt", "duplicate", "oversize", "parse", "semantic"} {
		t.Run(kind, func(t *testing.T) {
			original := bunProtocolOriginal()
			switch kind {
			case "absent":
				original.OriginalInputs = nil
			case "corrupt":
				original.OriginalInputs[0].Bytes[0] = '!'
			case "receipt":
				original.Model.Evidence[0].SHA256 = [32]byte{1}
			case "duplicate":
				original.OriginalInputs = append(original.OriginalInputs, original.OriginalInputs[0])
			case "oversize":
				original.OriginalInputs[0].Bytes = bytes.Repeat([]byte(" "), (512<<10)+1)
				original.Model.Evidence[0].SHA256 = sha256.Sum256(original.OriginalInputs[0].Bytes)
			case "parse":
				original.OriginalInputs[0].Bytes = []byte(`{`)
				original.Model.Evidence[0].SHA256 = sha256.Sum256(original.OriginalInputs[0].Bytes)
			case "semantic":
				original.Model.Observations[0].Fields["matching-context"] = "unsupported"
			}
			b := scanPolicyMaterialBuffer{}
			if b.addOriginal(original) == nil || b.bytes != 0 || b.originalRows != 0 {
				t.Fatal("invalid original admitted/charged")
			}
			called := false
			ok, err := b.emitOriginal(func(string, any) error { called = true; return nil }, original)
			if ok || err != nil || called {
				t.Fatal("invalid original emitted as authority")
			}
		})
	}
	original := projectinventory.PrivateOriginal(bunProtocolOriginal())
	encoded, _ := json.Marshal(original)
	var decoded projectinventory.Result
	if decode(encoded, &decoded) != nil || projectinventory.ValidateOriginalBytes(decoded) != nil {
		t.Fatal("strict original byte round trip")
	}
	b := scanPolicyMaterialBuffer{rows: make([]integrityscan.PolicyMaterial, integrityscan.MaxPolicyMaterials-(len(original.Model.Observations)+len(original.Model.Evidence)+len(original.OriginalInputs)))}
	if b.addOriginal(original) != nil {
		t.Fatal("exact cumulative original/raw/material row allowance")
	}
	if b.originalRows+len(b.rows) != integrityscan.MaxPolicyMaterials {
		t.Fatal("raw rows not charged")
	}
	b = scanPolicyMaterialBuffer{rows: append(b.rows, integrityscan.PolicyMaterial{})}
	if b.addOriginal(original) == nil {
		t.Fatal("raw rows escaped cumulative row cap")
	}
}
