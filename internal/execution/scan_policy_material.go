package execution

import (
	"encoding/json"

	"packtrace/internal/integrityscan"
)

// Private evidence has its own smaller ceiling and is also charged by channel
// to the existing shared frame/traffic budget. Exhaustion is not a finding loss.
type scanPolicyMaterialClosure struct {
	Rows    int  `json:"rows"`
	Bytes   int  `json:"bytes"`
	Limited bool `json:"limited"`
}

type scanPolicyMaterialBuffer struct {
	rows    []integrityscan.PolicyMaterial
	bytes   int
	limited bool
	closed  bool
}

func policyMaterialWanted(plan *integrityscan.Plan) bool {
	return plan != nil && (integrityscan.PlanPrivacy(*plan) == "local" || len(plan.Policy.Exceptions) != 0)
}

// accept never certifies physical truth or evaluates exceptions. Semantic joins
// are checked after the related admitted inventory/decision/instance closures.
func (b *scanPolicyMaterialBuffer) accept(v integrityscan.PolicyMaterial) error {
	if b.closed || integrityscan.ValidatePolicyMaterialShape(v) != nil {
		return errScanProtocol
	}
	encoded, e := json.Marshal(v)
	if e != nil || len(encoded) > maxMessage-4096 || len(b.rows) >= integrityscan.MaxPolicyMaterials || len(encoded) > integrityscan.MaxPolicyMaterialBytes-b.bytes {
		return errScanProtocol
	}
	b.rows = append(b.rows, v)
	b.bytes += len(encoded)
	return nil
}

// Witnesses arrive with independently admitted integrity records. Their encoded
// bytes share the smaller acceptance-evidence ceiling, not a renewed budget.
func (b *scanPolicyMaterialBuffer) addWitnesses(rows []integrityscan.PolicyDifferenceWitness) error {
	if b.closed || len(rows) > integrityscan.MaxPolicyMaterials {
		return errScanProtocol
	}
	if len(rows) == 0 {
		return nil
	}
	encoded, err := json.Marshal(rows)
	if err != nil || len(encoded) > integrityscan.MaxPolicyMaterialBytes-b.bytes {
		return errScanProtocol
	}
	b.bytes += len(encoded)
	return nil
}

func (b *scanPolicyMaterialBuffer) finish(v scanPolicyMaterialClosure) error {
	if b.closed || v.Rows != len(b.rows) || v.Bytes != b.bytes || b.limited && !v.Limited {
		return errScanProtocol
	}
	b.closed = true
	b.limited = v.Limited
	return nil
}

func (b *scanPolicyMaterialBuffer) emit(send func(string, any) error, v integrityscan.PolicyMaterial) error {
	if b.closed {
		return errScanProtocol
	}
	if b.limited {
		return nil
	}
	if integrityscan.ValidatePolicyMaterialShape(v) != nil {
		return errScanProtocol
	}
	encoded, e := json.Marshal(v)
	if e != nil {
		return errScanProtocol
	}
	if len(encoded) > maxMessage-4096 || len(b.rows) >= integrityscan.MaxPolicyMaterials || len(encoded) > integrityscan.MaxPolicyMaterialBytes-b.bytes {
		b.limited = true
		return nil
	}
	if e := send("policy-material", v); e != nil {
		return e
	}
	b.rows = append(b.rows, v)
	b.bytes += len(encoded)
	return nil
}

func (b *scanPolicyMaterialBuffer) close(send func(string, any) error) error {
	if b.closed {
		return errScanProtocol
	}
	b.closed = true
	return send("policy-material-closure", scanPolicyMaterialClosure{Rows: len(b.rows), Bytes: b.bytes, Limited: b.limited})
}
