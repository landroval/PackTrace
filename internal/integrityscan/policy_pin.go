package integrityscan

import (
	"bytes"
	"context"
	"packtrace/internal/integrity"
)

// OperatorReferenceAuthorityComplete concerns only explicitly pinned reference
// bindings, never native qualification or publisher authenticity. Its caller
// must validate records against the parent-owned plan first.
func OperatorReferenceAuthorityComplete(plan Plan, records []Record) bool {
	if plan.TrustedPolicyDigest == "" || !supportedPolicyPin(plan.TrustedPolicyDigest) || len(records) == 0 || len(records) != len(plan.Policy.References) {
		return false
	}
	for i, r := range records {
		if r.Index != i || r.Assessment.Assurance != integrity.AssuranceIndependent {
			return false
		}
	}
	return true
}

// A match authenticates only the bytes explicitly trusted by the operator,
// not a publisher, registry, provenance assertion or benign content.
func policyPinMatches(ctx context.Context, pin string, data []byte) bool {
	checked, e := integrity.CheckReferenceDigest(ctx, pin, bytes.NewReader(data), MaxPolicyBytes)
	return e == nil && checked.State == integrity.DigestMatch
}
func supportedPolicyPin(pin string) bool {
	checked, e := integrity.CheckReferenceDigest(context.Background(), pin, bytes.NewReader(nil), 0)
	return e == nil && checked.State != integrity.DigestUnknown
}
