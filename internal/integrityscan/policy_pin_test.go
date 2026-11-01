package integrityscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"packtrace/internal/integrity"
	"testing"
)

func TestOperatorAuthorityRequiresEveryExplicitReferenceBinding(t *testing.T) {
	p, e := ParsePolicy([]byte(policyJSON))
	if e != nil {
		t.Fatal("fixture")
	}
	plan := Plan{Policy: p, TrustedPolicyDigest: sourceSRI([]byte(policyJSON))}
	records := []Record{{Assessment: integrity.InstanceAssessment{Assurance: integrity.AssuranceIndependent}}}
	if !OperatorReferenceAuthorityComplete(plan, records) {
		t.Fatal("pinned independent bindings not recognized")
	}
	if OperatorReferenceAuthorityComplete(plan, nil) {
		t.Fatal("missing records acquired authority")
	}
	unpinned := plan
	unpinned.TrustedPolicyDigest = ""
	if OperatorReferenceAuthorityComplete(unpinned, records) {
		t.Fatal("missing pin acquired authority")
	}
	records[0].Assessment.Assurance = integrity.AssuranceLockfile
	if OperatorReferenceAuthorityComplete(plan, records) {
		t.Fatal("lockfile consistency promoted to independence")
	}
}

func TestOperatorPolicyPinMatchesExactBytesAcrossStrongDigests(t *testing.T) {
	data := []byte("owned operator baseline")
	a := sha256.Sum256(data)
	b := sha512.Sum384(data)
	c := sha512.Sum512(data)
	for _, pin := range []string{"sha256-" + base64.StdEncoding.EncodeToString(a[:]), "sha384-" + base64.StdEncoding.EncodeToString(b[:]), "sha512-" + base64.StdEncoding.EncodeToString(c[:])} {
		if !supportedPolicyPin(pin) || !policyPinMatches(context.Background(), pin, data) {
			t.Fatal("valid strong operator pin refused")
		}
		if policyPinMatches(context.Background(), pin, append(bytes.Clone(data), 'x')) {
			t.Fatal("changed policy accepted")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if policyPinMatches(ctx, pin, data) {
			t.Fatal("cancellation granted authority")
		}
	}
	for _, pin := range []string{"", "md5-PRIVATE", "sha256-PRIVATE", "sha256-" + base64.StdEncoding.EncodeToString(a[:]) + " sha256-" + base64.StdEncoding.EncodeToString(a[:])} {
		if supportedPolicyPin(pin) || policyPinMatches(context.Background(), pin, data) {
			t.Fatal("missing/unsupported policy pin granted authority")
		}
	}
	pin := "sha256-" + base64.StdEncoding.EncodeToString(a[:])
	if policyPinMatches(context.Background(), pin, make([]byte, MaxPolicyBytes+1)) {
		t.Fatal("oversize policy accepted")
	}
}
