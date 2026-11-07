package execution

import (
	"testing"

	"packtrace/internal/integrityscan"
)

func TestPolicyMaterialClosureIsExactAndSingleUse(t *testing.T) {
	limited := scanPolicyMaterialBuffer{limited: true}
	if limited.finish(scanPolicyMaterialClosure{}) == nil {
		t.Fatal("closure erased an admitted producer limitation")
	}
	if limited.finish(scanPolicyMaterialClosure{Limited: true}) != nil {
		t.Fatal("closure lost an honest producer limitation")
	}
	for _, v := range []scanPolicyMaterialClosure{{Rows: 1}, {Bytes: 1}, {Rows: -1}, {Bytes: -1}} {
		var b scanPolicyMaterialBuffer
		if b.finish(v) == nil || b.closed {
			t.Fatalf("accepted inconsistent closure: %+v", v)
		}
	}
	var b scanPolicyMaterialBuffer
	if b.finish(scanPolicyMaterialClosure{Limited: true}) != nil || !b.closed || !b.limited {
		t.Fatal("did not retain explicit material limitation")
	}
	if b.finish(scanPolicyMaterialClosure{}) == nil {
		t.Fatal("accepted duplicate closure")
	}
	if b.accept(integrityscan.PolicyMaterial{}) == nil {
		t.Fatal("accepted a row after closure")
	}
}

func TestPolicyMaterialLimitDoesNotInvokeTransportOrHideFindings(t *testing.T) {
	b := scanPolicyMaterialBuffer{limited: true}
	called := false
	send := func(string, any) error { called = true; return nil }
	if b.emit(send, integrityscan.PolicyMaterial{}) != nil || called || len(b.rows) != 0 {
		t.Fatal("material exhaustion attempted more evidence/transport")
	}
	if b.close(func(kind string, value any) error {
		called = true
		v, ok := value.(scanPolicyMaterialClosure)
		if kind != "policy-material-closure" || !ok || !v.Limited || v.Rows != 0 || v.Bytes != 0 {
			t.Fatalf("lost material-only limitation: %s %+v", kind, value)
		}
		return nil
	}) != nil || !called || !b.closed {
		t.Fatal("failed to close bounded evidence")
	}
}
