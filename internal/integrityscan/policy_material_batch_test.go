package integrityscan

import "testing"

func TestPolicyMaterialBatchKeepsWholeGraphAndEveryRowAdmission(t *testing.T) {
	plan, inv, decisions, m := engineFixture(t)
	if ValidatePolicyMaterials(plan, inv, nil, decisions, []PolicyMaterial{m}) != nil {
		t.Fatal("honest batch refused")
	}
	bad := m
	bad.Scope.Origin = "https://unrelated.invalid/package.tgz"
	if ValidatePolicyMaterials(plan, inv, nil, decisions, []PolicyMaterial{m, bad}) == nil {
		t.Fatal("later invalid row skipped after common graph admission")
	}
	inv.Evidence[0].ID = 999
	if ValidatePolicyMaterials(plan, inv, nil, decisions, []PolicyMaterial{m}) == nil {
		t.Fatal("invalid shared graph trusted")
	}
	plan.PolicyFile = ""
	if ValidatePolicyMaterials(plan, inv, nil, decisions, nil) == nil {
		t.Fatal("empty batch granted an invalid operational plan")
	}
}
