package integrityscan

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"packtrace/internal/cli"
)

func TestIntegrityCheckFrozenAuthority(t *testing.T) {
	for _, locations := range [][]string{{"node_modules/pkg"}, {}} {
		plan, _, root, prepared := wholeFixture(t, locations, false)
		plan.Policy.MinimumAssurance = "independently-anchored"
		plan, hash := fixturePlan(t, filepath.Join(prepared, "policy.json"), plan.Policy)
		plan.TrustedPolicyDigest = hash
		records, inventory, summary := wholeAcquire(t, plan, hash, root, prepared)
		report := wholeReport(plan, records, inventory, summary)
		_, conditions, err := RenderIntegrityCheck(report)
		if err != nil || cli.SelectScanExit(conditions) != 0 {
			t.Fatalf("real evidence refused: %v %+v", err, conditions)
		}
		// Original caller aliases cannot rewrite the frozen comparison decision.
		plan.Policy.References = nil
		if len(records) > 0 {
			records[0].IntegrityScope = nil
		}
		if _, conditions, err := RenderIntegrityCheck(report); err != nil || cli.SelectScanExit(conditions) != 0 {
			t.Fatal("aliased original changed frozen decision")
		}
		data, _ := json.Marshal(report)
		var public Report
		if err := json.Unmarshal(data, &public); err != nil {
			t.Fatal(err)
		}
		if _, _, err := RenderIntegrityCheck(public); err == nil {
			t.Fatal("public JSON minted check authority")
		}
		report.ExitCode = 0
		if _, _, err := RenderIntegrityCheck(report); err == nil {
			t.Fatal("mutated report rendered")
		}
	}
}
