package integrityscan

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"packtrace/internal/cli"
	"packtrace/internal/projectinventory"
)

func TestPolicyEvidenceBuiltinMatchingRemainsUnqualified(t *testing.T) {
	plan, err := ConfigureBuiltin(cli.ScanArgumentRequest{Manager: "auto", Checks: cli.ArgumentCheckMalicious, Privacy: "portable", Output: "-"})
	if err != nil {
		t.Fatal(err)
	}
	inv := newMatchingFixture().inv
	info := UnavailableIntelligence()
	rows := []AdvisoryDecision{}
	summary, err := MatchInventoryWithPolicyEvidence(context.Background(), plan, inv, nil, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil }, nil, func(PolicyMaterial) error { t.Fatal("builtin emitted granting material"); return nil })
	if err != nil || len(rows) != 1 || rows[0].EnforcementEligible || rows[0].Origin != "unqualified" || summary.BytesRead != 0 {
		t.Fatal(rows, summary, err)
	}
	public := projectinventory.PortableMatching(inv)
	if err := ValidateAdvisoryDecision(plan, public, info, rows[0]); err != nil {
		t.Fatal("builtin decision rejected", err)
	}
	if err := ValidateAdvisorySummary(summary, rows, public); err != nil {
		t.Fatal("builtin closure rejected", err)
	}
}

func TestPolicyEvidenceMatchingWrapperPrivacyAndErrors(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	plan := matchingPinnedPlan(t, info)
	inv := newMatchingFixture().inv
	inv.Model.Evidence[0].SHA256 = sha256.Sum256([]byte("selected lock original bytes"))
	inv.Model.Evidence = append(inv.Model.Evidence, projectinventory.Evidence{ID: 2, Scope: 1, Location: "package.json", Method: "native-input-lease", Complete: true, SHA256: sha256.Sum256([]byte("root manifest original bytes"))})
	run := func(p Plan, emitter PolicyEvidenceEmitter) ([]AdvisoryDecision, AdvisorySummary, error) {
		rows := []AdvisoryDecision{}
		summary, err := MatchInventoryWithPolicyEvidence(context.Background(), p, inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil }, nil, emitter)
		return rows, summary, err
	}
	var local []PolicyMaterial
	plan.Privacy = "local"
	rows, summary, err := run(plan, func(m PolicyMaterial) error { local = append(local, m); return nil })
	if err != nil || len(local) != 1 {
		t.Fatalf("local receipt count %d: %v", len(local), err)
	}
	plan.Policy.Exceptions = []Exception{{ID: "exact-review", Reason: "reviewed original", Owner: "reviewer", ApprovedAt: "2026-10-01T00:00:00Z", ExpiresAt: "2026-10-31T00:00:00Z", Scope: local[0].Scope, Acceptance: AcceptanceFingerprint(local[0])}}
	plan.Privacy = "portable"
	var portable []PolicyMaterial
	portableRows, portableSummary, err := run(plan, func(m PolicyMaterial) error { portable = append(portable, m); return nil })
	if err != nil || !reflect.DeepEqual(local, portable) || !reflect.DeepEqual(rows, portableRows) || !reflect.DeepEqual(summary, portableSummary) {
		t.Fatalf("privacy changed policy evidence: %v\nlocal %+v\nportable %+v", err, local, portable)
	}
	if err := ValidatePolicyMaterial(plan, projectinventory.PortableMatching(inv), nil, portableRows, portable[0]); err != nil {
		t.Fatalf("parent rejected producer receipt: %v", err)
	}
	sentinel := errors.New("receipt stopped")
	if _, _, err := run(plan, func(PolicyMaterial) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("receipt callback error swallowed: %v", err)
	}
	plan.Policy.Exceptions = nil
	emitted := 0
	if _, _, err := run(plan, func(PolicyMaterial) error { emitted++; return nil }); err != nil || emitted != 0 {
		t.Fatal("portable/no exceptions retained unnecessary material", err, emitted)
	}
}
