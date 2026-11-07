package integrityscan

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/projectinventory"
)

func TestLocalDetailsSanitizeAndValidateBeforeRendering(t *testing.T) {
	result := newMatchingFixture().inv
	result.Model.Observations[0].Name = "https://PRIVATE-user:PRIVATE-password@host.invalid"
	result.Model.Observations[0].Version = "PRIVATE-token"
	result.Model.Observations[0].Location = "/PRIVATE-absolute"
	details := CollectLocalObservations(result)
	if len(details.Observations) != 1 || details.Observations[0].Name != "" || details.Observations[0].Version != "" || details.Observations[0].Location != "" {
		t.Fatal("invalid metadata became local disclosure", details)
	}
	inventory := projectinventory.Portable(result)
	if ValidateLocalObservation(details.Observations[0], inventory) != nil {
		t.Fatal("sanitized unknowns rejected")
	}
	for _, mutate := range []func(*LocalObservation){
		func(o *LocalObservation) { o.Name = "https://PRIVATE-token@host.invalid" },
		func(o *LocalObservation) { o.Version = "PRIVATE-token" },
		func(o *LocalObservation) { o.Location = "../PRIVATE-escape" },
		func(o *LocalObservation) { o.Location = "/PRIVATE-absolute" },
		func(o *LocalObservation) { o.Observation = 9999 },
	} {
		bad := details.Observations[0]
		mutate(&bad)
		if ValidateLocalObservation(bad, inventory) == nil {
			t.Fatal("unsafe local observation admitted")
		}
	}
	if ValidateLocalAdvisory(LocalAdvisory{Advisory: 1, ID: "PRIVATE-token", SHA256: strings.Repeat("1", 64)}) == nil || ValidateLocalAdvisory(LocalAdvisory{Advisory: 1, SHA256: strings.Repeat("0", 64)}) == nil {
		t.Fatal("uncontrolled advisory ID/zero evidence admitted")
	}
}

func TestLocalAndPortableAreViewsOfTheSameMatchingEvidence(t *testing.T) {
	fixture := newMatchingFixture().inv
	inventory := projectinventory.Portable(fixture)
	snapshot, info := matchingSnapshot(t)
	plan := matchingPinnedPlan(t, info)
	plan.Privacy = "local"
	local := CollectLocalObservations(fixture)
	decisions := []AdvisoryDecision{}
	summary, e := MatchInventoryWithLocal(context.Background(), plan, fixture, snapshot, info, matchingNow, func(d AdvisoryDecision) error { decisions = append(decisions, d); return nil }, func(d LocalAdvisory) error { local.Advisories = append(local.Advisories, d); return nil })
	if e != nil || len(local.Advisories) == 0 {
		t.Fatal("actual owned fixture matching/details unavailable", e)
	}
	a := AdvisoryReport{State: "observed", Decisions: decisions, Summary: summary, Local: &local}
	for _, d := range decisions {
		if d.EnforcementEligible {
			a.Findings++
		}
	}
	if a.Findings != 1 {
		t.Fatal("legacy source fixture support changed", a.Findings)
	}
	localReport := BuildReportWithAdvisories(plan, nil, Summary{}, Resources{}, false, false, &inventory, &info, &a)
	portablePlan := plan
	portablePlan.Privacy = "portable"
	portable := a
	portable.Local = nil
	portableReport := BuildReportWithAdvisories(portablePlan, nil, Summary{}, Resources{}, false, false, &inventory, &info, &portable)
	if localReport.Advisories.State != "observed" || portableReport.Advisories.State != "observed" {
		t.Fatal("valid mode-specific evidence discarded")
	}
	left, _ := json.Marshal(localReport.Advisories.Decisions)
	right, _ := json.Marshal(portableReport.Advisories.Decisions)
	if !bytes.Equal(left, right) || localReport.Advisories.Findings != portableReport.Advisories.Findings || localReport.ExitCode != portableReport.ExitCode {
		t.Fatal("privacy changed semantics")
	}
	for _, format := range []string{"json", "terminal", "sarif"} {
		localBytes, e := Render(localReport, format)
		if e != nil || !bytes.Contains(localBytes, []byte("left-pad")) || !bytes.Contains(localBytes, []byte("node_modules/left-pad")) || !bytes.Contains(localBytes, []byte("MAL-2026-1")) {
			t.Fatal("explicit local output is not actionable", format, e)
		}
		portableBytes, e := Render(portableReport, format)
		if e != nil || bytes.Contains(portableBytes, []byte("left-pad")) || bytes.Contains(portableBytes, []byte("MAL-2026-")) || bytes.Contains(portableBytes, []byte(local.Advisories[0].SHA256)) {
			t.Fatal("portable view leaked local evidence", format, e)
		}
		bad := localReport
		bad.Privacy = "portable"
		if _, e := Render(bad, format); e == nil {
			t.Fatal("local sidecar relabeled portable")
		}
	}
}
