package integrityscan

import (
	"fmt"
	"strings"

	"packtrace/internal/cli"
	"packtrace/internal/projectinventory"
)

// AdvisoryReport keeps advisory findings separate from integrity drift. Its
// locators refer to the same portable inventory and fixed intelligence generation.
type AdvisoryReport struct {
	State     string             `json:"state"`
	Decisions []AdvisoryDecision `json:"decisions"`
	Summary   AdvisorySummary    `json:"summary"`
	Findings  int                `json:"findings"`
}

func BuildReportWithAdvisories(plan Plan, records []Record, summary Summary, resources Resources, interrupted, abnormal bool, inventory *projectinventory.PublicInventory, intelligence *Intelligence, advisories *AdvisoryReport) Report {
	r := BuildReportWithIntelligence(plan, records, summary, resources, interrupted, abnormal, inventory, intelligence)
	if plan.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) == 0 {
		return r
	}
	r.SchemaVersion = "1.3"
	a := AdvisoryReport{State: "unavailable", Decisions: []AdvisoryDecision{}, Summary: AdvisorySummary{Gaps: []string{}}}
	if advisories != nil && inventory != nil && intelligence != nil && validateAdvisoryReport(plan, *inventory, *intelligence, *advisories) {
		a = *advisories
		a.Decisions = append([]AdvisoryDecision{}, advisories.Decisions...)
		for i := range a.Decisions {
			a.Decisions[i].Gaps = append([]string{}, advisories.Decisions[i].Gaps...)
			a.Decisions[i].Support = append([]AdvisorySupport{}, advisories.Decisions[i].Support...)
		}
		a.Summary.Gaps = append([]string{}, advisories.Summary.Gaps...)
	}
	r.Advisories = &a
	r.advisoryPlan = &plan
	for i := range r.Coverage {
		c := &r.Coverage[i]
		if (c.Check == "malicious" && plan.Checks&cli.ArgumentCheckMalicious != 0) || (c.Check == "vulnerability" && plan.Checks&cli.ArgumentCheckVulnerability != 0) {
			c.Outcome = "incomplete"
			c.Reason = "matching-unavailable"
			if a.State == "observed" {
				c.Reason = "bounded-npm-locked-evidence; explicit-origin-rule; openssf-malicious-v1-only; other-categories-and-installed-applicability-unqualified"
			}
			if abnormal || resources.QueryFailed || resources.Stale || resources.Stopped {
				c.Reason += "; execution-incomplete"
			}
		}
		if c.Check == "intelligence-access" && a.State == "observed" {
			c.Reason = "fixed-generation-metadata-catalog-and-selected-originals; bounded-matching; storage-usage-not-observed"
		}
	}
	return r
}

func validateAdvisoryReport(plan Plan, inventory projectinventory.PublicInventory, intelligence Intelligence, a AdvisoryReport) bool {
	if a.State != "observed" || a.Decisions == nil || a.Summary.Gaps == nil || ValidateAdvisorySummary(a.Summary, a.Decisions, inventory) != nil {
		return false
	}
	findings := 0
	seen := map[[3]int]bool{}
	for i, d := range a.Decisions {
		if d.Sequence != i || ValidateAdvisoryDecision(plan, inventory, intelligence, d) != nil {
			return false
		}
		key := [3]int{int(d.Observation), d.Advisory, d.Affected}
		if seen[key] {
			return false
		}
		seen[key] = true
		if d.EnforcementEligible {
			findings++
		}
	}
	return findings == a.Findings
}

// Rendering validates the context-free public shape too. Authority validation
// above additionally uses the parent-selected policy and admitted inventory.
func validRenderedAdvisories(r Report) bool {
	if r.Advisories == nil {
		return r.SchemaVersion != "1.3"
	}
	if r.SchemaVersion != "1.3" {
		return false
	}
	a := r.Advisories
	if a.State == "unavailable" {
		return a.Decisions != nil && len(a.Decisions) == 0 && a.Findings == 0 && a.Summary.Decisions == 0 && a.Summary.Observations == 0 && a.Summary.TotalObservations == 0 && a.Summary.BytesRead == 0 && a.Summary.Gaps != nil && len(a.Summary.Gaps) == 0
	}
	return r.advisoryPlan != nil && r.Inventory != nil && r.Intelligence != nil && validateAdvisoryReport(*r.advisoryPlan, *r.Inventory, *r.Intelligence, *a)
}

func renderAdvisories(out *strings.Builder, a *AdvisoryReport) {
	if a == nil {
		return
	}
	fmt.Fprintf(out, "Advisories: %s; locked observations=%d/%d; decisions=%d; eligible matches=%d; identity bytes read=%d\n", a.State, a.Summary.Observations, a.Summary.TotalObservations, len(a.Decisions), a.Findings, a.Summary.BytesRead)
	for _, d := range a.Decisions {
		fmt.Fprintf(out, "Advisory observation=%d advisory=%d affected=%d: %s; version=%s; fully-evaluated=%t; category=%s; profile=%s; rule=%d; activity=%s; origin=%s; source=%s; enforcement-eligible=%t\n", d.Observation, d.Advisory, d.Affected, d.Outcome, d.VersionOutcome, d.FullyEvaluated, d.Category, d.Profile, d.Rule, d.Activity, d.Origin, d.Source, d.EnforcementEligible)
		for _, support := range d.Support {
			fmt.Fprintf(out, "  Support version=%d range=%d\n", support.Version, support.Range)
		}
		for _, gap := range d.Gaps {
			fmt.Fprintf(out, "  Advisory gap: %s\n", gap)
		}
	}
	for _, gap := range a.Summary.Gaps {
		fmt.Fprintf(out, "Matching gap: %s\n", gap)
	}
}
