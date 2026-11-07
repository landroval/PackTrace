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
	Local     *LocalDetails      `json:"local,omitempty"`
}

func BuildReportWithAdvisories(plan Plan, records []Record, summary Summary, resources Resources, interrupted, abnormal bool, inventory *projectinventory.PublicInventory, intelligence *Intelligence, advisories *AdvisoryReport) Report {
	r := BuildReportWithIntelligence(plan, records, summary, resources, interrupted, abnormal, inventory, intelligence)
	r.Privacy = PlanPrivacy(plan)
	r.advisoryPlan = &plan
	if plan.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) == 0 {
		return r
	}
	r.SchemaVersion = "1.4"
	a := AdvisoryReport{State: "unavailable", Decisions: []AdvisoryDecision{}, Summary: AdvisorySummary{Gaps: []string{}}}
	if advisories != nil && inventory != nil && intelligence != nil && validateAdvisoryReport(plan, *inventory, *intelligence, *advisories) {
		a = *advisories
		a.Decisions = append([]AdvisoryDecision{}, advisories.Decisions...)
		for i := range a.Decisions {
			a.Decisions[i].Gaps = append([]string{}, advisories.Decisions[i].Gaps...)
			a.Decisions[i].Support = append([]AdvisorySupport{}, advisories.Decisions[i].Support...)
		}
		a.Summary.Gaps = append([]string{}, advisories.Summary.Gaps...)
		if advisories.Local != nil {
			local := *advisories.Local
			local.Observations = append([]LocalObservation{}, local.Observations...)
			local.Advisories = append([]LocalAdvisory{}, local.Advisories...)
			a.Local = &local
		}
	}
	r.Advisories = &a
	for i := range r.Coverage {
		c := &r.Coverage[i]
		if (c.Check == "malicious" && plan.Checks&cli.ArgumentCheckMalicious != 0) || (c.Check == "vulnerability" && plan.Checks&cli.ArgumentCheckVulnerability != 0) {
			c.Outcome = "incomplete"
			c.Reason = "matching-unavailable"
			if a.State == "observed" {
				c.Reason = "bounded-npm-locked-and-observed-installed-evidence; explicit-origin-rules; documented-source-type-profiles; unsupported-or-incomplete-scope-visible"
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
	if PlanPrivacy(plan) == "portable" && a.Local != nil || PlanPrivacy(plan) == "local" && (a.Local == nil || ValidateLocalDetails(*a.Local, a.Decisions, inventory) != nil) {
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
		return r.SchemaVersion != "1.3" && r.SchemaVersion != "1.4"
	}
	if r.SchemaVersion != "1.3" && r.SchemaVersion != "1.4" {
		return false
	}
	a := r.Advisories
	if a.State == "unavailable" {
		return a.Local == nil && a.Decisions != nil && len(a.Decisions) == 0 && a.Findings == 0 && a.Summary.Decisions == 0 && a.Summary.Observations == 0 && a.Summary.TotalObservations == 0 && a.Summary.InstalledObservations == 0 && a.Summary.TotalInstalledObservations == 0 && a.Summary.Work == 0 && a.Summary.BytesRead == 0 && a.Summary.Gaps != nil && len(a.Summary.Gaps) == 0
	}
	return r.advisoryPlan != nil && r.Inventory != nil && r.Intelligence != nil && validateAdvisoryReport(*r.advisoryPlan, *r.Inventory, *r.Intelligence, *a)
}

func renderAdvisories(out *strings.Builder, a *AdvisoryReport, inventory *projectinventory.PublicInventory) {
	if a == nil {
		return
	}
	fmt.Fprintf(out, "Advisories: %s; locked observations=%d/%d; installed observations=%d/%d; decisions=%d; work=%d; eligible matches=%d; identity bytes read=%d\n", a.State, a.Summary.Observations, a.Summary.TotalObservations, a.Summary.InstalledObservations, a.Summary.TotalInstalledObservations, len(a.Decisions), a.Summary.Work, a.Findings, a.Summary.BytesRead)
	fmt.Fprintln(out, "Counts are observation-level matches, not distinct incidents; installed correspondence does not authenticate contents")
	observations, advisories := localDetailMaps(a.Local)
	for _, d := range a.Decisions {
		fmt.Fprintf(out, "Advisory observation=%d advisory=%d affected=%d: %s; version=%s; fully-evaluated=%t; category=%s; profile=%s; rule=%d; activity=%s; origin=%s; source=%s; enforcement-eligible=%t\n", d.Observation, d.Advisory, d.Affected, d.Outcome, d.VersionOutcome, d.FullyEvaluated, d.Category, d.Profile, d.Rule, d.Activity, d.Origin, d.Source, d.EnforcementEligible)
		if a.Local != nil {
			class := "unknown"
			if inventory != nil && d.Observation > 0 && int(d.Observation) <= len(inventory.Observations) {
				class = inventory.Observations[d.Observation-1].Class
			}
			if observation, ok := observations[d.Observation]; ok {
				fmt.Fprintf(out, "  Local %s evidence: name=%q version=%q relative-path=%q; supporting-lock=%d\n", class, observation.Name, observation.Version, observation.Location, d.LockedObservation)
			}
			if advisory, ok := advisories[d.Advisory]; ok {
				fmt.Fprintf(out, "  Local advisory: id=%q original-sha256=%s\n", advisory.ID, advisory.SHA256)
			}
		}
		for _, support := range d.Support {
			fmt.Fprintf(out, "  Support version=%d range=%d\n", support.Version, support.Range)
		}
		for _, gap := range d.Gaps {
			fmt.Fprintf(out, "  Advisory gap: %s\n", gap)
		}
	}
	if a.Local != nil && a.Local.Limited {
		fmt.Fprintln(out, "Local presentation: limited; unresolved evidence remains opaque")
	}
	for _, gap := range a.Summary.Gaps {
		fmt.Fprintf(out, "Matching gap: %s\n", gap)
	}
}
