package integrityscan

import (
	"encoding/json"
	"fmt"
	"strings"

	"packtrace/internal/cli"
	"packtrace/internal/projectinventory"
)

// AdvisoryReport keeps advisory findings separate from integrity drift. Its
// locators refer to the same portable inventory and fixed intelligence generation.
type AdvisoryReport struct {
	State      string             `json:"state"`
	Decisions  []AdvisoryDecision `json:"decisions"`
	Summary    AdvisorySummary    `json:"summary"`
	Findings   int                `json:"findings"`
	Candidates int                `json:"candidates"`
	Local      *LocalDetails      `json:"local,omitempty"`

	candidatesPresent     bool // Retain schema provenance even when the count is zero.
	candidateFlagsPresent bool // Explicit false is still a new-schema field.
	legacyCandidates      bool // Rendering historical reports omits the new field.
}

func (a AdvisoryReport) MarshalJSON() ([]byte, error) {
	type plain AdvisoryReport
	var candidates *int
	if !a.legacyCandidates {
		candidates = &a.Candidates
	}
	return json.Marshal(struct {
		plain
		Candidates *int `json:"candidates,omitempty"`
	}{plain(a), candidates})
}

func (a *AdvisoryReport) UnmarshalJSON(data []byte) error {
	type plain AdvisoryReport
	var decoded struct {
		plain
		Candidates json.RawMessage `json:"candidates"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*a = AdvisoryReport(decoded.plain)
	if decoded.Candidates != nil {
		if string(decoded.Candidates) == "null" {
			return fmt.Errorf("scan: report-failed")
		}
		if err := json.Unmarshal(decoded.Candidates, &a.Candidates); err != nil {
			return err
		}
		a.candidatesPresent = true
	} else {
		var fields struct {
			Decisions []struct {
				Candidate json.RawMessage `json:"candidate"`
			} `json:"decisions"`
		}
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		for _, d := range fields.Decisions {
			a.candidateFlagsPresent = a.candidateFlagsPresent || d.Candidate != nil
		}
	}
	return nil
}

func BuildReportWithAdvisories(plan Plan, records []Record, summary Summary, resources Resources, interrupted, abnormal bool, inventory *projectinventory.PublicInventory, intelligence *Intelligence, advisories *AdvisoryReport) Report {
	r := BuildReportWithIntelligence(plan, records, summary, resources, interrupted, abnormal, inventory, intelligence)
	r.Privacy = PlanPrivacy(plan)
	r.advisoryPlan = &plan
	if plan.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) == 0 {
		return r
	}
	r.SchemaVersion = "1.6"
	a := AdvisoryReport{State: "unavailable", Decisions: []AdvisoryDecision{}, Summary: AdvisorySummary{Gaps: []string{}}}
	if advisories != nil && inventory != nil && intelligence != nil && validateAdvisoryReport(plan, *inventory, *intelligence, *advisories) {
		a = *advisories
		a.Decisions = append([]AdvisoryDecision{}, advisories.Decisions...)
		for i := range a.Decisions {
			a.Decisions[i].FirstVersionProblem = cloneAdvisoryVersionProblem(advisories.Decisions[i].FirstVersionProblem)
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
	a.candidatesPresent = true
	a.legacyCandidates = false
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
	findings, candidates := 0, 0
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
		if d.Candidate {
			candidates++
		}
	}
	return findings == a.Findings && candidates == a.Candidates
}

// Rendering validates the context-free public shape too. Authority validation
// above additionally uses the parent-selected policy and admitted inventory.
func validRenderedAdvisories(r Report) bool {
	if r.Advisories == nil {
		return !oneOf(r.SchemaVersion, "1.3", "1.4", "1.5", "1.6")
	}
	if !oneOf(r.SchemaVersion, "1.3", "1.4", "1.5", "1.6") {
		return false
	}
	a := r.Advisories
	if r.SchemaVersion != "1.6" {
		if a.candidatesPresent || a.candidateFlagsPresent || a.Candidates != 0 || r.advisoryPlan != nil && r.advisoryPlan.Policy.AdvisoryCandidates {
			return false
		}
		for _, d := range a.Decisions {
			if d.Candidate {
				return false
			}
		}
	} else if !a.candidatesPresent || a.legacyCandidates {
		return false
	}
	if !oneOf(r.SchemaVersion, "1.5", "1.6") {
		for _, d := range a.Decisions {
			if d.FirstVersionProblem != nil {
				return false
			}
		}
	}
	if a.State == "unavailable" {
		return a.Local == nil && a.Decisions != nil && len(a.Decisions) == 0 && a.Findings == 0 && a.Candidates == 0 && a.Summary.Decisions == 0 && a.Summary.Observations == 0 && a.Summary.TotalObservations == 0 && a.Summary.InstalledObservations == 0 && a.Summary.TotalInstalledObservations == 0 && a.Summary.Work == 0 && a.Summary.BytesRead == 0 && a.Summary.Gaps != nil && len(a.Summary.Gaps) == 0
	}
	return r.advisoryPlan != nil && r.Inventory != nil && r.Intelligence != nil && validateAdvisoryReport(*r.advisoryPlan, *r.Inventory, *r.Intelligence, *a)
}

func renderAdvisories(out *strings.Builder, a *AdvisoryReport, inventory *projectinventory.PublicInventory) {
	if a == nil {
		return
	}
	fmt.Fprintf(out, "Advisories: %s; locked observations=%d/%d; installed observations=%d/%d; decisions=%d; work=%d; eligible matches=%d; candidates=%d; identity bytes read=%d\n", a.State, a.Summary.Observations, a.Summary.TotalObservations, a.Summary.InstalledObservations, a.Summary.TotalInstalledObservations, len(a.Decisions), a.Summary.Work, a.Findings, a.Candidates, a.Summary.BytesRead)
	fmt.Fprintln(out, "Counts are observation-level rows, not distinct incidents; candidates do not confirm origin; installed correspondence does not authenticate contents")
	observations, advisories := localDetailMaps(a.Local)
	for _, d := range a.Decisions {
		fmt.Fprintf(out, "Advisory observation=%d advisory=%d affected=%d: %s; version=%s; fully-evaluated=%t; category=%s; profile=%s; rule=%d; activity=%s; origin=%s; source=%s; enforcement-eligible=%t\n", d.Observation, d.Advisory, d.Affected, d.Outcome, d.VersionOutcome, d.FullyEvaluated, d.Category, d.Profile, d.Rule, d.Activity, d.Origin, d.Source, d.EnforcementEligible)
		if d.Candidate {
			fmt.Fprintln(out, "  Candidate only: local version match; origin unconfirmed; not enforcement-eligible")
		}
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
		if p := d.FirstVersionProblem; p != nil {
			fmt.Fprintf(out, "  First version problem: kind=%q scope=%q version=%d range=%d event=%d\n", p.Kind, p.Scope, p.Version, p.Range, p.Event)
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
