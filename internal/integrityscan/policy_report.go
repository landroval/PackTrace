package integrityscan

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/projectinventory"
)

// policyReportContext is never serialized. Frozen inputs prevent callers from
// changing the policy through aliased slices after the parent evaluation.
// The seal additionally binds coverage, privacy, findings and comparison exit.
type policyReportContext struct {
	inputs            []byte
	snapshot          [32]byte
	conditions        cli.ScanExitConditions
	integrityFindings map[int]int
	advisoryFindings  map[int]int
}
type policyReportInputs struct {
	Plan      Plan
	Records   []Record
	Inventory projectinventory.PublicInventory
	Decisions []AdvisoryDecision
	Materials []PolicyMaterial
	Limited   bool
	Now       time.Time
}

// BuildReportWithPolicy is the operational 1.7 comparison snapshot. It does not
// predict successful output, final binding checks or writer teardown/reap.
// Invalid policy material leaves an unrenderable report, never a legacy fallback.
func BuildReportWithPolicy(plan Plan, records []Record, summary Summary, resources Resources, interrupted, abnormal bool, inventory *projectinventory.PublicInventory, intelligence *Intelligence, advisories *AdvisoryReport, materials []PolicyMaterial, limited bool, now time.Time) Report {
	r := BuildReportWithAdvisories(plan, records, summary, resources, interrupted, abnormal, inventory, intelligence, advisories)
	r.SchemaVersion = "1.7"
	for i := range r.Coverage {
		c := &r.Coverage[i]
		switch c.Check {
		case "resident-observation":
			c.Reason = "pre-output-comparison-snapshot; 100ms-retained-child-and-supervisor-observation; rendering-writer-teardown-reap-pending-in-caller; sampled-sum-not-hard-ceiling"
		case "execution":
			c.Reason = "comparison-only: " + c.Reason + "; output-and-final-lifecycle-pending-in-caller"
		}
	}
	if plan.Builtin {
		r.PolicyOrigin = "built-in; no-external-policy-or-grants"
	}
	if plan.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) != 0 {
		outcome := "incomplete"
		if r.Intelligence != nil && r.Intelligence.State == "available" && r.Intelligence.CheckAge == "current" && r.Intelligence.ReconciliationAge == "current" && r.Intelligence.Provenance != "unqualified" {
			outcome = "completed"
		}
		r.Coverage = append(r.Coverage, Coverage{Check: "intelligence-freshness", Required: true, Outcome: outcome, Reason: "source-check-and-full-reconciliation-freshness; independent-of-exception-acceptance"})
	}
	inputs := policyReportInputs{Plan: plan, Records: records, Materials: materials, Limited: limited, Now: now}
	if r.Inventory != nil {
		inputs.Inventory = *r.Inventory
	}
	if r.Advisories != nil {
		inputs.Decisions = r.Advisories.Decisions
	}
	frozen, err := json.Marshal(inputs)
	if err != nil {
		return r
	}
	evaluation, err := EvaluatePolicy(plan, records, inputs.Inventory, inputs.Decisions, materials, limited, now)
	if err != nil {
		return r
	}
	r.Policy = &evaluation
	conditions := cli.ScanExitConditions{Interrupted: interrupted, RequiredCoverageIncomplete: RequiredCoverageIncomplete(r), EnforcedUnacceptedFindings: evaluation.EnforcedUnaccepted > 0}
	r.ExitCode = cli.SelectScanExit(conditions)
	snapshot, err := json.Marshal(r)
	if err != nil {
		r.Policy = nil
		return r
	}
	context := &policyReportContext{inputs: frozen, snapshot: sha256.Sum256(snapshot), conditions: conditions, integrityFindings: map[int]int{}, advisoryFindings: map[int]int{}}
	starts := make([]int, len(records))
	offset := 0
	for ri, record := range records {
		starts[ri] = offset
		offset += len(record.Assessment.Differences)
	}
	for i, f := range evaluation.Findings {
		if f.Category == "integrity" {
			if f.Record >= 0 && f.Record < len(records) && f.Difference >= 0 && f.Difference < len(records[f.Record].Assessment.Differences) {
				context.integrityFindings[starts[f.Record]+f.Difference] = i
			}
		} else {
			context.advisoryFindings[f.Decision] = i
		}
	}
	r.policyContext = context
	return r
}

// RequiredCoverageIncomplete consumes the complete outer model. Only positive
// completion or positive not-applicability satisfies a required obligation.
func RequiredCoverageIncomplete(r Report) bool {
	if len(r.Coverage) == 0 {
		return true
	}
	for _, c := range r.Coverage {
		if c.Required && c.Outcome != "completed" && c.Outcome != "not-applicable" {
			return true
		}
	}
	return false
}

// ReportConditions describes the comparison snapshot, not future output success.
// The CLI overlays actual output/final-lifecycle errors and interruption later.
func ReportConditions(r Report) cli.ScanExitConditions {
	c := cli.ScanExitConditions{Interrupted: r.ExitCode == 130, ReportPreventingError: r.ExitCode == 2, RequiredCoverageIncomplete: RequiredCoverageIncomplete(r)}
	if r.SchemaVersion == "1.7" {
		if r.Policy == nil || r.policyContext == nil {
			c.ReportPreventingError = true
			return c
		}
		c.Interrupted = r.policyContext.conditions.Interrupted
		c.EnforcedUnacceptedFindings = r.Policy.EnforcedUnaccepted > 0
	} else {
		// Historical builders retain their existing aggregate decision contract.
		c.EnforcedUnacceptedFindings = r.ExitCode == 1
	}
	return c
}

// UnmarshalJSON records typed policy provenance, including explicit null. Public
// JSON cannot recreate the private parent authority needed to render schema 1.7.
func (r *Report) UnmarshalJSON(data []byte) error {
	type plain Report
	var decoded struct {
		plain
		Policy json.RawMessage `json:"policy"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = Report(decoded.plain)
	if decoded.Policy != nil {
		r.policyPresent = true
		if string(decoded.Policy) != "null" {
			if err := json.Unmarshal(decoded.Policy, &r.Policy); err != nil {
				return err
			}
		}
	}
	return nil
}

func validRenderedPolicy(r Report) bool {
	if r.SchemaVersion != "1.7" {
		return r.Policy == nil && r.policyContext == nil && !r.policyPresent
	}
	if r.Policy == nil || r.policyContext == nil {
		return false
	}
	snapshot, err := json.Marshal(r)
	if err != nil || sha256.Sum256(snapshot) != r.policyContext.snapshot {
		return false
	}
	var inputs policyReportInputs
	if json.Unmarshal(r.policyContext.inputs, &inputs) != nil {
		return false
	}
	return ValidatePolicyEvaluation(inputs.Plan, inputs.Records, inputs.Inventory, inputs.Decisions, inputs.Materials, inputs.Limited, inputs.Now, *r.Policy) == nil
}

func renderPolicy(out *strings.Builder, p *PolicyEvaluation) {
	if p == nil {
		return
	}
	fmt.Fprintf(out, "Effective policy: source=%s checks=%d fail-on=%d manager=%s privacy=%s minimum-assurance=%s max-exception-days=%d material-limited=%t\n", p.Source, p.Checks, p.FailOn, p.Manager, p.Privacy, p.MinimumAssurance, p.MaxExceptionDays, p.MaterialLimited)
	fmt.Fprintln(out, "Policy states are comparison-only; output and final lifecycle pending in caller")
	for _, e := range p.Exceptions {
		fmt.Fprintf(out, "Exception %d: %s; findings=%v\n", e.Ordinal, e.Disposition, e.Findings)
	}
	for _, f := range p.Findings {
		fmt.Fprintf(out, "Finding %d: category=%s record=%d difference=%d decision=%d accepted=%t enforced=%t exception=%d\n", f.Ordinal, f.Category, f.Record, f.Difference, f.Decision, f.Accepted, f.Enforced, f.Exception)
		if f.Tracking != "" {
			fmt.Fprintf(out, "  Local tracking=%s acceptance=%s package=%q version=%q instance=%q relative-path=%q\n", f.Tracking, f.Acceptance, f.Package, f.Version, f.Instance, f.Path)
			if f.Review != nil {
				data, _ := json.Marshal(f.Review)
				fmt.Fprintf(out, "  Local review evidence: %s\n", data)
			}
		}
	}
	fmt.Fprintf(out, "Enforced unaccepted findings: %d\n", p.EnforcedUnaccepted)
}

// SARIF annotations refer to the existing alert, including accepted alerts.
func policyAlertProperties(r Report, evidence any, index int, advisory bool) any {
	if r.Policy == nil || r.policyContext == nil {
		return evidence
	}
	findings := r.policyContext.integrityFindings
	if advisory {
		findings = r.policyContext.advisoryFindings
	}
	if i, ok := findings[index]; ok {
		return struct {
			Evidence any           `json:"evidence"`
			Policy   PolicyFinding `json:"policy"`
		}{evidence, r.Policy.Findings[i]}
	}
	return evidence
}
