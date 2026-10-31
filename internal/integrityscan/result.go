package integrityscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"packtrace/internal/cli"
	"packtrace/internal/integrity"
)

// ValidateRecord checks native/engine receipts against parent-owned scope. No
// worker field grants policy authority, privacy, public exit or qualification.
func ValidateRecord(plan Plan, r Record, policyHash string) error {
	bad := errors.New("scan: worker-protocol")
	if r.Index < 0 || r.Index >= len(plan.Policy.References) || r.ObservedEntries < 0 || r.ObservedEntries > 100000 {
		return bad
	}
	id := instanceID(r.Index)
	a := r.Assessment
	if a.InstanceID != id || (a.Assurance != integrity.AssuranceUnknown && a.Assurance != integrity.AssuranceLockfile) || len(a.Gaps) > 256 || len(a.Differences) > 200000 || len(a.Contexts) > 1 {
		return bad
	}
	binding, gaps := integrity.ResolveReferenceBinding(Binding(plan, r.Index, r.Lock, policyHash))
	bound := len(gaps) == 0 && claimMatches(plan.Policy.References[r.Index], r.Lock) && plan.Policy.MinimumAssurance == "lockfile-consistent"
	if (len(a.Differences) > 0 || a.Assurance != integrity.AssuranceUnknown) && !bound {
		return bad
	}
	if bound && len(a.Differences) > 0 && a.Assurance != binding.Assurance() {
		return bad
	}
	validEntry := func(s string) bool {
		if s == "" {
			return true
		}
		n, e := strconv.Atoi(s)
		return e == nil && n >= 1 && n <= 100000 && strconv.Itoa(n) == s
	}
	validEvidence := func(s string) bool {
		if s == "" || s == id+":scope" || s == id+":nested" || s == id+":unmapped" {
			return true
		}
		prefix := id + ":observed:"
		if !strings.HasPrefix(s, prefix) {
			return false
		}
		n, e := strconv.Atoi(strings.TrimPrefix(s, prefix))
		return e == nil && n >= 1 && n <= r.ObservedEntries && s == prefix+strconv.Itoa(n)
	}
	seen := map[string]bool{}
	for _, d := range a.Differences {
		if d.InstanceID != id || d.Kind < integrity.DifferenceUnchanged || d.Kind > integrity.DifferenceTypeChanged || !validEntry(d.EntryID) || !validEvidence(d.EvidenceID) || d.EvidenceID == "" {
			return bad
		}
		if (d.Kind == integrity.DifferenceAdded) != (d.EntryID == "") {
			return bad
		}
		if d.Kind != integrity.DifferenceMissing && !strings.HasPrefix(d.EvidenceID, id+":observed:") {
			return bad
		}
		key := d.EntryID
		if key == "" {
			key = d.EvidenceID
		}
		if seen[key] {
			return bad
		}
		seen[key] = true
	}
	for _, g := range a.Gaps {
		if g.InstanceID != id || !validEntry(g.EntryID) || !validEvidence(g.EvidenceID) || !oneOf(string(g.Code), string(integrity.GapBinding), string(integrity.GapReference), string(integrity.GapObservation), string(integrity.GapOwnership), string(integrity.GapUnsupported), string(integrity.GapTruncated)) {
			return bad
		}
	}
	for _, c := range a.Contexts {
		want := integrity.ContextUnknown
		switch plan.Policy.References[r.Index].Context {
		case "patch":
			want = integrity.ContextPatch
		case "generated":
			want = integrity.ContextGenerated
		}
		if c.InstanceID != id || c.EvidenceID != id+":scope" || c.Kind != want || want == integrity.ContextUnknown {
			return bad
		}
	}
	if a.SuppliedComparisonComplete != (len(a.Gaps) == 0 && bound && a.Assurance == integrity.AssuranceLockfile) {
		return bad
	}
	return nil
}

type Resources struct {
	WorkerSamples       int    `json:"workerSamples"`
	SupervisorSamples   int    `json:"supervisorSamples"`
	WorkerPeakBytes     uint64 `json:"workerPeakResidentBytes"`
	SupervisorPeakBytes uint64 `json:"supervisorPeakResidentBytes"`
	PeakSampledSumBytes uint64 `json:"peakSampledResidentSumBytes"`
	QueryFailed         bool   `json:"queryFailed"`
	Stale               bool   `json:"stale"`
	Stopped             bool   `json:"thresholdStopped"`
}
type Coverage struct {
	Check    string `json:"check"`
	Required bool   `json:"required"`
	Outcome  string `json:"outcome"`
	Reason   string `json:"reason"`
}
type Report struct {
	SchemaVersion       string                            `json:"schemaVersion"`
	Execution           string                            `json:"execution"`
	NativeQualification string                            `json:"nativeQualification"`
	Privacy             string                            `json:"privacy"`
	PolicyOrigin        string                            `json:"policyOrigin"`
	MinimumAssurance    string                            `json:"minimumAssurance"`
	Instances           int                               `json:"instances"`
	ObservedEntries     int                               `json:"observedEntries"`
	Findings            int                               `json:"findings"`
	ExitCode            int                               `json:"exitCode"`
	Coverage            []Coverage                        `json:"coverage"`
	Resources           Resources                         `json:"resources"`
	Comparison          integrity.PortableIntegrityResult `json:"comparison"`
}

func BuildReport(plan Plan, records []Record, summary Summary, resources Resources, interrupted, abnormal bool) Report {
	assessment := integrity.Assessment{}
	findings := 0
	for _, record := range records {
		a := record.Assessment
		assessment.Instances = append(assessment.Instances, a)
		for _, d := range a.Differences {
			if d.Kind != integrity.DifferenceUnchanged {
				findings++
			}
		}
	}
	r := Report{SchemaVersion: "1.0", Execution: "gated-candidate", NativeQualification: "not-run", Privacy: "portable", PolicyOrigin: "explicit-user-designation; physical-separation-unqualified", MinimumAssurance: plan.Policy.MinimumAssurance, Instances: len(records), ObservedEntries: summary.ObservedEntries, Findings: findings, Resources: resources, Comparison: integrity.BuildPortableIntegrity(assessment)}
	coverage := func(check string, required, complete bool, reason string) {
		outcome := "incomplete"
		if !required {
			outcome = "not-run"
		} else if complete {
			outcome = "completed"
		}
		r.Coverage = append(r.Coverage, Coverage{check, required, outcome, reason})
	}
	coverage("inventory", true, false, "native-live-observations; producer-and-ownership-qualification-pending")
	integrityRequired := plan.Checks&cli.ArgumentCheckIntegrity != 0
	// Native/authority gates remain independent of the engine's supplied scope.
	coverage("integrity", integrityRequired, false, "native-and-authority-qualification-pending")
	coverage("malicious", plan.Checks&cli.ArgumentCheckMalicious != 0, false, "local-advisory-matching-not-implemented")
	coverage("vulnerability", plan.Checks&cli.ArgumentCheckVulnerability != 0, false, "local-advisory-matching-not-implemented")
	coverage("reference-authority", integrityRequired, false, "physical-policy-reference-separation-unqualified")
	coverage("native-qualification", true, false, "five-target-campaign-not-run")
	coverage("resident-observation", true, false, "100ms-scan-phase-own-resident-samples; writer-unsampled; sampled-sum-not-hard-ceiling")
	executionReason := "validated-closures-eof-and-reap"
	if abnormal {
		executionReason = "worker-incomplete"
	}
	coverage("execution", true, !abnormal, executionReason)
	r.ExitCode = cli.SelectScanExit(cli.ScanExitConditions{Interrupted: interrupted, RequiredCoverageIncomplete: true, EnforcedUnacceptedFindings: findings > 0 && plan.FailOn&cli.ArgumentCheckIntegrity != 0})
	return r
}
func Render(r Report, format string) ([]byte, error) {
	switch format {
	case "json":
		data, e := json.MarshalIndent(r, "", "  ")
		return append(data, '\n'), e
	case "terminal":
		var out strings.Builder
		fmt.Fprintln(&out, "PackTrace offline integrity — GATED CANDIDATE; not a qualified release")
		fmt.Fprintf(&out, "Observed entries: %d; instances: %d; drift findings: %d\n", r.ObservedEntries, r.Instances, r.Findings)
		for _, c := range r.Coverage {
			fmt.Fprintf(&out, "%s: %s (%s)\n", c.Check, c.Outcome, c.Reason)
		}
		// Reuse the engine's privacy-safe view without promoting its supplied-evidence
		// completion into acquired/native scan coverage.
		detail, e := integrity.RenderIntegrity(r.Comparison, "terminal")
		if e != nil {
			return nil, e
		}
		out.Write(detail)
		fmt.Fprintf(&out, "Required coverage: incomplete\nExit: %d\n", r.ExitCode)
		return []byte(out.String()), nil
	case "sarif":
		type message struct {
			Text string `json:"text"`
		}
		type result struct {
			RuleID     string                       `json:"ruleId"`
			Level      string                       `json:"level"`
			Message    message                      `json:"message"`
			Properties integrity.PortableDifference `json:"properties"`
		}
		results := []result{}
		for _, d := range r.Comparison.Differences {
			if d.Kind != integrity.DifferenceUnchanged {
				label := differenceName(d.Kind)
				results = append(results, result{"PT-INTEGRITY-" + strings.ToUpper(label), "warning", message{"Observed integrity drift: " + label + "; not evidence of malicious execution"}, d})
			}
		}
		notifications := []any{}
		for _, c := range r.Coverage {
			if c.Required && c.Outcome != "completed" {
				notifications = append(notifications, struct {
					Level   string  `json:"level"`
					Message message `json:"message"`
				}{"warning", message{c.Check + ": " + c.Reason}})
			}
		}
		data, e := json.Marshal(struct {
			Version string `json:"version"`
			Schema  string `json:"$schema"`
			Runs    []any  `json:"runs"`
		}{"2.1.0", "https://json.schemastore.org/sarif-2.1.0.json", []any{struct {
			Tool        any      `json:"tool"`
			Results     []result `json:"results"`
			Invocations []any    `json:"invocations"`
			Properties  Report   `json:"properties"`
		}{struct {
			Driver any `json:"driver"`
		}{struct {
			Name string `json:"name"`
		}{"PackTrace offline integrity candidate"}}, results, []any{struct {
			ExecutionSuccessful        bool  `json:"executionSuccessful"`
			ToolExecutionNotifications []any `json:"toolExecutionNotifications"`
		}{false, notifications}}, r}}})
		return append(data, '\n'), e
	}
	return nil, errors.New("scan: report-failed")
}
func differenceName(k integrity.DifferenceKind) string {
	switch k {
	case integrity.DifferenceModified:
		return "modified"
	case integrity.DifferenceMissing:
		return "missing"
	case integrity.DifferenceAdded:
		return "added"
	case integrity.DifferenceTypeChanged:
		return "type-changed"
	}
	return "unknown"
}
