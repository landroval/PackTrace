package integrityscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"packtrace/internal/cli"
	"packtrace/internal/integrity"
)

// RenderIntegrityCheck derives the narrower command's decision from frozen
// parent evidence, never from public report JSON or its aggregate scan exit.
// Native release qualification is not an obligation of this Linux-only check;
// actual execution/resource/output/finalization guards still belong to its caller.
func RenderIntegrityCheck(r Report) ([]byte, cli.ScanExitConditions, error) {
	bad := cli.ScanExitConditions{ReportPreventingError: true}
	if !validRenderedPolicy(r) || r.policyContext == nil {
		return nil, bad, errors.New("verify-integrity: evidence-invalid")
	}
	var in policyReportInputs
	if json.Unmarshal(r.policyContext.inputs, &in) != nil {
		return nil, bad, errors.New("verify-integrity: evidence-invalid")
	}
	p := in.Plan
	if p.Builtin || !strings.HasPrefix(p.Manager, "npm@") || p.Checks != cli.ArgumentCheckIntegrity || p.TrustedPolicyDigest == "" || p.Policy.MinimumAssurance != "independently-anchored" {
		return nil, bad, errors.New("verify-integrity: pinned-independent-npm-policy-required")
	}
	in.Inventory.OriginalClaims = in.OriginalClaims
	healthy := !r.policyContext.conditions.Interrupted && !r.Resources.QueryFailed && !r.Resources.Stale && !r.Resources.Stopped
	for _, c := range r.Coverage {
		if c.Check == "execution" && c.Outcome != "completed" {
			healthy = false
		}
	}
	references := OperatorReferenceAuthorityComplete(p, in.Records) && referenceComparisonsComplete(p, in.Records)
	// Vacuous reference authority is valid only with a positively closed empty
	// installed inventory, proven by the same whole-scope predicate below.
	if len(p.Policy.References) == 0 && len(in.Records) == 0 {
		references = supportedPolicyPin(p.TrustedPolicyDigest)
	}
	complete := healthy && references && wholeIntegrityComplete(p, in.Records, &in.Inventory)
	drift := 0
	// Count only positively observed differences from admitted bound comparisons.
	// Missing reference/evidence cannot create a finding or suppress incompleteness.
	for _, rec := range in.Records {
		for _, d := range rec.Assessment.Differences {
			if d.Kind != integrity.DifferenceUnchanged {
				drift++
			}
		}
	}
	conditions := cli.ScanExitConditions{Interrupted: r.policyContext.conditions.Interrupted, RequiredCoverageIncomplete: !complete, EnforcedUnacceptedFindings: drift > 0}
	state := "incomplete"
	if complete {
		state = "complete"
	}
	data := []byte(fmt.Sprintf("npm integrity comparison: %s; drift findings: %d\nTrusted pinned references and whole installed scope only; not advisory scanning or a safety verdict.\nComparison snapshot; output and final lifecycle checks pending.\n", state, drift))
	return data, conditions, nil
}
