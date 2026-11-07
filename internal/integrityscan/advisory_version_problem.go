package integrityscan

import "packtrace/internal/intel"

// AdvisoryVersionProblem retains only the first fixed evaluator code and numeric
// positions. It is not an exhaustive explanation or a coverage assertion.
type AdvisoryVersionProblem struct {
	Scope   string `json:"scope"`
	Kind    string `json:"kind"`
	Version int    `json:"version"`
	Range   int    `json:"range"`
	Event   int    `json:"event"`
}

func cloneAdvisoryVersionProblem(p *AdvisoryVersionProblem) *AdvisoryVersionProblem {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}

func advisoryVersionProblemShape(p *AdvisoryVersionProblem) bool {
	if p == nil {
		return true
	}
	if p.Version < -1 || p.Version >= 20000 || p.Range < -1 || p.Range >= 20000 || p.Event < -1 || p.Event >= 20000 {
		return false
	}
	unset := p.Version == -1 && p.Range == -1 && p.Event == -1
	if p.Scope == "global" {
		return unset && oneOf(p.Kind, "header-unsupported", "query-unqualified", "affected-uninspectable")
	}
	if p.Scope != "affected" {
		return false
	}
	switch p.Kind {
	case "affected-uninspectable", "ecosystem-outside-profile", "versions-uninspectable", "no-usable-condition":
		return unset
	case "version-outside-profile", "version-limit":
		return p.Version >= 0 && p.Range == -1 && p.Event == -1
	case "range-structure":
		// The evaluator also uses -1 for an uninspectable ranges list.
		return p.Version == -1 && p.Event == -1
	case "range-outside-profile":
		return p.Version == -1 && p.Range >= 0 && p.Event == -1
	case "bound-outside-profile", "bound-limit", "precedence-tie":
		return p.Version == -1 && p.Range >= 0 && p.Event >= 0
	}
	return false
}

// Parent validation checks only public structure, never reexecutes semantics.
func validAdvisoryVersionProblem(d AdvisoryDecision) bool {
	return advisoryVersionProblemShape(d.FirstVersionProblem) && (d.FirstVersionProblem == nil ||
		d.Advisory > 0 && d.Affected >= 0 && !d.FullyEvaluated && hasMatchingGap(d.Gaps, "version-unsupported"))
}

func firstAdvisoryVersionProblem(result intel.OSVVersionConditions, idx int) *AdvisoryVersionProblem {
	if idx < 0 || idx >= len(result.Entries) || result.Entries[idx].Index != idx || result.Entries[idx].FullyEvaluated {
		return nil
	}
	scope, problems := "global", result.Problems
	if len(problems) == 0 {
		scope, problems = "affected", result.Entries[idx].Problems
	}
	if len(problems) == 0 {
		return nil
	}
	first := problems[0]
	p := &AdvisoryVersionProblem{Scope: scope, Kind: string(first.Kind), Version: first.VersionIndex, Range: first.RangeIndex, Event: first.EventIndex}
	if !advisoryVersionProblemShape(p) {
		return nil
	}
	return p
}
