package execution

import (
	"fmt"
	"reflect"

	"packtrace/internal/demo"
	"packtrace/internal/inspect"
)

func one(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func profileField(profile string) string {
	if profile == "explicit-only" {
		return ""
	}
	return profile
}
func batchResult(locked int, profile string) inspect.BatchResult {
	return inspect.BatchResult{Schema: "packtrace.inspect.batch.v1", Experimental: true, Scope: "supplied-metadata", Privacy: "portable", IdentityProfile: profileField(profile), LockedEntries: locked, Advisories: []inspect.BatchAdvisory{}, Findings: []string{}, ExitCode: 3, Coverage: []demo.Coverage{
		{Check: "advisory-records", Outcome: "completed", Reason: "supplied-records-only"},
		{Check: "advisory-applicability", Outcome: "incomplete", Reason: "origin-freshness-category-unqualified"},
		{Check: "installed-inventory", Outcome: "not-run", Reason: "no-target-access"},
		{Check: "integrity", Outcome: "not-run", Reason: "no-target-access"},
	}}
}
func validateReport(r *inspect.Result, index, locked int, profile string) error {
	if r == nil || r.Schema != "packtrace.inspect.v1" || !r.Experimental || r.Scope != "supplied-metadata" || r.Privacy != "portable" || r.ExitCode != 3 || r.IdentityProfile != profileField(profile) || r.AdvisoryReference != fmt.Sprintf("advisory-%d", index) || r.Findings == nil || len(r.Findings) != 0 || len(r.Inventory) != locked || r.Inventory == nil || r.Evaluations == nil || r.Candidates == nil || len(r.Candidates) != 0 || len(r.Evaluations) > 4096 {
		return errProtocol
	}
	for i, o := range r.Inventory {
		if o.Reference != fmt.Sprintf("package-%d", i) || o.Observation != "locked" || o.TupleKind != "" || o.ResolutionQualification != "" || !one(o.NameQualification, "absent", "null", "value", "empty", "invalid-type") || !one(o.VersionQualification, "absent", "null", "qualified", "invalid-semver", "invalid-type") || !one(o.LinkQualification, "absent", "null", "non-link", "link", "invalid-type") {
			return errProtocol
		}
		if profile == "explicit-only" {
			if o.IdentitySource != "" || o.IdentityQualification != "" {
				return errProtocol
			}
		} else {
			switch o.IdentitySource {
			case "record-name":
				if o.IdentityQualification != "explicit-claim" || o.NameQualification != "value" {
					return errProtocol
				}
			case "locator-profile":
				if o.IdentityQualification != "installation-claim" {
					return errProtocol
				}
			case "unavailable":
				if !one(o.IdentityQualification, "locator-outside-profile", "explicit-unusable", "link-unqualified", "uninspectable-declarations", "alias-declaration") {
					return errProtocol
				}
			default:
				return errProtocol
			}
		}
	}
	affected := 0
	if locked > 0 {
		if len(r.Evaluations)%locked != 0 {
			return errProtocol
		}
		affected = len(r.Evaluations) / locked
		if affected > 64 {
			return errProtocol
		}
	} else if len(r.Evaluations) != 0 {
		return errProtocol
	}
	for i, e := range r.Evaluations {
		if e.PackageIndex != i/affected || e.AffectedIndex != i%affected || !one(e.IdentityQualification, "candidate", "unqualified", "conflict", "unknown") || !one(e.VersionOutcome, "not-evaluated", "match", "no-match", "indeterminate") || !one(e.Withdrawal, "not-declared", "reported", "unknown") || e.Support == nil || e.Problems == nil || len(e.Support) > 20000 || len(e.Problems) > 40002 {
			return errProtocol
		}
		// Withdrawal belongs to the advisory, and identity qualification to its
		// affected slot, not to the package being compared against that slot.
		if e.Withdrawal != r.Evaluations[0].Withdrawal || e.IdentityQualification != r.Evaluations[e.AffectedIndex].IdentityQualification {
			return errProtocol
		}
		o := r.Inventory[e.PackageIndex]
		expected := "indeterminate"
		nameOK := o.NameQualification == "value" || o.IdentitySource == "locator-profile"
		if nameOK && e.IdentityQualification == "candidate" {
			if !one(e.IdentityComparison, "equal", "different", "installation-claim-equal", "installation-claim-different") {
				return errProtocol
			}
			expected = e.IdentityComparison
			if o.IdentitySource == "locator-profile" {
				if !one(expected, "installation-claim-equal", "installation-claim-different") {
					return errProtocol
				}
			} else if !one(expected, "equal", "different") {
				return errProtocol
			}
		}
		if e.IdentityComparison != expected {
			return errProtocol
		}
		if (e.VersionOutcome == "not-evaluated") != (o.VersionQualification != "qualified") || (e.VersionOutcome == "not-evaluated" && (e.VersionFullyEvaluated || len(e.Support) > 0 || len(e.Problems) > 0)) || (e.VersionFullyEvaluated && (e.VersionOutcome == "indeterminate" || len(e.Problems) > 0)) || ((e.VersionOutcome == "match") != (len(e.Support) > 0)) || (e.VersionOutcome == "no-match" && (!e.VersionFullyEvaluated || len(e.Problems) != 0)) || (e.VersionOutcome == "indeterminate" && len(e.Problems) == 0) {
			return errProtocol
		}
		for _, s := range e.Support {
			if s.VersionIndex < -1 || s.VersionIndex >= 20000 || s.RangeIndex < -1 || s.RangeIndex >= 20000 || (s.VersionIndex == -1) == (s.RangeIndex == -1) {
				return errProtocol
			}
		}
		for _, p := range e.Problems {
			if !one(p.Kind, "header-unsupported", "query-unqualified", "affected-uninspectable", "version-outside-profile", "version-limit", "versions-uninspectable", "range-structure", "no-usable-condition", "range-outside-profile", "bound-limit", "bound-outside-profile", "precedence-tie") || p.VersionIndex < -1 || p.VersionIndex >= 20000 || p.RangeIndex < -1 || p.RangeIndex >= 20000 || p.EventIndex < -1 || p.EventIndex >= 20000 {
				return errProtocol
			}
		}
	}
	if len(r.Coverage) != 6 && len(r.Coverage) != 7 {
		return errProtocol
	}
	expected := []demo.Coverage{{Check: "supplied-inventory", Outcome: "completed", Reason: "supplied-document-only"}, {Check: "version-conditions", Outcome: "completed", Reason: "qualified-supplied-conditions"}, {Check: "advisory-applicability", Outcome: "incomplete", Reason: "origin-freshness-category-unqualified"}, {Check: "installed-inventory", Outcome: "not-run", Reason: "no-target-access"}, {Check: "integrity", Outcome: "not-run", Reason: "no-target-access"}, {Check: "record-qualification", Outcome: "completed", Reason: "explicit-inspectable-claims"}}
	complete := locked > 0 && affected > 0
	for _, e := range r.Evaluations {
		complete = complete && e.VersionFullyEvaluated
	}
	if !complete {
		expected[1].Outcome = "incomplete"
		expected[1].Reason = "unsupported-or-unqualified"
	}
	records := locked > 0
	hypothesis := false
	for _, o := range r.Inventory {
		records = records && o.NameQualification == "value" && o.VersionQualification == "qualified" && one(o.LinkQualification, "absent", "non-link")
		hypothesis = hypothesis || o.IdentitySource == "locator-profile"
	}
	if !records {
		expected[5].Outcome = "incomplete"
		expected[5].Reason = "missing-unqualified-or-link-claims"
	}
	if hypothesis {
		expected = append(expected, demo.Coverage{Check: "canonical-name-correspondence", Outcome: "incomplete", Reason: "installation-name-hypothesis"})
	}
	if !reflect.DeepEqual(r.Coverage, expected) {
		return errProtocol
	}
	// Rebuild authority-bearing constants; never let a worker choose public policy.
	r.Schema = "packtrace.inspect.v1"
	r.Experimental = true
	r.Scope = "supplied-metadata"
	r.Privacy = "portable"
	r.ExitCode = 3
	r.Coverage = expected
	return nil
}
func expectedCandidates(r *inspect.Result) []demo.Candidate {
	out := []demo.Candidate{}
	for _, e := range r.Evaluations {
		o := r.Inventory[e.PackageIndex]
		if one(e.IdentityComparison, "equal", "installation-claim-equal") && e.IdentityQualification == "candidate" && e.VersionOutcome == "match" && e.Withdrawal == "not-declared" && one(o.LinkQualification, "absent", "non-link") {
			kind := "identity-version-only"
			if o.IdentitySource == "locator-profile" {
				kind = "installation-name-version-only"
			}
			out = append(out, demo.Candidate{PackageIndex: e.PackageIndex, AffectedIndex: e.AffectedIndex, Kind: kind, EnforcementEligible: false})
		}
	}
	return out
}
