package integrityscan

import (
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"

	"packtrace/internal/intel"
)

const maxAdvisorySummary = 320
const maxAdvisoryConditions = 8
const maxLocalExplanationBytes = 4 << 20

// Positions bind every condition to its original affected entry and supporting
// version/range. They are source claims, not origin or remediation authority.
type LocalAdvisoryCondition struct {
	Affected     int    `json:"affected"`
	VersionIndex int    `json:"versionIndex"`
	RangeIndex   int    `json:"rangeIndex"`
	Version      string `json:"version,omitempty"`
	Type         string `json:"type,omitempty"`
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
}

func safeAdvisorySummary(s string) bool {
	if len(s) > maxAdvisorySummary || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	lower := strings.ToLower(s)
	for _, forbidden := range []string{"://", " /", "../", `\`, "sha256-", "bearer ", "token=", "password=", "authorization:"} {
		if strings.Contains(lower, forbidden) {
			return false
		}
	}
	return !strings.HasPrefix(s, "/")
}

func validLocalCondition(c LocalAdvisoryCondition) bool {
	if c.Affected < 0 || c.Affected >= 4096 {
		return false
	}
	validVersion := func(s string) bool { _, err := intel.ParseSemVer(s); return len(s) <= 256 && err == nil }
	if c.VersionIndex >= 0 {
		return c.VersionIndex < 20000 && c.RangeIndex == -1 && validVersion(c.Version) && c.Type == "" && c.Introduced == "" && c.Fixed == ""
	}
	if c.VersionIndex != -1 || c.RangeIndex < 0 || c.RangeIndex >= 20000 || c.Version != "" || !oneOf(c.Type, "SEMVER", "ECOSYSTEM") || !validVersion(c.Fixed) {
		return false
	}
	if c.Introduced == "0" {
		return true
	}
	if !validVersion(c.Introduced) {
		return false
	}
	a, _ := intel.ParseSemVer(c.Introduced)
	b, _ := intel.ParseSemVer(c.Fixed)
	n, err := intel.CompareSemVer(a, b)
	return err == nil && n < 0
}

func localAdvisoryExplanation(record intel.SnapshotOriginalEvidence, index int) LocalAdvisory {
	out := localAdvisoryRecord(record, index)
	if record.State != intel.SnapshotOriginalVerified || record.SHA256 != record.Header.SourceSHA256 || record.SHA256 != record.Affected.SourceSHA256 {
		return out
	}
	// The original was already strictly parsed, verified and charged by the
	// mandatory-original reader. Decode only its small optional summary field;
	// never expose details, URLs, arbitrary raw JSON or target contents.
	var title struct {
		Summary json.RawMessage `json:"summary"`
	}
	if json.Unmarshal(record.Raw, &title) == nil && len(title.Summary) <= maxAdvisorySummary*6+2 {
		var s string
		if json.Unmarshal(title.Summary, &s) == nil {
			s = strings.Join(strings.Fields(s), " ")
			if safeAdvisorySummary(s) {
				out.Summary = s
			} else {
				out.ExplanationLimited = true
			}
		}
	}
	if len(title.Summary) > maxAdvisorySummary*6+2 {
		out.ExplanationLimited = true
	}
	add := func(c LocalAdvisoryCondition) bool {
		if !validLocalCondition(c) {
			return true
		}
		if len(out.Conditions) == maxAdvisoryConditions {
			out.ExplanationLimited = true
			return false
		}
		out.Conditions = append(out.Conditions, c)
		return true
	}
	for _, entry := range record.Affected.Entries {
		if entry.State != intel.OSVFieldValue {
			continue
		}
		for _, r := range entry.Ranges.Entries {
			// ponytail: only one plain introduced→fixed interval is presented as
			// a fixed boundary. Complex/disjoint/last_affected ranges stay unknown.
			if r.State != intel.OSVFieldValue || r.Repo.State != intel.OSVFieldAbsent || len(r.Events.Entries) != 2 {
				continue
			}
			a, b := r.Events.Entries[0], r.Events.Entries[1]
			if a.State != intel.OSVFieldValue || b.State != intel.OSVFieldValue || len(a.Fields) != 1 || len(b.Fields) != 1 || a.Fields[0].Name != "introduced" || b.Fields[0].Name != "fixed" || a.Fields[0].Value.State != intel.OSVFieldValue || b.Fields[0].Value.State != intel.OSVFieldValue {
				continue
			}
			if !add(LocalAdvisoryCondition{Affected: entry.Index, VersionIndex: -1, RangeIndex: r.Index, Type: r.Type.Value, Introduced: a.Fields[0].Value.Value, Fixed: b.Fields[0].Value.Value}) {
				return out
			}
		}
		for vi, v := range entry.Versions.Entries {
			if v.State == intel.OSVFieldValue && !add(LocalAdvisoryCondition{Affected: entry.Index, VersionIndex: vi, RangeIndex: -1, Version: v.Value}) {
				return out
			}
		}
	}
	return out
}

func localExplanationBytes(a LocalAdvisory) int {
	n := len(a.Summary)
	for _, c := range a.Conditions {
		n += 64 + len(c.Version) + len(c.Type) + len(c.Introduced) + len(c.Fixed)
	}
	return n
}

// Use only this decision's own source positions. No condition, alias or fixed
// version from a sibling affected entry/range can explain the selected match.
func localMatchReason(d AdvisoryDecision, o LocalObservation, a LocalAdvisory) (string, string) {
	if d.Advisory != a.Advisory || d.VersionOutcome != "match" {
		return "Version applicability was not established.", "Fix not determined."
	}
	for _, support := range d.Support {
		for _, c := range a.Conditions {
			if c.Affected != d.Affected || c.VersionIndex != support.Version || c.RangeIndex != support.Range {
				continue
			}
			if c.VersionIndex >= 0 && c.Version == o.Version {
				return "This exact version is listed as affected in the advisory.", "No corrected version established by this explicit-version condition."
			}
			if c.RangeIndex >= 0 && len(d.Support) == 1 && d.FullyEvaluated && validLocalCondition(c) {
				q, err := intel.ParseSemVer(o.Version)
				if err != nil {
					continue
				}
				fixed, _ := intel.ParseSemVer(c.Fixed)
				before, _ := intel.CompareSemVer(q, fixed)
				if before >= 0 {
					continue
				}
				if c.Introduced != "0" {
					intro, _ := intel.ParseSemVer(c.Introduced)
					after, _ := intel.CompareSemVer(q, intro)
					if after < 0 {
						continue
					}
				}
				bounds := c.Introduced + " <= version < " + c.Fixed
				if c.Introduced == "0" {
					bounds = "all versions below " + c.Fixed
				}
				return "The observed version matches the recorded affected interval: " + bounds + ".", "Advisory records a fixed boundary at " + c.Fixed + "; verify current applicability and compatibility before updating."
			}
		}
	}
	return "The version matches an affected condition; detailed bounds are unavailable in this bounded view.", "Corrected version not established; review the original advisory."
}
