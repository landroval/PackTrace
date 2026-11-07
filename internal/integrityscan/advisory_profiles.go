package integrityscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"

	"packtrace/internal/intel"
)

// AdvisoryQualification interprets original-bound publisher/type metadata only.
// It supplies neither acquisition authority nor package/version affectedness.
type AdvisoryQualification struct {
	Category, Profile, Activity string
	Gaps                        []string
}

var githubProfileID = regexp.MustCompile(`^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$`)
var githubProfileDate = regexp.MustCompile(`^[0-9]{4}/(0[1-9]|1[0-2])$`)

// qualifyAdvisory requires the verified original and unchanged projections. The
// caller must separately qualify OSV acquisition and the selected affected binding.
// No URL is followed; ID, descriptive text and informational metadata never type
// an advisory. Unknown correction/applicability extensions fail closed globally.
func qualifyAdvisory(record intel.SnapshotOriginalEvidence, affectedIndex int, now time.Time) AdvisoryQualification {
	q := AdvisoryQualification{Category: "unknown", Profile: "unknown", Activity: "unknown", Gaps: []string{}}
	unsupported := func(correction bool) AdvisoryQualification {
		q.Gaps = append(q.Gaps, "profile-unsupported")
		if correction {
			q.Gaps = append(q.Gaps, "correction-unsupported")
		}
		return q
	}
	if record.State != intel.SnapshotOriginalVerified || sha256.Sum256(record.Raw) != record.SHA256 || record.Header.SourceSHA256 != record.SHA256 || record.Affected.SourceSHA256 != record.SHA256 || record.Times.SourceSHA256 != record.SHA256 || (record.Header.Schema != intel.OSVHeaderSchemaV1Implicit && record.Header.Schema != intel.OSVHeaderSchemaV1Declared) {
		q.Gaps = append(q.Gaps, "activity-unknown")
		return unsupported(false)
	}
	q.Activity = advisoryProfileActivity(record.Times, now)
	if q.Activity == "unknown" {
		q.Gaps = append(q.Gaps, "activity-unknown")
	}
	if record.Affected.State != intel.OSVFieldValue || affectedIndex < 0 || affectedIndex >= len(record.Affected.Entries) {
		q.Gaps = append(q.Gaps, "binding-unqualified")
		return unsupported(false)
	}
	top, ok := closedObject(record.Raw, "schema_version", "id", "modified", "published", "withdrawn", "aliases", "related", "upstream", "summary", "details", "severity", "credits", "references", "affected", "database_specific")
	if !ok {
		return unsupported(true)
	}
	var id string
	if json.Unmarshal(top["id"], &id) != nil || record.Header.ID.State != intel.OSVFieldValue || record.Header.ID.Value != id {
		return unsupported(false)
	}
	var affected []json.RawMessage
	if json.Unmarshal(top["affected"], &affected) != nil || len(affected) != len(record.Affected.Entries) {
		return unsupported(false)
	}
	// Preserve the authored first milestone profile without weakening its helpers.
	if len(affected) == 1 && record.Affected.Entries[0].State == intel.OSVFieldValue && record.Affected.Entries[0].Ecosystem.State == intel.OSVFieldValue && record.Affected.Entries[0].Ecosystem.Value == "npm" && record.Affected.Entries[0].Name.State == intel.OSVFieldValue && canonicalNPMName(record.Affected.Entries[0].Name.Value) && maliciousProfile(record.Raw, now) {
		q.Category, q.Profile = "malicious", "openssf-malicious-v1"
		return q
	}
	category, profile := "", ""
	for i, raw := range affected {
		a, ok := closedObject(raw, "package", "versions", "ranges", "severity", "database_specific", "ecosystem_specific")
		if !ok || !advisoryInformationalSeverity(a["ecosystem_specific"]) {
			return unsupported(true)
		}
		pkg, ok := closedObject(a["package"], "ecosystem", "name", "purl")
		var name, ecosystem string
		entry := record.Affected.Entries[i]
		if !ok || json.Unmarshal(pkg["name"], &name) != nil || !canonicalNPMName(name) || json.Unmarshal(pkg["ecosystem"], &ecosystem) != nil || ecosystem != "npm" || entry.Index != i || entry.State != intel.OSVFieldValue || entry.Name.State != intel.OSVFieldValue || entry.Name.Value != name || entry.Ecosystem.State != intel.OSVFieldValue || entry.Ecosystem.Value != ecosystem {
			return unsupported(false)
		}
		if ranges, exists := a["ranges"]; exists && !profileRanges(ranges) {
			return unsupported(true)
		}
		db, ok := closedObject(a["database_specific"], "source", "cwes")
		var source string
		if !ok || json.Unmarshal(db["source"], &source) != nil || !profileStringList(db["cwes"], 256) {
			return unsupported(true)
		}
		c, p := advisorySourceProfile(source, id, name)
		if c == "" || (category != "" && (category != c || profile != p)) {
			return unsupported(false)
		}
		category, profile = c, p
	}
	if category == "" || !advisoryTopMetadata(top["database_specific"], profile, now) {
		return unsupported(true)
	}
	q.Category, q.Profile = category, profile
	return q
}

func advisoryProfileActivity(t intel.OSVTimes, now time.Time) string {
	if t.Modified.State != intel.TimestampValue || t.Modified.Value.After(now) || (t.Published.State != intel.TimestampAbsent && t.Published.State != intel.TimestampValue) || t.Published.State == intel.TimestampValue && t.Published.Value.After(t.Modified.Value) {
		return "unknown"
	}
	if t.Withdrawal == intel.WithdrawalNotDeclared && t.Withdrawn.State == intel.TimestampAbsent {
		return "not-withdrawn"
	}
	if t.Withdrawal == intel.WithdrawalReported && t.Withdrawn.State == intel.TimestampValue && !t.Withdrawn.Value.After(now) && !t.Withdrawn.Value.After(t.Modified.Value) && (t.Published.State == intel.TimestampAbsent || !t.Withdrawn.Value.Before(t.Published.Value)) {
		return "withdrawn"
	}
	return "unknown"
}

func advisorySourceProfile(source, id, name string) (string, string) {
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.Opaque != "" || u.RawPath != "" || strings.Contains(source, "%") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(source, "#") || u.String() != source {
		return "", ""
	}
	if malID.MatchString(id) && u.Path == "/ossf/malicious-packages/blob/main/osv/malicious/npm/"+name+"/"+id+".json" {
		return "malicious", "osv-openssf-malicious-v1"
	}
	if !githubProfileID.MatchString(id) {
		return "", ""
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/github/advisory-database/blob/main/advisories/"), "/")
	if !strings.HasPrefix(u.Path, "/github/advisory-database/blob/main/advisories/") || len(parts) != 5 || !githubProfileDate.MatchString(parts[1]+"/"+parts[2]) || parts[3] != id || parts[4] != id+".json" {
		return "", ""
	}
	switch parts[0] {
	case "github-reviewed":
		return "vulnerability", "osv-github-reviewed-v1"
	case "malware":
		return "malicious", "osv-github-malware-v1"
	}
	return "", ""
}

// Absent informational lists are supported, but null/unknown shapes are not.
func profileStringList(raw json.RawMessage, limit int) bool {
	if raw == nil {
		return true
	}
	var values []string
	if json.Unmarshal(raw, &values) != nil || values == nil || len(values) > limit {
		return false
	}
	for _, value := range values {
		if !text(value, 256) {
			return false
		}
	}
	return true
}

// Only severity is informational here; functions/conditions/corrections remain
// unsupported. Empty and absent extensions preserve the legacy shape.
func advisoryInformationalSeverity(raw json.RawMessage) bool {
	if emptyExtension(raw) {
		return true
	}
	m, ok := closedObject(raw, "severity")
	if !ok {
		return false
	}
	return advisorySeverity(m["severity"])
}

func advisorySeverity(raw json.RawMessage) bool {
	var severity string
	return json.Unmarshal(raw, &severity) == nil && oneOf(severity, "LOW", "MODERATE", "HIGH", "CRITICAL", "UNKNOWN")
}

func advisoryTopMetadata(raw json.RawMessage, profile string, now time.Time) bool {
	if profile == "osv-openssf-malicious-v1" {
		return advisoryOpenSSFMetadata(raw, now)
	}
	if raw == nil {
		return true
	}
	db, ok := closedObject(raw, "cwe_ids", "github_reviewed", "github_reviewed_at", "nvd_published_at", "severity")
	if !ok || !profileStringList(db["cwe_ids"], 256) {
		return false
	}
	if v, exists := db["github_reviewed"]; exists {
		if string(v) != "true" && string(v) != "false" {
			return false
		}
	}
	for _, key := range []string{"github_reviewed_at", "nvd_published_at"} {
		if v, exists := db[key]; exists && string(v) != "null" {
			if _, ok := metadataTime(v, now); !ok {
				return false
			}
		}
	}
	if v, exists := db["severity"]; exists && !advisorySeverity(v) {
		return false
	}
	return true
}

// Contributor provenance remains informational, with the same bounded shape as
// the legacy helper. It cannot override the exact per-affected source type.
func advisoryOpenSSFMetadata(raw json.RawMessage, now time.Time) bool {
	db, ok := closedObject(raw, "malicious-packages-origins", "iocs")
	if !ok {
		return false
	}
	if v, exists := db["iocs"]; exists {
		var iocs map[string]json.RawMessage
		if json.Unmarshal(v, &iocs) != nil || iocs == nil {
			return false
		}
	}
	var origins []json.RawMessage
	if json.Unmarshal(db["malicious-packages-origins"], &origins) != nil || len(origins) == 0 || len(origins) > 64 {
		return false
	}
	for _, raw := range origins {
		o, ok := closedObject(raw, "source", "sha256", "import_time", "modified_time", "id", "versions", "ranges")
		var source, hash string
		if !ok || json.Unmarshal(o["source"], &source) != nil || !originSource.MatchString(source) || json.Unmarshal(o["sha256"], &hash) != nil {
			return false
		}
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != hash {
			return false
		}
		imported, ok := metadataTime(o["import_time"], now)
		modified, valid := metadataTime(o["modified_time"], now)
		if !ok || !valid || modified.After(imported) {
			return false
		}
		if v, exists := o["id"]; exists {
			var id string
			if json.Unmarshal(v, &id) != nil || !text(id, 256) {
				return false
			}
		}
		if !profileStringList(o["versions"], 4096) {
			return false
		}
		if v, exists := o["ranges"]; exists && !profileRanges(v) {
			return false
		}
	}
	return true
}
