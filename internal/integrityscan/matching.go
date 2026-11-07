package integrityscan

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	lockinventory "packtrace/internal/inventory"
	"packtrace/internal/projectinventory"
)

const maxMatchingBytes uint64 = 512 << 20
const maxMatchingObservations = 64
const maxMatchingDecisions = 4096

var ErrAdvisory = errors.New("scan: invalid-advisory-data")

type AdvisorySupport struct {
	Version int `json:"version"`
	Range   int `json:"range"`
}
type AdvisoryDecision struct {
	Sequence            int               `json:"sequence"`
	Observation         uint32            `json:"observation"`
	Advisory            int               `json:"advisory"`
	Affected            int               `json:"affected"`
	Rule                int               `json:"rule"`
	VersionOutcome      string            `json:"versionOutcome"`
	Outcome             string            `json:"outcome"`
	FullyEvaluated      bool              `json:"fullyEvaluated"`
	Category            string            `json:"category"`
	Profile             string            `json:"profile"`
	Activity            string            `json:"activity"`
	Origin              string            `json:"origin"`
	Source              string            `json:"source"`
	EnforcementEligible bool              `json:"enforcementEligible"`
	Support             []AdvisorySupport `json:"support"`
	Gaps                []string          `json:"gaps"`
}
type AdvisorySummary struct {
	Decisions         int      `json:"decisions"`
	Observations      int      `json:"observations"`
	TotalObservations int      `json:"totalObservations"`
	BytesRead         uint64   `json:"bytesRead"`
	Gaps              []string `json:"gaps"`
}

var matchingGaps = []string{
	"locked-only", "installed-unassessed", "declared-unassessed", "vulnerability-profile-unsupported",
	"index-completeness", "observation-limit", "evaluation-limit", "identity-byte-limit",
	"inventory-incomplete", "origin-unqualified", "source-unqualified", "identity-unqualified",
	"intelligence-unavailable", "identity-read-failed", "identity-empty", "binding-unqualified",
	"profile-unsupported", "activity-unknown", "version-unsupported", "support-limit",
	"source-stale", "correction-unsupported", "identity-resource-limit",
}

func addMatchingGap(gaps []string, gap string) []string {
	for _, g := range gaps {
		if g == gap {
			return gaps
		}
	}
	if len(gaps) < 32 {
		return append(gaps, gap)
	}
	return gaps
}
func matchingGapShape(gaps []string) bool {
	if gaps == nil || len(gaps) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, g := range gaps {
		if !oneOf(g, matchingGaps...) || seen[g] {
			return false
		}
		seen[g] = true
	}
	return true
}
func hasMatchingGap(gaps []string, gap string) bool {
	for _, g := range gaps {
		if g == gap {
			return true
		}
	}
	return false
}
func qualifiedSource(info Intelligence) bool {
	return ValidateIntelligence(info) == nil && info.State == "available" && oneOf(info.Provenance, "local-acquisition", "operator-designated")
}
func lockedPackage(class, kind string) bool { return class == "locked" && kind != "project" }
func baseAdvisory(o projectinventory.Observation, info Intelligence) AdvisoryDecision {
	d := AdvisoryDecision{Observation: o.ID, Affected: -1, VersionOutcome: "indeterminate", Outcome: "indeterminate", Category: "unknown", Profile: "unknown", Activity: "unknown", Origin: "unqualified", Source: "unqualified", Support: []AdvisorySupport{}, Gaps: []string{}}
	if qualifiedSource(info) {
		d.Source = "qualified"
	} else {
		d.Gaps = addMatchingGap(d.Gaps, "source-unqualified")
	}
	return d
}
func matchingRule(plan Plan, inv projectinventory.Result, o projectinventory.Observation) int {
	if ValidatePolicy(plan.Policy) != nil || plan.Manager != plan.Policy.Manager || !supportedPolicyPin(plan.TrustedPolicyDigest) || !strings.HasPrefix(plan.Manager, "npm@") || inv.Selection.Family != "npm" || inv.Selection.Profile != plan.Manager || inv.Selection.State != "usable" || o.Class != "locked" || o.Kind != "url" || o.Status != "complete" || !canonicalNPMName(o.Name) || o.Fields["version-state"] != "value" || o.Fields["origin-state"] != "value" || !oneOf(o.Fields["name-qualification"], "explicit-claim", "installation-claim") || o.Fields["installation-name"] != o.Name {
		return 0
	}
	if link, exists := o.Fields["link"]; exists && link != "false" {
		return 0
	}
	// Explicit names do not erase alias declarations in their owning lock record.
	for _, other := range inv.Model.Observations {
		if other.Source != o.Source || other.Class != "locked" {
			continue
		}
		for _, group := range other.Requirements {
			if group.State != lockinventory.FieldValue && group.State != lockinventory.FieldAbsent {
				return 0
			}
			for _, entry := range group.Entries {
				if entry.Name == o.Name && (entry.State != lockinventory.FieldValue || strings.HasPrefix(strings.TrimSpace(entry.Requirement), "npm:")) {
					return 0
				}
			}
		}
	}
	evidenceOK := false
	for _, e := range inv.Model.Evidence {
		if e.ID == o.Source && e.Complete && e.Location == inv.Selection.File && e.Method == "native-input-lease" {
			evidenceOK = true
		}
	}
	if !evidenceOK {
		return 0
	}
	for i, r := range plan.Policy.NPMOrigins {
		if r.Location == o.Location && r.Name == o.Name && r.Version == o.Version && r.Origin == o.Origin {
			return i + 1
		}
	}
	return 0
}

// MatchInventory evaluates locked claims only, sequentially releasing each raw identity.
// The source and operator rule qualify correspondence, not publisher authenticity.
func MatchInventory(ctx context.Context, plan Plan, inventory projectinventory.Result, snapshot *intelstore.Snapshot, info Intelligence, now time.Time, emit func(AdvisoryDecision) error) (AdvisorySummary, error) {
	s := AdvisorySummary{Gaps: []string{"locked-only", "installed-unassessed", "declared-unassessed", "index-completeness"}}
	if plan.Checks&cli.ArgumentCheckVulnerability != 0 {
		s.Gaps = addMatchingGap(s.Gaps, "vulnerability-profile-unsupported")
	}
	if !inventory.Complete {
		s.Gaps = addMatchingGap(s.Gaps, "inventory-incomplete")
	}
	if info.CheckAge != "current" || info.ReconciliationAge != "current" {
		s.Gaps = addMatchingGap(s.Gaps, "source-stale")
	}
	for _, o := range inventory.Model.Observations {
		if lockedPackage(o.Class, o.Kind) {
			s.TotalObservations++
		}
	}
	if plan.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) == 0 || emit == nil {
		return s, ErrAdvisory
	}
	ids := map[[32]byte]int{}
	work := 0
	send := func(d AdvisoryDecision) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		d.Sequence = s.Decisions
		if err := emit(d); err != nil {
			return err
		}
		s.Decisions++
		return nil
	}
	for _, o := range inventory.Model.Observations {
		if err := ctx.Err(); err != nil {
			return s, err
		}
		if !lockedPackage(o.Class, o.Kind) {
			continue
		}
		if s.Observations == maxMatchingObservations {
			s.Gaps = addMatchingGap(s.Gaps, "observation-limit")
			break
		}
		if work == maxMatchingDecisions {
			s.Gaps = addMatchingGap(s.Gaps, "evaluation-limit")
			break
		}
		d := baseAdvisory(o, info)
		d.Rule = matchingRule(plan, inventory, o)
		if d.Rule > 0 {
			d.Origin = "operator-npm-rule"
		} else {
			d.Gaps = addMatchingGap(d.Gaps, "origin-unqualified")
		}
		s.Observations++
		if d.Rule == 0 || !canonicalNPMName(o.Name) {
			work++
			d.Gaps = addMatchingGap(d.Gaps, "identity-unqualified")
			if err := send(d); err != nil {
				return s, err
			}
			continue
		}
		if snapshot == nil || ValidateIntelligence(info) != nil || info.State != "available" {
			work++
			d.Gaps = addMatchingGap(d.Gaps, "intelligence-unavailable")
			if err := send(d); err != nil {
				return s, err
			}
			continue
		}
		if s.BytesRead == maxMatchingBytes {
			work++
			d.Gaps = addMatchingGap(d.Gaps, "identity-byte-limit")
			s.Gaps = addMatchingGap(s.Gaps, "identity-byte-limit")
			if err := send(d); err != nil {
				return s, err
			}
			continue
		}
		evidence, consumed, err := snapshot.ReadIdentityLimited(ctx, o.Name, maxMatchingBytes-s.BytesRead)
		// The reader charges failed and canceled reads as well as successful ones.
		if consumed > maxMatchingBytes-s.BytesRead {
			return s, ErrAdvisory
		}
		s.BytesRead += consumed
		if s.BytesRead == maxMatchingBytes {
			s.Gaps = addMatchingGap(s.Gaps, "identity-byte-limit")
		}
		if ctx.Err() != nil {
			return s, ctx.Err()
		}
		if err != nil {
			work++
			d.Gaps = addMatchingGap(d.Gaps, "identity-read-failed")
			if s.BytesRead == maxMatchingBytes {
				d.Gaps = addMatchingGap(d.Gaps, "identity-byte-limit")
				s.Gaps = addMatchingGap(s.Gaps, "identity-byte-limit")
			}
			if err := send(d); err != nil {
				return s, err
			}
			continue
		}
		scopeGap := matchingIdentityScopeGap(evidence)
		if scopeGap != "" {
			d.Gaps = addMatchingGap(d.Gaps, scopeGap)
			s.Gaps = addMatchingGap(s.Gaps, scopeGap)
		}
		start := s.Decisions
		query, _ := intel.ParseSemVer(o.Version)
		unavailableSent := false
		for _, record := range evidence.Records {
			if work == maxMatchingDecisions || s.Decisions == maxMatchingDecisions {
				s.Gaps = addMatchingGap(s.Gaps, "evaluation-limit")
				break
			}
			if record.State != intel.SnapshotOriginalVerified || len(record.Bindings) == 0 {
				if unavailableSent {
					continue
				}
				unavailableSent = true
				work++
				row := d
				row.Gaps = append([]string{}, d.Gaps...)
				row.Gaps = addMatchingGap(row.Gaps, "binding-unqualified")
				if err := send(row); err != nil {
					return s, err
				}
				continue
			}
			// The shared evaluator evaluates ALL affected slots, not merely index hits.
			// Reserve that work before calling it; the summary has no public work counter.
			units := max(1, len(record.Affected.Entries), len(record.Bindings))
			if units > maxMatchingDecisions-work {
				s.Gaps = addMatchingGap(s.Gaps, "evaluation-limit")
				work = maxMatchingDecisions
				break
			}
			work += units
			if ids[record.SHA256] == 0 {
				ids[record.SHA256] = len(ids) + 1
			}
			versions, versionErr := intel.EvaluateOSVVersionConditions(record.Header, record.Affected, query)
			supported := qualifiedSource(info) && maliciousProfile(record.Raw, now) && (record.Header.Schema == intel.OSVHeaderSchemaV1Implicit || record.Header.Schema == intel.OSVHeaderSchemaV1Declared)
			activity := matchingActivity(record.Times, now)
			retainedSlots := map[int]bool{}
			for _, binding := range record.Bindings {
				if err := ctx.Err(); err != nil {
					return s, err
				}
				if s.Decisions == maxMatchingDecisions {
					s.Gaps = addMatchingGap(s.Gaps, "evaluation-limit")
					break
				}
				row := d
				row.Gaps = append([]string{}, d.Gaps...)
				row.Advisory = ids[record.SHA256]
				row.Activity = activity
				if supported {
					row.Category = "malicious"
					row.Profile = "openssf-malicious-v1"
				} else {
					row.Gaps = addMatchingGap(row.Gaps, "profile-unsupported")
					row.Gaps = addMatchingGap(row.Gaps, "correction-unsupported")
				}
				if activity == "unknown" {
					row.Gaps = addMatchingGap(row.Gaps, "activity-unknown")
				}
				idx := int(binding.AffectedIndex)
				valid := evidence.Declaration == intel.SnapshotDeclarationVerified && binding.State == intel.SnapshotBindingEligible && idx >= 0 && idx < len(record.Identity.Entries) && record.Identity.Entries[idx].Index == idx && record.Identity.Entries[idx].Qualification == intel.OSVNPMIdentityCandidate && record.Identity.Entries[idx].Name.Value == o.Name
				if valid && versionErr == nil && idx < len(versions.Entries) && versions.Entries[idx].Index == idx {
					row.Affected = idx
					v := versions.Entries[idx]
					row.FullyEvaluated = v.FullyEvaluated
					switch v.Outcome {
					case intel.OSVVersionMatch:
						row.VersionOutcome = "match"
					case intel.OSVVersionNoMatch:
						row.VersionOutcome = "no-match"
					}
					for _, support := range v.Support {
						if len(row.Support) == 256 {
							row.Gaps = addMatchingGap(row.Gaps, "support-limit")
							break
						}
						row.Support = append(row.Support, AdvisorySupport{Version: support.VersionIndex, Range: support.RangeIndex})
					}
					if !v.FullyEvaluated {
						row.Gaps = addMatchingGap(row.Gaps, "version-unsupported")
					}
				} else {
					row.Gaps = addMatchingGap(row.Gaps, "binding-unqualified")
				}
				if supported && row.Source == "qualified" && row.Origin == "operator-npm-rule" && row.Affected >= 0 {
					if activity == "withdrawn" {
						row.Outcome = "no-match"
					} else if activity == "not-withdrawn" {
						row.Outcome = row.VersionOutcome
					}
				}
				row.EnforcementEligible = row.Outcome == "match" && plan.Checks&cli.ArgumentCheckMalicious != 0
				// Several invalid index rows can refer to the same unavailable slot.
				// One controlled diagnostic retains that uncertainty without duplicate decisions.
				if retainedSlots[row.Affected] {
					continue
				}
				retainedSlots[row.Affected] = true
				if err := send(row); err != nil {
					return s, err
				}
			}
		}
		if start == s.Decisions && s.Decisions < maxMatchingDecisions {
			if work == maxMatchingDecisions {
				d.Gaps = addMatchingGap(d.Gaps, "evaluation-limit")
			} else {
				work++
				if scopeGap == "" {
					d.Gaps = addMatchingGap(d.Gaps, "identity-empty")
				}
			}
			if err := send(d); err != nil {
				return s, err
			}
		}
	}
	return s, nil
}

// Reader exhaustion is usable partial evidence, not an empty identity. Preserve
// both index/metadata limits and per-original retention limits across this boundary.
func matchingIdentityScopeGap(e intel.SnapshotNPMEvidence) string {
	for _, gap := range e.Gaps {
		if gap == intel.SnapshotGapResource {
			return "identity-resource-limit"
		}
	}
	for _, record := range e.Records {
		if record.Problem == intel.SnapshotOriginalProblemResource {
			return "identity-resource-limit"
		}
	}
	if e.BlockState != intel.SnapshotStreamStructured || e.CatalogState != intel.SnapshotStreamStructured || e.Declaration != intel.SnapshotDeclarationVerified {
		return "binding-unqualified"
	}
	return ""
}

var malID = regexp.MustCompile(`^MAL-[0-9]{4}-[0-9]+$`)

// The documented source key is a bounded lowercase identifier, not a URL.
var originSource = regexp.MustCompile(`^[a-z0-9-]{1,256}$`)

func closedObject(raw json.RawMessage, keys ...string) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, false
	}
	for k := range m {
		if !oneOf(k, keys...) {
			return nil, false
		}
	}
	return m, true
}
func emptyExtension(raw json.RawMessage) bool {
	if raw == nil {
		return true
	}
	m, ok := closedObject(raw)
	return ok && len(m) == 0
}
func metadataTime(raw json.RawMessage, now time.Time) (time.Time, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil || !strings.HasSuffix(s, "Z") {
		return time.Time{}, false
	}
	t := intel.ProjectOSVTimestampText(s)
	return t.Value, t.State == intel.TimestampValue && !t.Value.After(now)
}
func matchingActivity(t intel.OSVTimes, now time.Time) string {
	if t.Modified.State != intel.TimestampValue || t.Modified.Value.After(now) || t.Published.State != intel.TimestampValue || t.Published.Value.After(t.Modified.Value) {
		return "unknown"
	}
	switch t.Withdrawal {
	case intel.WithdrawalNotDeclared:
		return "not-withdrawn"
	case intel.WithdrawalReported:
		if !t.Withdrawn.Value.After(now) && !t.Withdrawn.Value.Before(t.Published.Value) && !t.Withdrawn.Value.After(t.Modified.Value) {
			return "withdrawn"
		}
	}
	return "unknown"
}

// Unknown applicability/correction fields fail closed, including unrelated affected
// slots. Informational OSV fields are never followed or used as classification.
func maliciousProfile(raw []byte, now time.Time) bool {
	top, ok := closedObject(raw, "schema_version", "id", "modified", "published", "withdrawn", "aliases", "related", "upstream", "summary", "details", "severity", "credits", "references", "affected", "database_specific")
	if !ok {
		return false
	}
	var id string
	if json.Unmarshal(top["id"], &id) != nil || !malID.MatchString(id) {
		return false
	}
	db, ok := closedObject(top["database_specific"], "malicious-packages-origins", "iocs")
	if !ok {
		return false
	}
	if iocs, exists := db["iocs"]; exists {
		var m map[string]json.RawMessage
		if json.Unmarshal(iocs, &m) != nil || m == nil {
			return false
		}
	}
	var origins []json.RawMessage
	if json.Unmarshal(db["malicious-packages-origins"], &origins) != nil || len(origins) == 0 || len(origins) > 64 {
		return false
	}
	for _, rawOrigin := range origins {
		o, ok := closedObject(rawOrigin, "source", "sha256", "import_time", "modified_time", "id", "versions", "ranges")
		if !ok {
			return false
		}
		var source, hash string
		if json.Unmarshal(o["source"], &source) != nil || !originSource.MatchString(source) || json.Unmarshal(o["sha256"], &hash) != nil {
			return false
		}
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != hash {
			return false
		}
		imported, ok := metadataTime(o["import_time"], now)
		if !ok {
			return false
		}
		modified, ok := metadataTime(o["modified_time"], now)
		if !ok || modified.After(imported) {
			return false
		}
		if rawID, exists := o["id"]; exists {
			var s string
			if json.Unmarshal(rawID, &s) != nil || !text(s, 256) {
				return false
			}
		}
		if rawVersions, exists := o["versions"]; exists {
			var versions []string
			if json.Unmarshal(rawVersions, &versions) != nil || versions == nil || len(versions) > 4096 {
				return false
			}
			for _, v := range versions {
				if !text(v, 256) {
					return false
				}
			}
		}
		if rawRanges, exists := o["ranges"]; exists {
			if !profileRanges(rawRanges) {
				return false
			}
		}
	}
	var affected []json.RawMessage
	if json.Unmarshal(top["affected"], &affected) != nil || len(affected) != 1 {
		return false
	}
	for _, rawAffected := range affected {
		a, ok := closedObject(rawAffected, "package", "versions", "ranges", "severity", "database_specific", "ecosystem_specific")
		if !ok || !emptyExtension(a["database_specific"]) || !emptyExtension(a["ecosystem_specific"]) {
			return false
		}
		if _, ok := closedObject(a["package"], "ecosystem", "name", "purl"); !ok {
			return false
		}
		if ranges, exists := a["ranges"]; exists && !profileRanges(ranges) {
			return false
		}
	}
	return true
}
func profileRanges(raw json.RawMessage) bool {
	var ranges []json.RawMessage
	if json.Unmarshal(raw, &ranges) != nil || ranges == nil || len(ranges) > 4096 {
		return false
	}
	for _, rawRange := range ranges {
		r, ok := closedObject(rawRange, "type", "repo", "events", "database_specific")
		if !ok || !emptyExtension(r["database_specific"]) {
			return false
		}
		var events []json.RawMessage
		if json.Unmarshal(r["events"], &events) != nil || events == nil || len(events) > 4096 {
			return false
		}
		for _, event := range events {
			if _, ok := closedObject(event, "introduced", "fixed", "last_affected", "limit"); !ok {
				return false
			}
		}
	}
	return true
}

func ValidateAdvisoryDecision(plan Plan, inventory projectinventory.PublicInventory, info Intelligence, d AdvisoryDecision) error {
	if projectinventory.ValidatePublic(inventory) != nil || ValidateIntelligence(info) != nil || ValidatePolicy(plan.Policy) != nil || plan.Manager != plan.Policy.Manager || plan.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) == 0 || d.Sequence < 0 || d.Sequence >= 4096 || d.Observation == 0 || int(d.Observation) > len(inventory.Observations) || d.Advisory < 0 || d.Advisory > 4096 || d.Affected < -1 || d.Affected >= 20000 || d.Rule < 0 || d.Rule > len(plan.Policy.NPMOrigins) || !oneOf(d.VersionOutcome, "match", "no-match", "indeterminate") || !oneOf(d.Outcome, "match", "no-match", "indeterminate") || !oneOf(d.Category, "malicious", "unknown") || !oneOf(d.Profile, "openssf-malicious-v1", "unknown") || !oneOf(d.Activity, "not-withdrawn", "withdrawn", "unknown") || !oneOf(d.Origin, "operator-npm-rule", "unqualified") || !oneOf(d.Source, "qualified", "unqualified") || d.Support == nil || len(d.Support) > 256 || !matchingGapShape(d.Gaps) {
		return ErrAdvisory
	}
	if info.State == "available" {
		if plan.TrustedSnapshotDigest != "" {
			pin, err := intel.ParseSnapshotDigest(plan.TrustedSnapshotDigest)
			if err != nil || hex.EncodeToString(pin[:]) != info.ID || info.Selection != "expected-digest" {
				return ErrAdvisory
			}
		} else if info.Selection == "expected-digest" {
			return ErrAdvisory
		}
	}
	o := inventory.Observations[d.Observation-1]
	if o.ID != d.Observation || !lockedPackage(o.Class, o.Kind) {
		return ErrAdvisory
	}
	if (d.Source == "qualified") != qualifiedSource(info) || (d.Profile == "openssf-malicious-v1") != (d.Category == "malicious") || (d.Origin == "operator-npm-rule") != (d.Rule > 0) {
		return ErrAdvisory
	}
	if d.Rule > 0 {
		if !supportedPolicyPin(plan.TrustedPolicyDigest) || !strings.HasPrefix(plan.Manager, "npm@") || inventory.Selection.Family != "npm" || inventory.Selection.State != "usable" || o.Kind != "url" || o.Status != "complete" || o.Source == 0 || int(o.Source) > len(inventory.Evidence) {
			return ErrAdvisory
		}
		e := inventory.Evidence[o.Source-1]
		if e.Status != "complete" || e.Method != "native-input-lease" {
			return ErrAdvisory
		}
	}
	if d.Category == "malicious" && d.Source != "qualified" {
		return ErrAdvisory
	}
	if d.Advisory > 0 && info.State != "available" {
		return ErrAdvisory
	}
	if d.Advisory == 0 && (d.Category != "unknown" || d.Profile != "unknown" || d.Activity != "unknown" || d.Affected != -1 || d.FullyEvaluated) {
		return ErrAdvisory
	}
	if d.Affected >= 0 && d.Advisory == 0 || d.VersionOutcome != "indeterminate" && (d.Affected < 0 || d.Advisory == 0) || d.FullyEvaluated && d.VersionOutcome == "indeterminate" || d.VersionOutcome == "no-match" && !d.FullyEvaluated {
		return ErrAdvisory
	}
	if d.VersionOutcome == "match" && len(d.Support) == 0 || d.VersionOutcome != "match" && len(d.Support) != 0 {
		return ErrAdvisory
	}
	seen := map[AdvisorySupport]bool{}
	for _, support := range d.Support {
		if support.Version < -1 || support.Range < -1 || support.Version >= 20000 || support.Range >= 20000 || (support.Version >= 0) == (support.Range >= 0) || seen[support] {
			return ErrAdvisory
		}
		seen[support] = true
	}
	if hasMatchingGap(d.Gaps, "origin-unqualified") != (d.Origin == "unqualified") || hasMatchingGap(d.Gaps, "source-unqualified") != (d.Source == "unqualified") {
		return ErrAdvisory
	}
	if d.Profile != "unknown" && (hasMatchingGap(d.Gaps, "profile-unsupported") || hasMatchingGap(d.Gaps, "correction-unsupported")) || d.Activity != "unknown" && hasMatchingGap(d.Gaps, "activity-unknown") || d.Affected >= 0 && hasMatchingGap(d.Gaps, "binding-unqualified") {
		return ErrAdvisory
	}
	if d.Affected >= 0 && !d.FullyEvaluated && !hasMatchingGap(d.Gaps, "version-unsupported") {
		return ErrAdvisory
	}
	qualified := d.Category == "malicious" && d.Profile == "openssf-malicious-v1" && d.Source == "qualified" && d.Origin == "operator-npm-rule" && d.Affected >= 0
	expected := "indeterminate"
	if qualified {
		if d.Activity == "withdrawn" {
			expected = "no-match"
		} else if d.Activity == "not-withdrawn" {
			expected = d.VersionOutcome
		}
	}
	if d.Outcome != expected || d.EnforcementEligible != (d.Outcome == "match" && plan.Checks&cli.ArgumentCheckMalicious != 0) {
		return ErrAdvisory
	}
	for _, requirement := range []struct {
		condition bool
		gap       string
	}{
		{d.Origin == "unqualified", "origin-unqualified"}, {d.Source == "unqualified", "source-unqualified"},
		{d.Profile == "unknown" && d.Advisory > 0, "profile-unsupported"}, {d.Activity == "unknown" && d.Advisory > 0, "activity-unknown"},
	} {
		if requirement.condition && !hasMatchingGap(d.Gaps, requirement.gap) {
			return ErrAdvisory
		}
	}
	return nil
}

func ValidateAdvisorySummary(s AdvisorySummary, decisions []AdvisoryDecision, inventory projectinventory.PublicInventory) error {
	if projectinventory.ValidatePublic(inventory) != nil || s.Decisions != len(decisions) || s.Decisions > 4096 || s.Observations < 0 || s.Observations > 64 || s.TotalObservations < 0 || s.BytesRead > maxMatchingBytes || !matchingGapShape(s.Gaps) {
		return ErrAdvisory
	}
	total := 0
	for _, o := range inventory.Observations {
		if lockedPackage(o.Class, o.Kind) {
			total++
		}
	}
	if total != s.TotalObservations {
		return ErrAdvisory
	}
	observations := map[uint32]bool{}
	seen := map[[3]int]bool{}
	advisories := map[int]bool{}
	for i, d := range decisions {
		if d.Sequence != i || d.Observation == 0 || int(d.Observation) > len(inventory.Observations) || !lockedPackage(inventory.Observations[d.Observation-1].Class, inventory.Observations[d.Observation-1].Kind) {
			return ErrAdvisory
		}
		if d.Advisory < 0 || d.Advisory > maxMatchingDecisions {
			return ErrAdvisory
		}
		if d.Advisory > 0 && !advisories[d.Advisory] {
			if d.Advisory != len(advisories)+1 {
				return ErrAdvisory
			}
			advisories[d.Advisory] = true
		}
		key := [3]int{int(d.Observation), d.Advisory, d.Affected}
		if seen[key] {
			return ErrAdvisory
		}
		seen[key] = true
		observations[d.Observation] = true
	}
	if !inventory.Complete && !hasMatchingGap(s.Gaps, "inventory-incomplete") {
		return ErrAdvisory
	}
	// Exhaustion can precede evaluation of an oversized original, but only after
	// an actual identity read and an emitted diagnostic for its observation.
	if hasMatchingGap(s.Gaps, "evaluation-limit") && (s.Observations == 0 || s.Decisions == 0 || s.BytesRead == 0) {
		return ErrAdvisory
	}
	if len(observations) != s.Observations || s.Observations > s.TotalObservations {
		return ErrAdvisory
	}
	for _, gap := range []string{"locked-only", "installed-unassessed", "declared-unassessed", "index-completeness"} {
		if !hasMatchingGap(s.Gaps, gap) {
			return ErrAdvisory
		}
	}
	if s.Observations < s.TotalObservations && !hasMatchingGap(s.Gaps, "observation-limit") && !hasMatchingGap(s.Gaps, "evaluation-limit") {
		return ErrAdvisory
	}
	if hasMatchingGap(s.Gaps, "observation-limit") && (s.Observations != 64 || s.TotalObservations <= 64) || hasMatchingGap(s.Gaps, "identity-byte-limit") && s.BytesRead != maxMatchingBytes {
		return ErrAdvisory
	}
	return nil
}
