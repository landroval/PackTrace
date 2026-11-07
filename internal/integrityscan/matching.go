package integrityscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
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
	Sequence            int                     `json:"sequence"`
	Observation         uint32                  `json:"observation"`
	LockedObservation   uint32                  `json:"lockedObservation,omitempty"`
	Advisory            int                     `json:"advisory"`
	Affected            int                     `json:"affected"`
	Rule                int                     `json:"rule"`
	VersionOutcome      string                  `json:"versionOutcome"`
	Outcome             string                  `json:"outcome"`
	FullyEvaluated      bool                    `json:"fullyEvaluated"`
	FirstVersionProblem *AdvisoryVersionProblem `json:"firstVersionProblem,omitempty"`
	Category            string                  `json:"category"`
	Profile             string                  `json:"profile"`
	Activity            string                  `json:"activity"`
	Origin              string                  `json:"origin"`
	Source              string                  `json:"source"`
	EnforcementEligible bool                    `json:"enforcementEligible"`
	Support             []AdvisorySupport       `json:"support"`
	Gaps                []string                `json:"gaps"`
}
type AdvisorySummary struct {
	Decisions                  int      `json:"decisions"`
	Observations               int      `json:"observations"`
	TotalObservations          int      `json:"totalObservations"`
	InstalledObservations      int      `json:"installedObservations"`
	TotalInstalledObservations int      `json:"totalInstalledObservations"`
	Work                       int      `json:"work"`
	BytesRead                  uint64   `json:"bytesRead"`
	Gaps                       []string `json:"gaps"`
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

// MatchInventory preserves the portable callback API.
func MatchInventory(ctx context.Context, plan Plan, inventory projectinventory.Result, snapshot *intelstore.Snapshot, info Intelligence, now time.Time, emit func(AdvisoryDecision) error) (AdvisorySummary, error) {
	return MatchInventoryWithLocal(ctx, plan, inventory, snapshot, info, now, emit, nil)
}

func categorySelected(plan Plan, category string) bool {
	return category == "malicious" && plan.Checks&cli.ArgumentCheckMalicious != 0 || category == "vulnerability" && plan.Checks&cli.ArgumentCheckVulnerability != 0
}

// indexedMatchingOrigins shares the selected-lock and alias checks across physical
// observations. Exact location rules take priority, including mismatching rules.
func indexedMatchingOrigins(plan Plan, inv projectinventory.Result) map[uint32]AdvisoryDecision {
	out := map[uint32]AdvisoryDecision{}
	if ValidatePolicy(plan.Policy) != nil || plan.Manager != plan.Policy.Manager || !supportedPolicyPin(plan.TrustedPolicyDigest) || !strings.HasPrefix(plan.Manager, "npm@") || inv.Selection.Family != "npm" || inv.Selection.Profile != plan.Manager || inv.Selection.State != "usable" {
		return out
	}
	evidence := map[uint32]projectinventory.Evidence{}
	observations := map[uint32]projectinventory.Observation{}
	badSource := map[uint32]bool{}
	aliases := map[uint32]map[string]bool{}
	rules := map[string]int{}
	for i, r := range plan.Policy.NPMOrigins {
		rules[strings.ToLower(r.Location)] = i + 1
	}
	for _, e := range inv.Model.Evidence {
		evidence[e.ID] = e
	}
	for _, o := range inv.Model.Observations {
		observations[o.ID] = o
		if o.Class != "locked" {
			continue
		}
		for _, group := range o.Requirements {
			if group.State != lockinventory.FieldValue && group.State != lockinventory.FieldAbsent {
				badSource[o.Source] = true
			}
			for _, entry := range group.Entries {
				if entry.State != lockinventory.FieldValue || strings.HasPrefix(strings.TrimSpace(entry.Requirement), "npm:") {
					if aliases[o.Source] == nil {
						aliases[o.Source] = map[string]bool{}
					}
					aliases[o.Source][entry.Name] = true
				}
			}
		}
	}
	for _, o := range inv.Model.Observations {
		e := evidence[o.Source]
		_, versionErr := intel.ParseSemVer(o.Version)
		if o.Class != "locked" || o.Kind != "url" || o.Status != "complete" || !canonicalNPMName(o.Name) || versionErr != nil || o.Fields["version-state"] != "value" || o.Fields["origin-state"] != "value" || !oneOf(o.Fields["name-qualification"], "explicit-claim", "installation-claim") || o.Fields["installation-name"] != o.Name || badSource[o.Source] || aliases[o.Source][o.Name] || !e.Complete || e.Method != "native-input-lease" || e.Location != inv.Selection.File {
			continue
		}
		if link, exists := o.Fields["link"]; exists && link != "false" {
			continue
		}
		d := AdvisoryDecision{}
		if i := rules[strings.ToLower(o.Location)]; i > 0 {
			r := plan.Policy.NPMOrigins[i-1]
			if r.Location != o.Location || r.Name != o.Name || r.Version != o.Version || r.Origin != o.Origin {
				continue
			}
			d.Rule, d.Origin = i, "operator-npm-rule"
		} else if plan.Policy.NPMRegistry != "" && o.Origin == npmTarballOrigin(o.Name, o.Version) {
			d.Origin = "operator-npm-registry"
		} else {
			continue
		}
		out[o.ID] = d
	}
	relations := map[uint32][]projectinventory.Relation{}
	for _, r := range inv.Model.Relations {
		if r.Kind == "locked-correspondence" {
			relations[r.To] = append(relations[r.To], r)
		}
	}
	// The older exact rules granted locked correspondence only. Installed
	// association is the newly explicit registry grant, never an implicit upgrade.
	if plan.Policy.NPMRegistry == "" {
		return out
	}
	for _, o := range inv.Model.Observations {
		if o.Class != "installed" || o.Kind != "directory" || o.Status != "complete" || !canonicalNPMName(o.Name) || o.Fields["name-state"] != "value" || o.Fields["version-state"] != "value" || o.Fields["installation-name"] != o.Name || o.Fields["physical-target"] != o.Location {
			continue
		}
		_, err := intel.ParseSemVer(o.Version)
		mid, metaErr := strconv.ParseUint(o.Fields["metadata-evidence"], 10, 32)
		manifest, metadata := evidence[o.Source], evidence[uint32(mid)]
		if err != nil || metaErr != nil || !manifest.Complete || manifest.Method != "native-input-lease" || manifest.Location != o.Location+"/package.json" || !metadata.Complete || metadata.Method != "native-metadata-lease" || metadata.Location != o.Location || manifest.Scope != o.Workspace || metadata.Scope != o.Workspace {
			continue
		}
		rs := relations[o.ID]
		if len(rs) != 1 {
			continue
		}
		r := rs[0]
		locked := observations[r.From]
		d, ok := out[r.From]
		if !ok || locked.Class != "locked" || r.Status != "claim-agreement" || r.Evidence != o.Source || locked.Workspace != o.Workspace || locked.Location != o.Location || locked.Name != o.Name || locked.Version != o.Version {
			continue
		}
		d.LockedObservation = locked.ID
		out[o.ID] = d
	}
	return out
}

// MatchInventoryWithLocal retains only one identity's raw evidence at a time.
// A window groups at most 64 names in one selected block; budgets are global.
func MatchInventoryWithLocal(ctx context.Context, plan Plan, inventory projectinventory.Result, snapshot *intelstore.Snapshot, info Intelligence, now time.Time, emit func(AdvisoryDecision) error, local func(LocalAdvisory) error) (AdvisorySummary, error) {
	s := AdvisorySummary{Gaps: []string{"declared-unassessed", "index-completeness"}}
	if !inventory.Complete {
		s.Gaps = addMatchingGap(s.Gaps, "inventory-incomplete")
	}
	if info.CheckAge != "current" || info.ReconciliationAge != "current" {
		s.Gaps = addMatchingGap(s.Gaps, "source-stale")
	}
	if plan.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) == 0 || emit == nil || !oneOf(plan.Privacy, "", "portable", "local") || plan.Policy.RequirePortable && plan.Privacy == "local" {
		return s, ErrAdvisory
	}
	origins := indexedMatchingOrigins(plan, inventory)
	groups := map[string][]projectinventory.Observation{}
	ids := map[[32]byte]int{}
	counted := map[uint32]bool{}
	classes := map[uint32]string{}
	for _, o := range inventory.Model.Observations {
		classes[o.ID] = o.Class
	}
	limited := false
	send := func(d AdvisoryDecision) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.Work >= maxMatchingDecisions {
			limited = true
			s.Gaps = addMatchingGap(s.Gaps, "evaluation-limit")
			return nil
		}
		d.Sequence = s.Decisions
		if err := emit(d); err != nil {
			return err
		}
		s.Work++
		s.Decisions++
		if !counted[d.Observation] {
			counted[d.Observation] = true
			if classes[d.Observation] == "installed" {
				s.InstalledObservations++
			} else {
				s.Observations++
			}
		}
		return nil
	}
	base := func(o projectinventory.Observation) AdvisoryDecision {
		d := baseAdvisory(o, info)
		if grant, ok := origins[o.ID]; ok {
			d.Rule, d.Origin, d.LockedObservation = grant.Rule, grant.Origin, grant.LockedObservation
		} else {
			d.Gaps = addMatchingGap(d.Gaps, "origin-unqualified")
		}
		return d
	}
	for _, o := range inventory.Model.Observations {
		if lockedPackage(o.Class, o.Kind) {
			s.TotalObservations++
		} else if o.Class == "installed" {
			s.TotalInstalledObservations++
		} else {
			continue
		}
		groups[o.Name] = append(groups[o.Name], o)
	}
	// Unqualified observations are still visible; they cannot trigger public lookups.
	qualified := map[string][]projectinventory.Observation{}
	names := []string{}
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, o := range groups[name] {
			d := base(o)
			gap := ""
			if d.Origin == "unqualified" {
				gap = "identity-unqualified"
			} else if snapshot == nil || ValidateIntelligence(info) != nil || info.State != "available" {
				gap = "intelligence-unavailable"
			}
			if gap != "" {
				d.Gaps = addMatchingGap(d.Gaps, gap)
				if err := send(d); err != nil {
					return s, err
				}
			} else {
				qualified[name] = append(qualified[name], o)
			}
		}
	}
	// Sort by the reader's exact npm identity hash, keeping every bucket contiguous.
	names = names[:0]
	for name := range qualified {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := sha256.Sum256([]byte("npm\x00"+names[i])), sha256.Sum256([]byte("npm\x00"+names[j]))
		return hex.EncodeToString(a[:]) < hex.EncodeToString(b[:])
	})
	process := func(name string, evidence intel.SnapshotNPMEvidence) error {
		scopeGap := matchingIdentityScopeGap(evidence)
		if scopeGap != "" {
			s.Gaps = addMatchingGap(s.Gaps, scopeGap)
		}
		versions := map[string][]projectinventory.Observation{}
		order := []string{}
		for _, o := range qualified[name] {
			if _, ok := versions[o.Version]; !ok {
				order = append(order, o.Version)
			}
			versions[o.Version] = append(versions[o.Version], o)
		}
		// Only bounded decision projections survive each evaluation, never raw originals.
		for _, version := range order {
			query, _ := intel.ParseSemVer(version)
			rows := []AdvisoryDecision{}
			unavailable := false
			for _, record := range evidence.Records {
				if limited {
					break
				}
				if record.State != intel.SnapshotOriginalVerified || len(record.Bindings) == 0 {
					if !unavailable {
						rows = append(rows, AdvisoryDecision{Affected: -1, Gaps: []string{"binding-unqualified"}})
						unavailable = true
					}
					continue
				}
				// The evaluator inspects all affected slots, including non-index hits.
				units := max(1, len(record.Affected.Entries), len(record.Bindings))
				if units+len(rows)+1 > maxMatchingDecisions-s.Work {
					limited = true
					s.Gaps = addMatchingGap(s.Gaps, "evaluation-limit")
					break
				}
				s.Work += units
				result, versionErr := intel.EvaluateOSVNPMVersionConditions(record.Header, record.Affected, query)
				retained := map[int]bool{}
				for _, binding := range record.Bindings {
					if s.Work+len(rows) == maxMatchingDecisions {
						limited = true
						s.Gaps = addMatchingGap(s.Gaps, "evaluation-limit")
						break
					}
					idx := int(binding.AffectedIndex)
					row := AdvisoryDecision{Affected: -1, Category: "unknown", Profile: "unknown", Activity: "unknown", VersionOutcome: "indeterminate", Support: []AdvisorySupport{}, Gaps: []string{}}
					q := qualifyAdvisory(record, idx, now)
					row.Activity = q.Activity
					if qualifiedSource(info) {
						row.Category, row.Profile = q.Category, q.Profile
					}
					for _, gap := range q.Gaps {
						row.Gaps = addMatchingGap(row.Gaps, gap)
					}
					if row.Profile == "unknown" {
						row.Gaps = addMatchingGap(row.Gaps, "profile-unsupported")
						row.Gaps = addMatchingGap(row.Gaps, "correction-unsupported")
					}
					if row.Activity == "unknown" {
						row.Gaps = addMatchingGap(row.Gaps, "activity-unknown")
					}
					valid := scopeGap != "binding-unqualified" && evidence.Declaration == intel.SnapshotDeclarationVerified && binding.State == intel.SnapshotBindingEligible && idx >= 0 && idx < len(record.Identity.Entries) && record.Identity.Entries[idx].Index == idx && record.Identity.Entries[idx].Qualification == intel.OSVNPMIdentityCandidate && record.Identity.Entries[idx].Name.Value == name
					if valid && versionErr == nil && idx < len(result.Entries) && result.Entries[idx].Index == idx {
						row.Affected = idx
						v := result.Entries[idx]
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
							row.FirstVersionProblem = firstAdvisoryVersionProblem(result, idx)
						}
					} else {
						row.Gaps = addMatchingGap(row.Gaps, "binding-unqualified")
					}
					if retained[row.Affected] {
						continue
					}
					retained[row.Affected] = true
					if ids[record.SHA256] == 0 {
						ids[record.SHA256] = len(ids) + 1
						if plan.Privacy == "local" && local != nil {
							if err := local(localAdvisoryRecord(record, ids[record.SHA256])); err != nil {
								return err
							}
						}
					}
					row.Advisory = ids[record.SHA256]
					rows = append(rows, row)
					if len(rows) >= maxMatchingDecisions {
						limited = true
						s.Gaps = addMatchingGap(s.Gaps, "evaluation-limit")
						break
					}
				}
			}
			if len(rows) == 0 {
				gap := scopeGap
				if limited {
					gap = "evaluation-limit"
				} else if gap == "" {
					gap = "identity-empty"
				}
				rows = append(rows, AdvisoryDecision{Affected: -1, Gaps: []string{gap}})
			}
			for _, o := range versions[version] {
				for _, template := range rows {
					d := base(o)
					d.Advisory, d.Affected = template.Advisory, template.Affected
					if template.Advisory > 0 {
						d.Category, d.Profile, d.Activity, d.VersionOutcome, d.FullyEvaluated = template.Category, template.Profile, template.Activity, template.VersionOutcome, template.FullyEvaluated
						d.Support = append(d.Support, template.Support...)
						d.FirstVersionProblem = cloneAdvisoryVersionProblem(template.FirstVersionProblem)
					}
					for _, gap := range template.Gaps {
						d.Gaps = addMatchingGap(d.Gaps, gap)
					}
					if scopeGap != "" {
						d.Gaps = addMatchingGap(d.Gaps, scopeGap)
					}
					if d.Profile != "unknown" && d.Source == "qualified" && d.Affected >= 0 {
						if d.Activity == "withdrawn" {
							d.Outcome = "no-match"
						} else if d.Activity == "not-withdrawn" {
							d.Outcome = d.VersionOutcome
						}
					}
					d.EnforcementEligible = d.Outcome == "match" && categorySelected(plan, d.Category)
					if err := send(d); err != nil {
						return err
					}
				}
			}
			if limited {
				break
			}
		}
		delete(qualified, name)
		return nil
	}
	for start := 0; start < len(names) && !limited; {
		end := start + 1
		first := sha256.Sum256([]byte("npm\x00" + names[start]))
		for end < len(names) && end-start < maxMatchingObservations {
			h := sha256.Sum256([]byte("npm\x00" + names[end]))
			if h[0] != first[0] {
				break
			}
			end++
		}
		if s.BytesRead == maxMatchingBytes {
			s.Gaps = addMatchingGap(s.Gaps, "identity-byte-limit")
			break
		}
		var callbackErr error
		windowStart := s.Decisions
		consumed, err := snapshot.WalkIdentities(ctx, names[start:end], maxMatchingBytes-s.BytesRead, func(name string, evidence intel.SnapshotNPMEvidence) error {
			callbackErr = process(name, evidence)
			if callbackErr == nil && (limited || s.Work == maxMatchingDecisions && len(qualified) > 0) {
				limited = true
				s.Gaps = addMatchingGap(s.Gaps, "evaluation-limit")
				return intelstore.ErrIdentityWalkStopped
			}
			return callbackErr
		})
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
		if callbackErr != nil {
			return s, callbackErr
		}
		if err != nil {
			// A failed final lease/close cannot certify already emitted evidence.
			// Abort closure instead of retaining a positive from an unstable generation.
			if s.Decisions != windowStart {
				return s, ErrAdvisory
			}
			// A reader failure leaves un-emitted identities explicitly indeterminate.
			for _, name := range names[start:end] {
				for _, o := range qualified[name] {
					d := base(o)
					d.Gaps = addMatchingGap(d.Gaps, "identity-read-failed")
					if s.BytesRead == maxMatchingBytes {
						d.Gaps = addMatchingGap(d.Gaps, "identity-byte-limit")
					}
					if e := send(d); e != nil {
						return s, e
					}
				}
				delete(qualified, name)
			}
		}
		start = end
	}
	if err := ctx.Err(); err != nil {
		return s, err
	}
	if s.Observations+s.InstalledObservations < s.TotalObservations+s.TotalInstalledObservations && !hasMatchingGap(s.Gaps, "evaluation-limit") && !hasMatchingGap(s.Gaps, "identity-byte-limit") {
		s.Gaps = addMatchingGap(s.Gaps, "observation-limit")
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

// Public validation can check typed endpoints/evidence, not redacted claim text.
func publicMatchingEndpoint(inv projectinventory.PublicInventory, o projectinventory.PublicObservation, d AdvisoryDecision) bool {
	if o.Class == "locked" {
		return d.LockedObservation == 0
	}
	if o.Class != "installed" {
		return false
	}
	if d.Origin == "unqualified" {
		return d.LockedObservation == 0
	}
	if o.Kind != "directory" || o.Status != "complete" || d.LockedObservation == 0 || int(d.LockedObservation) > len(inv.Observations) {
		return false
	}
	locked := inv.Observations[d.LockedObservation-1]
	if !lockedPackage(locked.Class, locked.Kind) || locked.Kind != "url" || locked.Status != "complete" || locked.Workspace != o.Workspace {
		return false
	}
	count := 0
	for _, r := range inv.Relations {
		if r.Kind != "locked-correspondence" || r.To != o.ID {
			continue
		}
		count++
		if r.From != locked.ID || r.Status != "claim-agreement" || r.Evidence != o.Source {
			return false
		}
	}
	if count != 1 || o.Source == 0 || int(o.Source) > len(inv.Evidence) {
		return false
	}
	e := inv.Evidence[o.Source-1]
	if e.Status != "complete" || e.Method != "native-input-lease" || e.Scope != o.Workspace {
		return false
	}
	if o.MetadataEvidence == 0 || int(o.MetadataEvidence) > len(inv.Evidence) {
		return false
	}
	metadata := inv.Evidence[o.MetadataEvidence-1]
	return metadata.Scope == o.Workspace && metadata.Method == "native-metadata-lease" && metadata.Status == "complete"
}

func ValidateAdvisoryDecision(plan Plan, inventory projectinventory.PublicInventory, info Intelligence, d AdvisoryDecision) error {
	if projectinventory.ValidatePublic(inventory) != nil || ValidateIntelligence(info) != nil || ValidatePolicy(plan.Policy) != nil || plan.Manager != plan.Policy.Manager || !oneOf(plan.Privacy, "", "portable", "local") || plan.Policy.RequirePortable && plan.Privacy == "local" || plan.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) == 0 || d.Sequence < 0 || d.Sequence >= 4096 || d.Observation == 0 || int(d.Observation) > len(inventory.Observations) || d.Advisory < 0 || d.Advisory > 4096 || d.Affected < -1 || d.Affected >= 20000 || d.Rule < 0 || d.Rule > len(plan.Policy.NPMOrigins) || !oneOf(d.VersionOutcome, "match", "no-match", "indeterminate") || !oneOf(d.Outcome, "match", "no-match", "indeterminate") || !oneOf(d.Category, "malicious", "vulnerability", "unknown") || !oneOf(d.Profile, "openssf-malicious-v1", "osv-openssf-malicious-v1", "osv-github-reviewed-v1", "osv-github-malware-v1", "unknown") || !oneOf(d.Activity, "not-withdrawn", "withdrawn", "unknown") || !oneOf(d.Origin, "operator-npm-rule", "operator-npm-registry", "unqualified") || !oneOf(d.Source, "qualified", "unqualified") || d.Support == nil || len(d.Support) > 256 || !matchingGapShape(d.Gaps) {
		return ErrAdvisory
	}
	if !validAdvisoryVersionProblem(d) {
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
	if o.ID != d.Observation || !(lockedPackage(o.Class, o.Kind) || o.Class == "installed") {
		return ErrAdvisory
	}
	if !publicMatchingEndpoint(inventory, o, d) || o.Class == "installed" && d.Origin != "unqualified" && plan.Policy.NPMRegistry != "https://registry.npmjs.org" {
		return ErrAdvisory
	}
	profileCategory := "unknown"
	switch d.Profile {
	case "openssf-malicious-v1", "osv-openssf-malicious-v1", "osv-github-malware-v1":
		profileCategory = "malicious"
	case "osv-github-reviewed-v1":
		profileCategory = "vulnerability"
	}
	if (d.Source == "qualified") != qualifiedSource(info) || profileCategory != d.Category || (d.Origin == "operator-npm-rule") != (d.Rule > 0) {
		return ErrAdvisory
	}
	if d.Origin != "unqualified" {
		locked := o
		if d.LockedObservation > 0 {
			locked = inventory.Observations[d.LockedObservation-1]
		}
		if d.Origin == "operator-npm-registry" && plan.Policy.NPMRegistry != "https://registry.npmjs.org" {
			return ErrAdvisory
		}
		if !supportedPolicyPin(plan.TrustedPolicyDigest) || !strings.HasPrefix(plan.Manager, "npm@") || inventory.Selection.Family != "npm" || inventory.Selection.State != "usable" || locked.Kind != "url" || locked.Status != "complete" || locked.Source == 0 || int(locked.Source) > len(inventory.Evidence) {
			return ErrAdvisory
		}
		e := inventory.Evidence[locked.Source-1]
		if e.Status != "complete" || e.Method != "native-input-lease" {
			return ErrAdvisory
		}
	}
	if d.Category != "unknown" && d.Source != "qualified" {
		return ErrAdvisory
	}
	if d.Origin == "unqualified" && d.Advisory > 0 {
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
	qualified := d.Category != "unknown" && d.Profile != "unknown" && d.Source == "qualified" && d.Origin != "unqualified" && d.Affected >= 0
	expected := "indeterminate"
	if qualified {
		if d.Activity == "withdrawn" {
			expected = "no-match"
		} else if d.Activity == "not-withdrawn" {
			expected = d.VersionOutcome
		}
	}
	if d.Outcome != expected || d.EnforcementEligible != (d.Outcome == "match" && categorySelected(plan, d.Category)) {
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
	if projectinventory.ValidatePublic(inventory) != nil || s.Decisions != len(decisions) || s.Decisions > maxMatchingDecisions || s.Work < s.Decisions || s.Work > maxMatchingDecisions || s.Observations < 0 || s.InstalledObservations < 0 || s.Observations+s.InstalledObservations > maxMatchingDecisions || s.TotalObservations < 0 || s.TotalInstalledObservations < 0 || s.BytesRead > maxMatchingBytes || !matchingGapShape(s.Gaps) {
		return ErrAdvisory
	}
	total, installed := 0, 0
	for _, o := range inventory.Observations {
		if lockedPackage(o.Class, o.Kind) {
			total++
		} else if o.Class == "installed" {
			installed++
		}
	}
	if total != s.TotalObservations || installed != s.TotalInstalledObservations {
		return ErrAdvisory
	}
	observations := map[uint32]bool{}
	seen := map[[3]int]bool{}
	advisories := map[int]bool{}
	assessedLocked, assessedInstalled := 0, 0
	for i, d := range decisions {
		if d.Sequence != i || d.Observation == 0 || int(d.Observation) > len(inventory.Observations) {
			return ErrAdvisory
		}
		o := inventory.Observations[d.Observation-1]
		if !(lockedPackage(o.Class, o.Kind) || o.Class == "installed") || !publicMatchingEndpoint(inventory, o, d) || d.Advisory < 0 || d.Advisory > maxMatchingDecisions {
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
		if !observations[d.Observation] {
			if o.Class == "installed" {
				assessedInstalled++
			} else {
				assessedLocked++
			}
			observations[d.Observation] = true
		}
	}
	if assessedLocked != s.Observations || assessedInstalled != s.InstalledObservations || s.Observations > total || s.InstalledObservations > installed {
		return ErrAdvisory
	}
	if !inventory.Complete && !hasMatchingGap(s.Gaps, "inventory-incomplete") {
		return ErrAdvisory
	}
	for _, gap := range []string{"declared-unassessed", "index-completeness"} {
		if !hasMatchingGap(s.Gaps, gap) {
			return ErrAdvisory
		}
	}
	// Exhaustion is observable work, never a fabricated zero-scope success.
	if s.Work < s.Decisions+len(advisories) || len(advisories) == 0 && s.Work != s.Decisions || s.Work > s.Decisions && s.BytesRead == 0 || s.BytesRead > 0 && len(observations) == 0 {
		return ErrAdvisory
	}
	if hasMatchingGap(s.Gaps, "evaluation-limit") && (s.Work == 0 || s.Decisions == 0 || s.Work != maxMatchingDecisions && s.BytesRead == 0) {
		return ErrAdvisory
	}
	if hasMatchingGap(s.Gaps, "identity-byte-limit") && s.BytesRead != maxMatchingBytes {
		return ErrAdvisory
	}
	omitted := s.Observations+s.InstalledObservations < total+installed
	if omitted && !hasMatchingGap(s.Gaps, "evaluation-limit") && !hasMatchingGap(s.Gaps, "identity-byte-limit") && !hasMatchingGap(s.Gaps, "observation-limit") {
		return ErrAdvisory
	}
	if hasMatchingGap(s.Gaps, "observation-limit") && (!omitted || s.Observations+s.InstalledObservations != maxMatchingDecisions) {
		return ErrAdvisory
	}
	if hasMatchingGap(s.Gaps, "locked-only") || hasMatchingGap(s.Gaps, "installed-unassessed") || hasMatchingGap(s.Gaps, "vulnerability-profile-unsupported") {
		return ErrAdvisory
	}
	return nil
}
