package integrityscan

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/integrity"
	"packtrace/internal/projectinventory"
)

var ErrPolicyMaterial = errors.New("scan: invalid-policy-material")

// These public projections deliberately omit exception text and raw receipts.
type PolicyEvaluation struct {
	Source             string                 `json:"source"`
	Provided           cli.ArgumentOptions    `json:"provided"`
	Checks             cli.ArgumentChecks     `json:"checks"`
	FailOn             cli.ArgumentChecks     `json:"failOn"`
	Manager            string                 `json:"manager"`
	Privacy            string                 `json:"privacy"`
	MinimumAssurance   string                 `json:"minimumAssurance"`
	MaxExceptionDays   int                    `json:"maxExceptionDays"`
	MaterialLimited    bool                   `json:"materialLimited"`
	Findings           []PolicyFinding        `json:"findings"`
	Exceptions         []ExceptionDisposition `json:"exceptions"`
	EnforcedUnaccepted int                    `json:"enforcedUnaccepted"`
}
type PolicyFinding struct {
	Ordinal    int           `json:"ordinal"`
	Category   string        `json:"category"`
	Record     int           `json:"record"`
	Difference int           `json:"difference"`
	Decision   int           `json:"decision"`
	Accepted   bool          `json:"accepted"`
	Enforced   bool          `json:"enforced"`
	Exception  int           `json:"exception"`
	Tracking   string        `json:"tracking,omitempty"`
	Acceptance string        `json:"acceptance,omitempty"`
	Package    string        `json:"package,omitempty"`
	Version    string        `json:"version,omitempty"`
	Instance   string        `json:"instance,omitempty"`
	Path       string        `json:"path,omitempty"`
	Review     *PolicyReview `json:"review,omitempty"`
}
type ExceptionDisposition struct {
	Ordinal     int    `json:"ordinal"`
	Disposition string `json:"disposition"`
	Findings    []int  `json:"findings"`
}

// Fixed ordered JSON arrays provide typed, deterministic, domain-separated
// encoding. Never include scan IDs, policy bytes/pin, or container freshness.
func policyFingerprint(domain string, values ...any) string {
	b, _ := json.Marshal(append([]any{"packtrace-policy-v1", domain}, values...))
	return sourceSRI(b)
}
func ProjectFingerprint(p ProjectEvidence) string {
	if !projectShape(p) {
		return ""
	}
	return policyFingerprint("project", p.ManifestSHA256, p.LockSHA256, p.Profile, p.LockFile)
}
func TrackingFingerprint(m PolicyMaterial) string {
	if !scopeShape(m.Scope) {
		return ""
	}
	s := m.Scope
	return policyFingerprint("tracking", s.Project, s.Category, s.Rule, s.Class, s.Package, s.Version, s.Origin, s.Instance, s.Path, s.Advisory, s.Change)
}
func AcceptanceFingerprint(m PolicyMaterial) string {
	if ValidatePolicyMaterialShape(m) != nil {
		return ""
	}
	return policyFingerprint("acceptance", TrackingFingerprint(m), ProjectFingerprint(m.Project), m.SourceSHA256, m.LockSourceSHA256, m.OriginalSHA256, m.Affected, m.Profile, m.PhysicalTarget, m.DirectoryKind, m.LinkSHA256, m.Expected, m.Observed, m.ReferenceSRI, m.ReferenceObservedSRI, m.Assurance, m.ReferenceContext)
}
func projectShape(p ProjectEvidence) bool {
	return p.Scope == 1 && p.Manifest > 0 && p.Lock > 0 && p.Manifest != p.Lock && hexSHA(p.ManifestSHA256) && hexSHA(p.LockSHA256) && profile(p.Profile) && oneOf(p.LockFile, "package-lock.json", "npm-shrinkwrap.json", "bun.lock") && (strings.HasPrefix(p.Profile, "npm@") == (p.LockFile != "bun.lock"))
}
func sideShape(s EvidenceSide) bool {
	if s.State == "absent" {
		return s.Type == "none" && s.Size == 0 && s.SHA256 == "" && s.LinkSHA256 == ""
	}
	if s.State != "present" || s.Size < 0 {
		return false
	}
	switch s.Type {
	case "file":
		return hexSHA(s.SHA256) && s.LinkSHA256 == ""
	case "directory":
		return s.Size == 0 && s.SHA256 == "" && s.LinkSHA256 == ""
	case "link":
		return s.Size == 0 && s.SHA256 == "" && hexSHA(s.LinkSHA256)
	}
	return false
}
func ValidatePolicyMaterialShape(m PolicyMaterial) error {
	if !projectShape(m.Project) || !scopeShape(m.Scope) || m.Scope.Project != ProjectFingerprint(m.Project) || !hexSHA(m.SourceSHA256) || !hexSHA(m.LockSourceSHA256) || m.LockSourceSHA256 != m.Project.LockSHA256 || m.Profile == "" || len(m.Profile) > 128 || m.Record < 0 || m.Difference < 0 || m.Advisory < 0 || m.Affected < 0 {
		return ErrPolicyMaterial
	}
	if m.Scope.Category == "integrity" {
		if m.ObservedEntryID == "" || len(m.ReferenceEntryID) > 128 || len(m.ObservedEntryID) > 128 || m.Observation == 0 || m.Advisory != 0 || m.Affected != 0 || m.OriginalSHA256 != "" || m.Profile != m.Project.Profile || !relative(m.PhysicalTarget) || !oneOf(m.DirectoryKind, "directory", "link") || (m.DirectoryKind == "link" && !hexSHA(m.LinkSHA256)) || (m.DirectoryKind == "directory" && m.LinkSHA256 != "") || !sideShape(m.Expected) || m.Expected.Type == "link" || !sideShape(m.Observed) || !strongSRI(m.ReferenceSRI) || !strongSRI(m.ReferenceObservedSRI) || !oneOf(m.Assurance, "lockfile-consistent", "independently-anchored") || !oneOf(m.ReferenceContext, "none", "patch", "generated") {
			return ErrPolicyMaterial
		}
		switch m.Scope.Change {
		case "missing":
			if m.Expected.State != "present" || m.Observed.State != "absent" {
				return ErrPolicyMaterial
			}
		case "added":
			if m.Expected.State != "absent" || m.Observed.State != "present" {
				return ErrPolicyMaterial
			}
		case "modified":
			if m.Expected.Type != "file" || m.Observed.Type != "file" || m.Expected.State != "present" || m.Observed.State != "present" || m.Expected == m.Observed {
				return ErrPolicyMaterial
			}
		case "type-changed":
			if m.Expected.State != "present" || m.Observed.State != "present" || m.Expected.Type == m.Observed.Type {
				return ErrPolicyMaterial
			}
		}
	} else {
		if m.ReferenceEntryID != "" || m.ObservedEntryID != "" || m.Observation == 0 || m.Advisory < 1 || m.Record != 0 || m.Difference != 0 || !hexSHA(m.OriginalSHA256) || !oneOf(m.Profile, "openssf-malicious-v1", "osv-openssf-malicious-v1", "osv-github-reviewed-v1", "osv-github-malware-v1") || m.Expected != (EvidenceSide{}) || m.Observed != (EvidenceSide{}) || m.ReferenceSRI != "" || m.ReferenceObservedSRI != "" || m.Assurance != "" || m.ReferenceContext != "" {
			return ErrPolicyMaterial
		}
		if m.Scope.Class == "locked" {
			if m.PhysicalTarget != "" || m.DirectoryKind != "" || m.LinkSHA256 != "" || m.SourceSHA256 != m.LockSourceSHA256 {
				return ErrPolicyMaterial
			}
		} else if !relative(m.PhysicalTarget) || !oneOf(m.DirectoryKind, "directory", "link") || (m.DirectoryKind == "link" && !hexSHA(m.LinkSHA256)) || (m.DirectoryKind == "directory" && m.LinkSHA256 != "") {
			return ErrPolicyMaterial
		}
	}
	return nil
}

// ValidatePolicyMaterial joins already admitted numeric endpoints and semantic
// parents. Supplied byte hashes are physical-worker receipts, not independent
// physical attestation by this validator.
func ValidatePolicyMaterial(plan Plan, inv projectinventory.PublicInventory, records []Record, advisories []AdvisoryDecision, m PolicyMaterial) error {
	return ValidatePolicyMaterials(plan, inv, records, advisories, []PolicyMaterial{m})
}

// Validate the shared graph/plan once, not once per finding. The supervisor calls
// this after the private exchange joins, so semantic work cannot starve receipt
// of the worker's bounded periodic samples or certify provisional frames.
func ValidatePolicyMaterials(plan Plan, inv projectinventory.PublicInventory, records []Record, advisories []AdvisoryDecision, rows []PolicyMaterial) error {
	if len(rows) > MaxPolicyMaterials || ValidatePlanPolicy(plan) != nil || len(rows) != 0 && projectinventory.ValidatePublic(inv) != nil {
		return ErrPolicyMaterial
	}
	for _, row := range rows {
		if validatePolicyMaterial(plan, inv, records, advisories, row) != nil {
			return ErrPolicyMaterial
		}
	}
	return nil
}

func validatePolicyMaterial(plan Plan, inv projectinventory.PublicInventory, records []Record, advisories []AdvisoryDecision, m PolicyMaterial) error {
	if ValidatePolicyMaterialShape(m) != nil || (!plan.Builtin && m.Project.Profile != plan.Manager) || (plan.Builtin && profile(plan.Manager) && m.Project.Profile != plan.Manager) || inv.Selection.State != "usable" || inv.Selection.Evidence != m.Project.Lock || inv.Selection.Family != strings.Split(m.Project.Profile, "@")[0] {
		return ErrPolicyMaterial
	}
	evidence := func(id uint32, method string) bool {
		if id == 0 || int(id) > len(inv.Evidence) {
			return false
		}
		e := inv.Evidence[id-1]
		return e.ID == id && e.Scope == m.Project.Scope && e.Method == method && e.Status == "complete"
	}
	bit, validCategory := categories([]string{m.Scope.Category})
	if !validCategory || plan.Checks&bit == 0 {
		return ErrPolicyMaterial
	}
	for _, g := range inv.Gaps {
		if g.Evidence == m.Project.Manifest || g.Evidence == m.Project.Lock || oneOf(g.Code, "discovery-incomplete", "path-collision", "name-limit", "gap-list-truncated", "selection-invalid", "selection-indeterminate") {
			return ErrPolicyMaterial
		}
	}
	if !evidence(m.Project.Manifest, "native-input-lease") || !evidence(m.Project.Lock, "native-input-lease") {
		return ErrPolicyMaterial
	}
	root := false
	for _, s := range inv.Scopes {
		if s.ID == 1 && s.Kind == "project" && s.Parent == 0 {
			root = true
		}
	}
	if !root {
		return ErrPolicyMaterial
	}
	if int(m.Observation) > len(inv.Observations) || m.Observation == 0 {
		return ErrPolicyMaterial
	}
	own := inv.Observations[m.Observation-1]
	if own.ID != m.Observation || own.Class != m.Scope.Class || own.Status != "complete" || own.Source == 0 || int(own.Source) > len(inv.Evidence) {
		return ErrPolicyMaterial
	}
	source := inv.Evidence[own.Source-1]
	if source.ID != own.Source || source.Status != "complete" || source.Method != "native-input-lease" || source.Scope != own.Workspace {
		return ErrPolicyMaterial
	}
	if own.Class == "installed" {
		if own.Kind != m.DirectoryKind || own.MetadataEvidence == 0 || int(own.MetadataEvidence) > len(inv.Evidence) {
			return ErrPolicyMaterial
		}
		witness := inv.Evidence[own.MetadataEvidence-1]
		if witness.ID != own.MetadataEvidence || witness.Scope != own.Workspace || witness.Method != "native-metadata-lease" || witness.Status != "complete" {
			return ErrPolicyMaterial
		}
	}
	if m.Scope.Category == "integrity" {
		if m.Record >= len(records) {
			return ErrPolicyMaterial
		}
		r := records[m.Record]
		if r.Index != m.Record || r.Index < 0 || r.Index >= len(plan.Policy.References) || m.Difference >= len(r.Assessment.Differences) || !validPolicyWitnesses(r) || r.PolicyObservation != m.Observation || own.Class != "installed" || source.MetadataEvidence != own.MetadataEvidence {
			return ErrPolicyMaterial
		}
		foundWitness := false
		for _, w := range r.PolicyWitnesses {
			if w.Difference == m.Difference && w.EntryID == m.ReferenceEntryID && w.EvidenceID == m.ObservedEntryID && w.Fingerprint == PolicyDifferenceFingerprint(m) {
				foundWitness = true
			}
		}
		if !foundWitness {
			return ErrPolicyMaterial
		}
		ref := plan.Policy.References[r.Index]
		d := r.Assessment.Differences[m.Difference]
		if d.EntryID != m.ReferenceEntryID || d.EvidenceID != m.ObservedEntryID || differenceName(d.Kind) != m.Scope.Change || m.Scope.Package != ref.Name || m.Scope.Version != ref.Version || m.Scope.Origin != ref.Origin || m.Scope.Instance != ref.Location || m.PhysicalTarget != ref.Location || m.ReferenceSRI != ref.ExpectedSRI || m.ReferenceContext != ref.Context || m.Assurance != policyAssurance(r.Assessment.Assurance) || r.Lock.SourceHash != hexSRI(m.LockSourceSHA256) || r.Lock.SourceLocator != m.Project.LockFile || !claimMatches(ref, r.Lock) {
			return ErrPolicyMaterial
		}
		// The observed compressed artifact must be an actual allowed SRI token.
		tokens := strings.Fields(m.ReferenceObservedSRI)
		if len(tokens) != 1 {
			return ErrPolicyMaterial
		}
		found := false
		for _, v := range strings.Fields(ref.ExpectedSRI) {
			if v == tokens[0] {
				found = true
			}
		}
		if !found {
			return ErrPolicyMaterial
		}
	} else {
		if int(m.Observation) > len(inv.Observations) {
			return ErrPolicyMaterial
		}
		o := inv.Observations[m.Observation-1]
		if o.ID != m.Observation || o.Class != m.Scope.Class || o.Status != "complete" || o.Source == 0 || int(o.Source) > len(inv.Evidence) {
			return ErrPolicyMaterial
		}
		e := inv.Evidence[o.Source-1]
		if e.ID != o.Source || e.Status != "complete" || e.Method != "native-input-lease" {
			return ErrPolicyMaterial
		}
		if o.Class == "locked" && o.Source != m.Project.Lock {
			return ErrPolicyMaterial
		}
		matched := 0
		for _, d := range advisories {
			if d.Observation == m.Observation && d.Advisory == m.Advisory && d.Affected == m.Affected && d.Category == m.Scope.Category {
				if !d.EnforcementEligible || d.Candidate || d.Outcome != "match" || d.VersionOutcome != "match" || d.Activity != "not-withdrawn" || d.Source != "qualified" || d.Origin == "unqualified" || d.Profile != m.Profile || !publicMatchingEndpoint(inv, o, d) || !materialOrigin(plan, inv, m, d) {
					return ErrPolicyMaterial
				}
				matched++
			}
		}
		if matched != 1 {
			return ErrPolicyMaterial
		}
		if o.Class == "installed" {
			if o.MetadataEvidence == 0 || int(o.MetadataEvidence) > len(inv.Evidence) {
				return ErrPolicyMaterial
			}
			w := inv.Evidence[o.MetadataEvidence-1]
			if w.Status != "complete" || w.Method != "native-metadata-lease" {
				return ErrPolicyMaterial
			}
		}
	}
	return nil
}

func materialOrigin(p Plan, inv projectinventory.PublicInventory, m PolicyMaterial, d AdvisoryDecision) bool {
	if !supportedPolicyPin(p.TrustedPolicyDigest) || !strings.HasPrefix(m.Project.Profile, "npm@") {
		return false
	}
	if m.Scope.Class == "installed" {
		if p.Policy.NPMRegistry != "https://registry.npmjs.org" || m.PhysicalTarget != m.Scope.Instance || d.LockedObservation == 0 || int(d.LockedObservation) > len(inv.Observations) || inv.Observations[d.LockedObservation-1].Source != m.Project.Lock {
			return false
		}
	}
	// Exact location rules take priority even when a tuple mismatches. A
	// registry-wide grant cannot repair a more specific refusal.
	for i, r := range p.Policy.NPMOrigins {
		if strings.EqualFold(r.Location, m.Scope.Instance) {
			return d.Origin == "operator-npm-rule" && d.Rule == i+1 && r.Location == m.Scope.Instance && r.Name == m.Scope.Package && r.Version == m.Scope.Version && r.Origin == m.Scope.Origin
		}
	}
	return d.Rule == 0 && d.Origin == "operator-npm-registry" && p.Policy.NPMRegistry == "https://registry.npmjs.org" && m.Scope.Origin == npmTarballOrigin(m.Scope.Package, m.Scope.Version)
}
func hexSRI(s string) string {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 {
		return ""
	}
	return "sha256-" + base64.StdEncoding.EncodeToString(b)
}
func policyAssurance(a integrity.AssuranceLevel) string {
	switch a {
	case integrity.AssuranceLockfile:
		return "lockfile-consistent"
	case integrity.AssuranceIndependent:
		return "independently-anchored"
	}
	return "unknown"
}
func materialKey(m PolicyMaterial) string {
	if m.Scope.Category == "integrity" {
		b, _ := json.Marshal([]any{"integrity", m.Record, m.Difference})
		return string(b)
	}
	b, _ := json.Marshal([]any{m.Scope.Category, m.Observation, m.Advisory, m.Affected})
	return string(b)
}
func EvaluatePolicy(plan Plan, records []Record, inv projectinventory.PublicInventory, advisories []AdvisoryDecision, materials []PolicyMaterial, limited bool, now time.Time) (PolicyEvaluation, error) {
	if now.IsZero() || ValidatePolicyMaterials(plan, inv, records, advisories, materials) != nil {
		return PolicyEvaluation{}, ErrPolicyMaterial
	}
	out := PolicyEvaluation{Source: "explicit", Provided: plan.Provided, Checks: plan.Checks, FailOn: plan.FailOn, Manager: plan.Manager, Privacy: plan.Privacy, MinimumAssurance: plan.Policy.MinimumAssurance, MaxExceptionDays: exceptionDays(plan.Policy), MaterialLimited: limited, Findings: []PolicyFinding{}, Exceptions: []ExceptionDisposition{}}
	if plan.Builtin {
		out.Source = "built-in"
	}
	byKey := map[string]PolicyMaterial{}
	observations := map[uint32]string{}
	originals := map[int]string{}
	var project ProjectEvidence
	bytes := 0
	for _, m := range materials {
		if project.Scope == 0 {
			project = m.Project
		} else if project != m.Project {
			return PolicyEvaluation{}, ErrPolicyMaterial
		}
		observation := policyFingerprint("receipt-observation", m.Scope.Class, m.Scope.Package, m.Scope.Version, m.Scope.Origin, m.Scope.Instance, m.SourceSHA256, m.LockSourceSHA256, m.PhysicalTarget, m.DirectoryKind, m.LinkSHA256)
		if old, ok := observations[m.Observation]; ok && old != observation {
			return PolicyEvaluation{}, ErrPolicyMaterial
		}
		observations[m.Observation] = observation
		if m.Advisory != 0 {
			original := policyFingerprint("receipt-original", m.Scope.Advisory, m.OriginalSHA256)
			if old, ok := originals[m.Advisory]; ok && old != original {
				return PolicyEvaluation{}, ErrPolicyMaterial
			}
			originals[m.Advisory] = original
		}
		key := materialKey(m)
		if _, ok := byKey[key]; ok {
			return PolicyEvaluation{}, ErrPolicyMaterial
		}
		byKey[key] = m
		b, _ := json.Marshal(m)
		bytes += len(b)
		if bytes > MaxPolicyMaterialBytes {
			return PolicyEvaluation{}, ErrPolicyMaterial
		}
	}
	for i, x := range plan.Policy.Exceptions {
		a, _ := utcTime(x.ApprovedAt)
		b, _ := utcTime(x.ExpiresAt)
		state := "unmatched"
		if now.Before(a) {
			state = "future"
		} else if !now.Before(b) {
			state = "expired"
		}
		out.Exceptions = append(out.Exceptions, ExceptionDisposition{Ordinal: i + 1, Disposition: state, Findings: []int{}})
	}
	add := func(f PolicyFinding, m PolicyMaterial, ok bool) {
		f.Ordinal = len(out.Findings) + 1
		if ok && !limited {
			acceptance := AcceptanceFingerprint(m)
			if plan.Privacy == "local" {
				f.Tracking = TrackingFingerprint(m)
				f.Acceptance = acceptance
				f.Package = m.Scope.Package
				f.Version = m.Scope.Version
				f.Instance = m.Scope.Instance
				f.Path = m.Scope.Path
				f.Review = localPolicyReview(m)
			}
			for i, x := range plan.Policy.Exceptions {
				a, _ := utcTime(x.ApprovedAt)
				b, _ := utcTime(x.ExpiresAt)
				if !now.Before(a) && now.Before(b) && x.Scope == m.Scope && x.Acceptance == acceptance {
					out.Exceptions[i].Disposition = "applied"
					out.Exceptions[i].Findings = append(out.Exceptions[i].Findings, f.Ordinal)
					if !f.Accepted {
						f.Accepted = true
						f.Exception = i + 1
					}
				}
			}
		}
		bit, _ := categories([]string{f.Category})
		f.Enforced = !f.Accepted && plan.FailOn&bit != 0
		if f.Enforced {
			out.EnforcedUnaccepted++
		}
		out.Findings = append(out.Findings, f)
	}
	if plan.Checks&cli.ArgumentCheckIntegrity != 0 {
		for ri, r := range records {
			for di, d := range r.Assessment.Differences {
				if d.Kind == integrity.DifferenceUnchanged {
					continue
				}
				key := materialKey(PolicyMaterial{Scope: FindingScope{Category: "integrity"}, Record: ri, Difference: di})
				m, ok := byKey[key]
				add(PolicyFinding{Category: "integrity", Record: ri, Difference: di, Decision: -1}, m, ok)
			}
		}
	}
	for i, d := range advisories {
		if !d.EnforcementEligible || d.Candidate || d.Outcome != "match" || !categorySelected(plan, d.Category) {
			continue
		}
		key := materialKey(PolicyMaterial{Scope: FindingScope{Category: d.Category}, Observation: d.Observation, Advisory: d.Advisory, Affected: d.Affected})
		m, ok := byKey[key]
		add(PolicyFinding{Category: d.Category, Record: -1, Difference: -1, Decision: i}, m, ok)
	}
	if limited {
		for i := range out.Exceptions {
			if out.Exceptions[i].Disposition == "unmatched" {
				out.Exceptions[i].Disposition = "material-limited"
			}
		}
	}
	return out, nil
}

// ValidatePolicyEvaluation is the render provenance guard: retain the original
// private parent inputs and clock, and re-evaluate rather than trusting public
// accepted/enforcement fields or relabelled privacy.
func ValidatePolicyEvaluation(p Plan, r []Record, i projectinventory.PublicInventory, a []AdvisoryDecision, m []PolicyMaterial, l bool, t time.Time, v PolicyEvaluation) error {
	want, e := EvaluatePolicy(p, r, i, a, m, l, t)
	if e != nil || !reflect.DeepEqual(want, v) {
		return ErrPolicyMaterial
	}
	return nil
}
