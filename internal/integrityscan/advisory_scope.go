package integrityscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	lockinventory "packtrace/internal/inventory"
	"packtrace/internal/projectinventory"
)

// MaxAdvisoryReadBytes is the unchanged matching ceiling shared by independent
// parent acquisition, original audit and replay, not an additional allowance.
const MaxAdvisoryReadBytes = maxMatchingBytes

// SelectedAdvisoryScope supersedes only the historical declaration/index gaps.
// It means all applicable known records in the admitted selected generation were
// accounted for, NOT upstream completeness, threat absence or publisher trust.
// Public JSON cannot recreate the independently verified private receipt.
type SelectedAdvisoryScope struct {
	Contract      string `json:"contract"`
	Malicious     bool   `json:"malicious"`
	Vulnerability bool   `json:"vulnerability"`
}

// Extra proof work, including failed attempts, never renews the scan budget.
type AdvisoryScopeAttempt struct {
	BytesRead uint64 `json:"bytesRead"`
	Work      int    `json:"work"`
}
type advisoryScopeReceipt struct{ digest [32]byte }
type advisoryIndexKey struct {
	Digest            [32]byte
	Ordinal, Affected uint64
}

func advisoryScopeDigest(plan Plan, inv projectinventory.PublicInventory, info Intelligence, a AdvisoryReport) [32]byte {
	a.scopeReceipt = nil
	raw, _ := json.Marshal(struct {
		Plan         Plan
		Inventory    projectinventory.PublicInventory
		Originals    *projectinventory.Result
		Intelligence Intelligence
		Advisory     AdvisoryReport
	}{plan, inv, inv.OriginalClaims, info, a})
	return sha256.Sum256(raw)
}
func validSelectedAdvisoryScope(plan Plan, inv projectinventory.PublicInventory, info Intelligence, a AdvisoryReport) bool {
	return a.SelectedScope != nil && a.SelectedScope.Contract == "selected-generation-originals-v1" && a.SelectedScope.Malicious && a.SelectedScope.Vulnerability && a.scopeReceipt != nil && a.scopeReceipt.digest == advisoryScopeDigest(plan, inv, info, a)
}

// exactDeclaredScope is deliberately not a resolver. Every declaration in every
// original row must be an exact semver bound to one unambiguous selected lock
// identity. Aliases, ranges, optional absence, peers without locks, and workspace
// resolution abstain. This useful finite subset includes flat exact-pinned npm
// and explicitly admitted Bun projects; installed manifests remain separate rows.
func advisoryDeclarationContext(inv projectinventory.Result, o projectinventory.Observation) bool {
	return inv.Selection.Family == "bun" && o.Class == "locked" && o.Kind == "workspace" && o.Workspace == 1 && o.Location == "" && o.Name == "" && o.Version == "" && o.Fields["name-state"] == "absent" && o.Fields["version-state"] == "absent"
}

func exactDeclaredScope(inv projectinventory.Result, origins map[uint32]AdvisoryDecision) bool {
	locks := map[string][]projectinventory.Observation{}
	for _, o := range inv.Model.Observations {
		if lockedPackage(o.Class, o.Kind) && !advisoryDeclarationContext(inv, o) {
			locks[o.Name] = append(locks[o.Name], o)
		}
	}
	bound := func(name, requirement string) bool {
		if _, err := intel.ParseSemVer(requirement); err != nil {
			return false
		}
		rows := locks[name]
		if len(rows) != 1 || rows[0].Version != requirement {
			return false
		}
		location := "node_modules/" + name
		if inv.Selection.Family == "bun" {
			location = name
		}
		_, admitted := origins[rows[0].ID]
		return admitted && rows[0].Location == location
	}
	for _, o := range inv.Model.Observations {
		if o.Workspace != 1 || o.Status != "complete" {
			return false
		}
		if o.Class == "declared" && (o.Fields["requirement-state"] != "value" || !bound(o.Name, o.Requirement)) {
			return false
		}
		for _, group := range o.Requirements {
			if group.State != lockinventory.FieldValue && group.State != lockinventory.FieldAbsent {
				return false
			}
			for _, entry := range group.Entries {
				if entry.State != lockinventory.FieldValue || !bound(entry.Name, entry.Requirement) {
					return false
				}
			}
		}
	}
	return true
}

func advisoryOriginalRoutable(record intel.SnapshotOriginalEvidence) bool {
	if sha256.Sum256(record.Raw) != record.SHA256 || record.Header.SourceSHA256 != record.SHA256 || record.Identity.SourceSHA256 != record.SHA256 || record.Affected.SourceSHA256 != record.SHA256 || record.Times.SourceSHA256 != record.SHA256 {
		return false
	}
	if record.State != intel.SnapshotOriginalVerified || (record.Header.Schema != intel.OSVHeaderSchemaV1Implicit && record.Header.Schema != intel.OSVHeaderSchemaV1Declared) || record.Affected.State != intel.OSVFieldValue || len(record.Identity.Entries) == 0 || len(record.Identity.Entries) != len(record.Affected.Entries) {
		return false
	}
	for i, identity := range record.Identity.Entries {
		if identity.Index != i || identity.Qualification != intel.OSVNPMIdentityCandidate || identity.Ecosystem.Value != "npm" || !canonicalNPMName(identity.Name.Value) {
			return false
		}
	}
	return true
}

func selectedIndexMatches(name string, e intel.SnapshotNPMEvidence, expected map[advisoryIndexKey]bool) bool {
	hash := sha256.Sum256([]byte("npm\x00" + name))
	if e.Name != name || e.Ecosystem != "npm" || e.IdentityHash != hash || e.BlockIndex != hash[0] || matchingIdentityScopeGap(e) != "" || expected == nil {
		return false
	}
	actual := map[advisoryIndexKey]bool{}
	for _, r := range e.Records {
		if r.State != intel.SnapshotOriginalVerified || len(r.Bindings) == 0 {
			return false
		}
		for _, b := range r.Bindings {
			key := advisoryIndexKey{r.SHA256, b.SourceOrdinal, b.AffectedIndex}
			if b.State != intel.SnapshotBindingEligible || actual[key] || !expected[key] {
				return false
			}
			actual[key] = true
		}
	}
	return reflect.DeepEqual(actual, expected)
}

// AdmitSelectedAdvisoryScope is parent-side admission, never a worker Completed
// flag. It reads every original, reconstructs selected identity/index support,
// independently repeats actual evaluation, and compares all emitted decisions.
// All extra work is charged cumulatively against the original scan's ceilings.
// Failure leaves the historical report unchanged. The same Snapshot must remain
// retained by the caller through output/finalization; admission never reseals it.
func AdmitSelectedAdvisoryScope(ctx context.Context, plan Plan, inv projectinventory.PublicInventory, info Intelligence, a AdvisoryReport, snapshot *intelstore.Snapshot, now time.Time, acquisitionBytes uint64) (out AdvisoryReport) {
	out = a
	if a.SelectedScope != nil || a.ScopeAttempt != nil || acquisitionBytes > maxMatchingBytes-a.Summary.BytesRead {
		return a
	}
	work := a.Summary.Work
	proofBytes := acquisitionBytes
	attempted := acquisitionBytes != 0
	defer func() {
		if attempted {
			out.ScopeAttempt = &AdvisoryScopeAttempt{BytesRead: proofBytes, Work: work - a.Summary.Work}
		}
		if out.SelectedScope != nil {
			out.scopeReceipt = &advisoryScopeReceipt{digest: advisoryScopeDigest(plan, inv, info, out)}
		}
	}()
	if ctx == nil || snapshot == nil || a.SelectedScope != nil || a.ScopeAttempt != nil || !validateAdvisoryReport(plan, inv, info, a) || projectinventory.ValidateOriginalClaims(inv) != nil || !operationalInventoryComplete(&inv) || !qualifiedSource(info) || info.CheckAge != "current" || info.ReconciliationAge != "current" {
		return a
	}
	// Independently compare selected generation/source/freshness against the
	// actual retained pin, not a receipt hash supplied alongside claimed inputs.
	if info.Selection == "previous-fallback" || len(info.Gaps) != 2 {
		return a
	}
	rawID, err := hex.DecodeString(info.ID)
	if err != nil || len(rawID) != 32 {
		return a
	}
	var id intelstore.ID
	copy(id[:], rawID)
	var expectedID *intelstore.ID
	if plan.TrustedSnapshotDigest != "" {
		sum, err := intel.ParseSnapshotDigest(plan.TrustedSnapshotDigest)
		if err != nil || intelstore.ID(sum) != id {
			return a
		}
		expectedID = &id
	}
	observation, err := snapshot.Observe(ctx, now, expectedID)
	if err != nil || !reflect.DeepEqual(SnapshotIntelligence(observation, info.Selection), info) {
		return a
	}
	original := *inv.OriginalClaims
	origins := indexedMatchingOrigins(plan, original)
	selected := map[string]bool{}
	for _, o := range original.Model.Observations {
		// This is a positively original-proven absent identity, not an omitted
		// package. Its declarations are still required by exactDeclaredScope.
		if advisoryDeclarationContext(original, o) {
			continue
		}
		if lockedPackage(o.Class, o.Kind) || o.Class == "installed" {
			if _, ok := origins[o.ID]; !ok {
				return a
			}
			selected[o.Name] = true
		}
	}
	if !exactDeclaredScope(original, origins) || len(selected) > maxMatchingDecisions || a.Summary.BytesRead >= maxMatchingBytes || a.Summary.Work >= maxMatchingDecisions {
		return a
	}
	expected := map[string]map[advisoryIndexKey]bool{}
	for name := range selected {
		expected[name] = map[advisoryIndexKey]bool{}
	}
	attempted = true
	bindings := 0
	consumed, err := snapshot.WalkOriginals(ctx, maxMatchingBytes-a.Summary.BytesRead-proofBytes, func(ordinal uint64, record intel.SnapshotOriginalEvidence) error {
		units := max(1, len(record.Affected.Entries))
		if units > maxMatchingDecisions-work {
			return ErrAdvisory
		}
		work += units
		// Missing/unknown routing may conceal a selected identity: never infer absence.
		if !advisoryOriginalRoutable(record) {
			return ErrAdvisory
		}
		for i, identity := range record.Identity.Entries {
			// Routing is checked for every original. Category/correction/activity
			// qualification is additionally required for every selected identity;
			// unrelated identities cannot silently widen the selected scope.
			if selected[identity.Name.Value] {
				q := qualifyAdvisory(record, i, now)
				if q.Profile == "unknown" || q.Category == "unknown" || q.Activity == "unknown" || len(q.Gaps) != 0 {
					return ErrAdvisory
				}
				if bindings == maxMatchingDecisions {
					return ErrAdvisory
				}
				bindings++
				expected[identity.Name.Value][advisoryIndexKey{record.SHA256, ordinal, uint64(i)}] = true
			}
		}
		return nil
	})
	proofBytes += consumed
	if err != nil || proofBytes > maxMatchingBytes-a.Summary.BytesRead {
		return a
	}
	observed := map[string]bool{}
	inspect := func(name string, e intel.SnapshotNPMEvidence) error {
		if !selected[name] || observed[name] || e.Name != name || matchingIdentityScopeGap(e) != "" {
			return ErrAdvisory
		}
		observed[name] = true
		if !selectedIndexMatches(name, e, expected[name]) {
			return ErrAdvisory
		}
		return nil
	}
	replay := []AdvisoryDecision{}
	summary, err := matchInventoryBudget(ctx, plan, original, snapshot, info, now, func(d AdvisoryDecision) error { replay = append(replay, d); return nil }, nil, nil, a.Summary.BytesRead+proofBytes, work, inspect)
	replayBytes := summary.BytesRead - a.Summary.BytesRead - proofBytes
	replayWork := summary.Work - work
	proofBytes = summary.BytesRead - a.Summary.BytesRead
	work = summary.Work
	if err != nil || replayBytes != a.Summary.BytesRead || replayWork != a.Summary.Work || len(observed) != len(selected) || !reflect.DeepEqual(replay, a.Decisions) || summary.Observations != summary.TotalObservations || summary.InstalledObservations != summary.TotalInstalledObservations {
		return a
	}
	for _, gap := range summary.Gaps {
		if gap != "declared-unassessed" && gap != "index-completeness" {
			return a
		}
	}
	for _, d := range replay {
		// A qualified empty lookup is represented by the historical identity-empty
		// placeholder, not an invented no-match decision. Its absence meaning is only
		// supplied by the separately admitted selected-generation scope above.
		o := original.Model.Observations[d.Observation-1]
		if advisoryDeclarationContext(original, o) {
			if d.Advisory != 0 || len(d.Gaps) != 2 || !hasMatchingGap(d.Gaps, "origin-unqualified") || !hasMatchingGap(d.Gaps, "identity-unqualified") {
				return a
			}
			continue
		}
		empty := len(expected[o.Name]) == 0
		if empty {
			if d.Advisory != 0 || len(d.Gaps) != 1 || d.Gaps[0] != "identity-empty" {
				return a
			}
		} else if !d.FullyEvaluated || d.Candidate || len(d.Gaps) != 0 || d.Outcome == "indeterminate" {
			return a
		}
	}
	a.SelectedScope = &SelectedAdvisoryScope{Contract: "selected-generation-originals-v1", Malicious: true, Vulnerability: true}
	a.Summary.Gaps = []string{}
	a.scopeReceipt = &advisoryScopeReceipt{digest: advisoryScopeDigest(plan, inv, info, a)}
	return a
}
