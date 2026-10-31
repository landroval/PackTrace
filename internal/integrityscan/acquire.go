package integrityscan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"packtrace/internal/cli"
	"packtrace/internal/integrity"
	"packtrace/internal/inventory"
	"packtrace/internal/nativefs"
)

var ErrAcquisition = errors.New("scan: acquisition-unavailable")

type PolicyObservation struct {
	Policy     Policy `json:"policy"`
	SourceHash string `json:"sourceHash"`
}
type Record struct {
	Index           int                          `json:"index"`
	Lock            integrity.BindingClaim       `json:"lock"`
	Assessment      integrity.InstanceAssessment `json:"assessment"`
	ObservedEntries int                          `json:"observedEntries"`
}
type Summary struct {
	Records           int  `json:"records"`
	ObservedEntries   int  `json:"observedEntries"`
	SnapshotComplete  bool `json:"snapshotComplete"`
	InventoryComplete bool `json:"inventoryComplete"`
	AuthorityComplete bool `json:"authorityComplete"`
	Qualified         bool `json:"qualified"`
}

// Lexical rejection is an additional early refusal, never physical separation
// proof. Actual controller reads also require a native external capability.
func containedName(root, name string) bool {
	rel, e := filepath.Rel(root, name)
	return e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func AcquirePolicy(ctx context.Context, name, target string) (PolicyObservation, error) {
	if ctx.Err() != nil || !filepath.IsAbs(name) || !filepath.IsAbs(target) || containedName(target, name) {
		return PolicyObservation{}, ErrPolicy
	}
	investigated, e := nativefs.OpenRoot(ctx, target)
	if e != nil {
		return PolicyObservation{}, ErrAcquisition
	}
	defer investigated.Close()
	root, e := investigated.OpenExternalRoot(ctx, filepath.Dir(name))
	if e != nil {
		return PolicyObservation{}, ErrPolicy
	}
	defer root.Close()
	data, e := readLease(ctx, root, filepath.Base(name), MaxPolicyBytes)
	if e != nil {
		return PolicyObservation{}, ErrPolicy
	}
	p, e := ParsePolicy(data)
	if e != nil {
		return PolicyObservation{}, e
	}
	return PolicyObservation{p, sourceSRI(data)}, nil
}
func readLease(ctx context.Context, root *nativefs.Root, name string, limit int64) ([]byte, error) {
	file, e := root.OpenInput(ctx, name, limit)
	if e != nil {
		return nil, ErrAcquisition
	}
	data, readErr := readBounded(file, limit)
	stableErr := file.Stable()
	closeErr := file.Close()
	if readErr != nil || stableErr != nil || closeErr != nil {
		return nil, ErrAcquisition
	}
	return data, nil
}

type lockedInputs struct {
	claims   map[string]integrity.BindingClaim
	complete bool
}

func readLocked(ctx context.Context, root *nativefs.Root, snap nativefs.Snapshot, manager string) lockedInputs {
	out := lockedInputs{claims: map[string]integrity.BindingClaim{}}
	present := map[string]nativefs.Entry{}
	for _, entry := range snap.Entries {
		present[entry.Name] = entry
	}
	if strings.HasPrefix(manager, "npm@") {
		name := "package-lock.json"
		if _, ok := present["npm-shrinkwrap.json"]; ok {
			name = "npm-shrinkwrap.json"
		}
		if _, ok := present["bun.lock"]; ok {
			return out
		} // no silent mixed-manager interpretation
		data, e := readLease(ctx, root, name, 64<<20)
		if e != nil {
			return out
		}
		doc, e := inventory.ParseNPMLock(data)
		if e != nil {
			return out
		}
		projection, e := inventory.ProjectNPMLock(doc)
		if e != nil {
			return out
		}
		names, e := inventory.ProjectNPMLockNames(projection)
		if e != nil {
			return out
		}
		for i, r := range projection.Records {
			if r.Location == "" {
				continue
			}
			if !relative(r.Location) || r.Version.State != inventory.FieldValue || r.Resolved.State != inventory.FieldValue || r.Integrity.State != inventory.FieldValue || (r.Link.State != inventory.FieldAbsent && (r.Link.State != inventory.FieldValue || r.Link.Value)) {
				continue
			}
			n := names.Entries[i]
			if n.SelectedName == "" {
				continue
			}
			out.claims[r.Location] = integrity.BindingClaim{PackageID: n.SelectedName, Version: r.Version.Value, Origin: r.Resolved.Value, ExpectedSRI: r.Integrity.Value, SourceLocator: name, SourceHash: sourceSRI(data), EvidenceID: "locked:" + r.Location}
		}
		out.complete = true
		return out
	}
	if _, ok := present["package-lock.json"]; ok {
		return out
	}
	if _, ok := present["npm-shrinkwrap.json"]; ok {
		return out
	}
	data, e := readLease(ctx, root, "bun.lock", 64<<20)
	if e != nil {
		return out
	}
	doc, e := inventory.ParseBunLock(data)
	if e != nil {
		return out
	}
	projection, e := inventory.ProjectBunLock(doc)
	if e != nil {
		return out
	}
	for _, r := range projection.Records {
		if r.Kind != inventory.BunKindNPM || r.Name.State != inventory.FieldValue || r.Resolution.State != inventory.FieldValue || r.Registry.State != inventory.FieldValue || r.Integrity.State != inventory.FieldValue {
			continue
		}
		out.claims[r.Key] = integrity.BindingClaim{PackageID: r.Name.Value, Version: r.Resolution.Value, Origin: r.Registry.Value, ExpectedSRI: r.Integrity.Value, SourceLocator: "bun.lock", SourceHash: sourceSRI(data), EvidenceID: "locked:" + r.Key}
	}
	out.complete = true
	return out
}

func Binding(plan Plan, index int, claim integrity.BindingClaim, policyHash string) integrity.BindingInput {
	return integrity.BindingInput{InstanceID: instanceID(index), Lockfile: claim, SelectedBaseline: integrity.BaselineLockfile, SelectionReason: plan.Policy.Reason, RequiredAssurance: integrity.AssuranceLockfile, Qualification: integrity.QualificationEvidence{ControllerEvidenceID: policyHash, Basis: "native-live-lease; independence-unqualified"}}
}
func instanceID(index int) string { return fmt.Sprintf("instance-%d", index+1) }
func badRecord(index int, claim integrity.BindingClaim, code integrity.GapCode) Record {
	id := instanceID(index)
	return Record{Index: index, Lock: claim, Assessment: integrity.InstanceAssessment{InstanceID: id, Gaps: []integrity.Gap{{Code: code, InstanceID: id}}}}
}
func claimMatches(r Reference, c integrity.BindingClaim) bool {
	return c.PackageID == r.Name && c.Version == r.Version && c.Origin == r.Origin && sameSRI(c.ExpectedSRI, r.ExpectedSRI)
}
func sameSRI(a, b string) bool {
	aa, bb := strings.Fields(a), strings.Fields(b)
	sort.Strings(aa)
	sort.Strings(bb)
	return strings.Join(aa, " ") == strings.Join(bb, " ")
}

// Acquire is called only in the concrete native worker, after PrepareProcess.
// References stream sequentially, without extraction or target-code execution.
func Acquire(ctx context.Context, target, prepared, policyHash string, plan Plan, emit func(Record) error) (Summary, error) {
	summary := Summary{}
	if ctx.Err() != nil {
		return summary, ErrAcquisition
	}
	if ValidatePolicy(plan.Policy) != nil || plan.Manager != plan.Policy.Manager || !filepath.IsAbs(target) || !filepath.IsAbs(prepared) || containedName(target, prepared) {
		return summary, ErrPolicy
	}
	root, e := nativefs.OpenRoot(ctx, target)
	if e != nil {
		return summary, ErrAcquisition
	}
	defer root.Close()
	// Reject a target-backed reference directory BEFORE discovery/comparison.
	refs, e := root.OpenExternalRoot(ctx, prepared)
	if e != nil {
		return summary, ErrAcquisition
	}
	defer refs.Close()
	if !relative(plan.PolicyFile) || strings.Contains(plan.PolicyFile, "/") {
		return summary, ErrPolicy
	}
	policyData, e := readLease(ctx, refs, plan.PolicyFile, MaxPolicyBytes)
	if e != nil || sourceSRI(policyData) != policyHash {
		return summary, ErrPolicy
	}
	policy, e := ParsePolicy(policyData)
	if e != nil || !reflect.DeepEqual(policy, plan.Policy) {
		return summary, ErrPolicy
	}
	// The hash checks continuity only; the native external lease above supplies
	// the authority exclusion. A hash or child assertion alone cannot admit it.
	// Discovery is metadata-only. Content is acquired only through a necessary
	// lock-file selection or a captured package subroot, never root-then-filter.
	metadata, e := root.Metadata(ctx, nativefs.Limits{Entries: 100000, Depth: 64})
	if e != nil {
		metadata.Complete = false
	}
	locked := readLocked(ctx, root, metadata, plan.Manager)
	summary.SnapshotComplete = metadata.Complete
	summary.InventoryComplete = locked.complete && metadata.Complete
	// Native campaign qualification and independent archive assurance remain
	// unproved. Descriptor separation is necessary, not sufficient for either.
	summary.AuthorityComplete = false
	summary.Qualified = false
	var reread int64 = 7 << 30
	var snapshotRemaining int64 = 8 << 30
	entriesRemaining := 100000
	referenceRemaining, expandedRemaining := int64(16<<30), int64(8<<30)
	mapped := map[string]bool{}
	for _, r := range plan.Policy.References {
		mapped[r.Location] = true
	}
	for name := range locked.claims {
		if !mapped[name] && strings.HasPrefix(plan.Manager, "npm@") {
			summary.InventoryComplete = false
		}
	}
	for _, entry := range metadata.Entries {
		if entry.Kind == nativefs.KindDirectory && packageLocation(entry.Name) && !mapped[entry.Name] {
			summary.InventoryComplete = false
		}
	}
	if plan.Checks&cli.ArgumentCheckIntegrity == 0 {
		return summary, nil
	}
	for i, r := range plan.Policy.References {
		if ctx.Err() != nil {
			return summary, ErrAcquisition
		}
		claim := locked.claims[r.LockKey]
		record := badRecord(i, claim, integrity.GapBinding)
		if plan.Policy.MinimumAssurance == "independently-anchored" {
			record = badRecord(i, claim, integrity.GapBinding)
		} else if claimMatches(r, claim) {
			binding, gaps := integrity.ResolveReferenceBinding(Binding(plan, i, claim, policyHash))
			if len(gaps) == 0 && referenceRemaining > 0 && expandedRemaining > 0 {
				file, openErr := refs.OpenRegular(ctx, r.Archive, min(512<<20, referenceRemaining))
				if openErr == nil {
					catalog, archiveErr := integrity.InspectReferenceArchive(ctx, binding, file, integrity.Limits{ReferenceReadBytes: referenceRemaining, AggregateExpandedBytes: expandedRemaining})
					referenceRemaining -= catalog.CompressedRead
					expandedRemaining -= catalog.ExpandedRead
					stableErr := file.Stable()
					closeErr := file.Close()
					record = badRecord(i, claim, integrity.GapReference)
					if archiveErr == nil && stableErr == nil && closeErr == nil && referenceRemaining >= 0 && expandedRemaining >= 0 {
						installed := integrity.InstalledSnapshot{}
						count := 0
						packageRoot, openErr := root.OpenSubroot(ctx, r.Location)
						if openErr == nil && snapshotRemaining > 0 && entriesRemaining > 1 {
							snap, snapErr := packageRoot.SnapshotPruned(ctx, nativefs.Limits{FileBytes: 256 << 20, TotalBytes: snapshotRemaining, Entries: entriesRemaining - 1, Depth: 64}, func(entry nativefs.Entry) bool {
								// Only a captured directory can be a nested physical owner;
								// regular files at package-shaped paths remain content.
								return entry.Kind == nativefs.KindDirectory && packageLocation(r.Location+"/"+entry.Name)
							})
							snapshotRemaining -= snap.ReadBytes
							if snapErr != nil {
								snap.Complete = false
							}
							if !metadata.Complete {
								snap.Complete = false
								snap.Enumerated = false
							}
							for j := range snap.Entries {
								snap.Entries[j].Name = r.Location + "/" + snap.Entries[j].Name
							}
							snap.Entries = append(snap.Entries, nativefs.Entry{Name: r.Location, Kind: nativefs.KindDirectory, Status: nativefs.StatusComplete})
							entriesRemaining -= len(snap.Entries)
							summary.ObservedEntries += len(snap.Entries)
							summary.SnapshotComplete = summary.SnapshotComplete && snap.Complete
							installed, count = installedSnapshot(ctx, packageRoot, snap, plan, i, &reread)
						} else {
							summary.SnapshotComplete = false
						}
						if packageRoot != nil {
							packageRoot.Close()
						}
						assessment, compareErr := integrity.CompareReferenceCatalog(binding, catalog, installed)
						if compareErr == nil {
							if len(assessment.Contexts) == 0 && r.Context != "none" {
								kind := integrity.ContextPatch
								if r.Context == "generated" {
									kind = integrity.ContextGenerated
								}
								assessment.Contexts = []integrity.ScopedContext{{Kind: kind, InstanceID: instanceID(i), EvidenceID: instanceID(i) + ":scope"}}
							}
							record.Assessment = assessment
							record.ObservedEntries = count
						}
					}
				} else {
					record = badRecord(i, claim, integrity.GapReference)
				}
			}
		}
		if emit(record) != nil {
			return summary, ErrAcquisition
		}
		summary.Records++
	}
	return summary, nil
}

func installedSnapshot(ctx context.Context, root *nativefs.Root, snap nativefs.Snapshot, plan Plan, index int, remaining *int64) (integrity.InstalledSnapshot, int) {
	ref := plan.Policy.References[index]
	id := instanceID(index)
	scope := integrity.InstalledScope{InstanceID: id, OwnerInstanceID: id, EvidenceID: id + ":scope", Enumerated: snap.Enumerated, OwnershipKnown: true, Status: integrity.ObservationComplete}
	if ref.Context == "patch" {
		scope.Context = integrity.ContextPatch
	}
	if ref.Context == "generated" {
		scope.Context = integrity.ContextGenerated
	}
	result := integrity.InstalledSnapshot{Scopes: []integrity.InstalledScope{scope}}
	prefix := ref.Location + "/"
	physicalDirectories := map[string]bool{}
	for _, entry := range snap.Entries {
		if entry.Kind == nativefs.KindDirectory && entry.Status == nativefs.StatusComplete {
			physicalDirectories[entry.Name] = true
		}
	}
	found := false
	for _, entry := range snap.Entries {
		if entry.Name == ref.Location {
			found = entry.Kind == nativefs.KindDirectory && entry.Status == nativefs.StatusComplete
			continue
		}
		if !strings.HasPrefix(entry.Name, prefix) {
			continue
		}
		name := strings.TrimPrefix(entry.Name, prefix)
		owner := id
		for j, other := range plan.Policy.References {
			if j != index && physicalDirectories[other.Location] && strings.HasPrefix(other.Location, prefix) && (entry.Name == other.Location || strings.HasPrefix(entry.Name, other.Location+"/")) {
				owner = instanceID(j)
			}
		}
		if owner != id {
			continue
		} // explicit negative scope below, never silently covered
		o := integrity.InstalledEntry{EvidenceID: id + ":observed:" + strconv.Itoa(len(result.Entries)+1), InstanceID: id, OwnerInstanceID: id, Name: name, LinkTarget: entry.LinkTarget, Size: entry.Size, SHA256: entry.SHA256, Type: integrity.EntryType(entry.Kind), Status: integrity.ObservationStatus(entry.Status)}
		if entry.Kind == nativefs.KindRegular && entry.Status == nativefs.StatusComplete {
			// Reopen the exact relative name through the pinned root and require a
			// bounded stable lease. A changed snapshot hash invalidates this entry.
			if entry.Size < 0 || entry.Size >= *remaining {
				o.Status = integrity.ObservationUnreadable
			} else {
				limit := min(int64(256<<20), *remaining-1)
				file, e := root.OpenRegular(ctx, name, limit)
				if e != nil {
					o.Status = integrity.ObservationUnreadable
				} else {
					hash := sha256.New()
					n, readErr := io.Copy(hash, io.LimitReader(file, limit+1))
					*remaining -= n
					stableErr := file.Stable()
					closeErr := file.Close()
					if readErr != nil || n > limit || stableErr != nil || closeErr != nil || n != entry.Size || !equalHash(hash.Sum(nil), entry.SHA256) {
						o.Status = integrity.ObservationUnstable
					}
				}
			}
		}
		result.Entries = append(result.Entries, o)
	}
	if !found || !snap.Enumerated {
		// Incomplete enumeration grants no absence/addition scope. Content
		// failures are separately negative entries: they block their prefix,
		// without erasing drift in other physically enumerated entries.
		result.Scopes = nil
	}
	for j, other := range plan.Policy.References {
		if j != index && physicalDirectories[other.Location] && strings.HasPrefix(other.Location, prefix) {
			result.Scopes = append(result.Scopes, integrity.InstalledScope{InstanceID: id, OwnerInstanceID: instanceID(j), Prefix: strings.TrimPrefix(other.Location, prefix), EvidenceID: id + ":nested", Enumerated: true, OwnershipKnown: true, Status: integrity.ObservationComplete})
		}
	}
	for _, entry := range snap.Entries {
		if entry.Kind == nativefs.KindDirectory && strings.HasPrefix(entry.Name, prefix) && packageLocation(entry.Name) && !mappedLocation(plan, entry.Name) {
			result.Scopes = append(result.Scopes, integrity.InstalledScope{InstanceID: id, Prefix: strings.TrimPrefix(entry.Name, prefix), EvidenceID: id + ":unmapped", Status: integrity.ObservationUnknown})
		}
	}
	return result, len(result.Entries)
}
func equalHash(data []byte, sum [32]byte) bool {
	return len(data) == 32 && string(data) == string(sum[:])
}
func mappedLocation(plan Plan, name string) bool {
	for _, r := range plan.Policy.References {
		if r.Location == name {
			return true
		}
	}
	return false
}
func packageLocation(name string) bool {
	parts := strings.Split(name, "/")
	for i := 0; i < len(parts); i++ {
		if parts[i] != "node_modules" || i+1 >= len(parts) {
			continue
		}
		i++
		if strings.HasPrefix(parts[i], "@") {
			i++
			if i >= len(parts) {
				return false
			}
		}
		if i == len(parts)-1 && parts[i] != ".bin" {
			return true
		}
	}
	return false
}
