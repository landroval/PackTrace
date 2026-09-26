package inventory

// RequirementOutcome describes decoded text/presence, not dependency semantics.
type RequirementOutcome string

const (
	RequirementEqual         RequirementOutcome = "equal"
	RequirementManifestOnly  RequirementOutcome = "manifest-only"
	RequirementLockOnly      RequirementOutcome = "lock-only"
	RequirementTextChanged   RequirementOutcome = "text-changed"
	RequirementIndeterminate RequirementOutcome = "indeterminate"
)

// RequirementComparison keeps declared and locked evidence on distinct sides.
type RequirementComparison struct {
	Name             string
	Manifest, Locked LockField[string]
	Outcome          RequirementOutcome
}

// RootGroupComparison preserves source states even when comparison is incomplete.
type RootGroupComparison struct {
	Name                     string
	ManifestState, LockState FieldState
	Complete                 bool
	Entries                  []RequirementComparison
}

// RootComparison concerns only literal root requirements, not scan coverage or safety.
// Source locators use each side's digest, group/name, and lock location "".
type RootComparison struct {
	ManifestSHA256, LockSHA256 [32]byte
	RootPresent, Complete      bool
	Groups                     []RootGroupComparison
}

// CompareRootRequirements requires unchanged successful projections explicitly
// paired by the caller, without concurrent mutation. It cannot authenticate the
// pairing/digests or revalidate forged projections. Complete is not scan coverage.
func CompareRootRequirements(manifest ManifestProjection, lock NPMLockProjection) (RootComparison, error) {
	if err := checkComparisonGroups(manifest.Groups, maxManifestDeclarations); err != nil {
		return RootComparison{}, err
	}
	if lock.Records == nil {
		return RootComparison{}, &ParseError{Code: "invalid-shape"}
	}
	result := RootComparison{ManifestSHA256: manifest.SourceSHA256, LockSHA256: lock.SourceSHA256}
	if len(lock.Records) == 0 || lock.Records[0].Location != "" {
		return result, nil
	}
	locked := lock.Records[0].Requirements
	if err := checkComparisonGroups(locked, maxLockedRequirements); err != nil {
		return RootComparison{}, err
	}
	result.RootPresent, result.Complete = true, true
	result.Groups = make([]RootGroupComparison, len(manifest.Groups))
	for index, left := range manifest.Groups {
		right := locked[index]
		group := &result.Groups[index]
		*group = RootGroupComparison{Name: left.Name, ManifestState: left.State, LockState: right.State}
		if !comparableState(left.State) || !comparableState(right.State) {
			result.Complete = false
			continue
		}
		group.Complete = true
		a, b := left.Entries, right.Entries
		group.Entries = make([]RequirementComparison, 0, len(a)+len(b))
		for i, j := 0, 0; i < len(a) || j < len(b); {
			var name string
			if j == len(b) || (i < len(a) && a[i].Name < b[j].Name) {
				name = a[i].Name
			} else {
				name = b[j].Name
			}
			row := RequirementComparison{Name: name}
			if i < len(a) && a[i].Name == name {
				row.Manifest = LockField[string]{State: a[i].State, Value: a[i].Requirement}
				i++
			}
			if j < len(b) && b[j].Name == name {
				row.Locked = LockField[string]{State: b[j].State, Value: b[j].Requirement}
				j++
			}
			switch {
			case !comparableState(row.Manifest.State) || !comparableState(row.Locked.State):
				row.Outcome = RequirementIndeterminate
				group.Complete, result.Complete = false, false
			case row.Manifest.State == FieldAbsent:
				row.Outcome = RequirementLockOnly
			case row.Locked.State == FieldAbsent:
				row.Outcome = RequirementManifestOnly
			case row.Manifest.Value == row.Locked.Value:
				row.Outcome = RequirementEqual
			default:
				row.Outcome = RequirementTextChanged
			}
			group.Entries = append(group.Entries, row)
		}
	}
	return result, nil
}

func checkComparisonGroups(groups []DependencyGroup, remaining int) error {
	names := [...]string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}
	if len(groups) != len(names) {
		return &ParseError{Code: "invalid-shape"}
	}
	for i, group := range groups {
		if group.Name != names[i] {
			return &ParseError{Code: "invalid-shape"}
		}
		if len(group.Entries) > remaining {
			return &ParseError{Code: "limit-exceeded"}
		}
		remaining -= len(group.Entries)
	}
	return nil
}

func comparableState(state FieldState) bool {
	return state == FieldAbsent || state == FieldValue
}
