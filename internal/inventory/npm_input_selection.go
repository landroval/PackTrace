package inventory

// NPMInputPresence records caller-qualified presence in the explicit-root view.
type NPMInputPresence uint8

const (
	NPMInputPresenceUnknown NPMInputPresence = iota
	NPMInputPresenceAbsent
	NPMInputPresencePresent
)

// NPMInputUsability is independent of presence; access failures do not prove it.
type NPMInputUsability uint8

const (
	NPMInputUsabilityUnqualified NPMInputUsability = iota
	NPMInputUsabilityUsable
	NPMInputUsabilityUnreadable
	NPMInputUsabilityUnsafe
	NPMInputUsabilityUnsupported
	NPMInputUsabilityInvalid
)

// NPMInputState contains classifications, not source/native authentication.
type NPMInputState struct {
	Presence  NPMInputPresence
	Usability NPMInputUsability
}

// NPMInputCandidate identifies a governing slot, not a usable dependency tree.
type NPMInputCandidate uint8

const (
	NPMInputCandidateNone NPMInputCandidate = iota
	NPMInputCandidateShrinkwrap
	NPMInputCandidatePackageLock
)

type NPMInputSelectionState uint8

const (
	NPMInputSelectionUnknown NPMInputSelectionState = iota
	NPMInputSelectionUsable
	NPMInputSelectionUnusable
	NPMInputSelectionIndeterminate
	NPMInputSelectionAbsent
)

// NPMInputDiagnostic is a fixed primary decision reason, not every source error.
type NPMInputDiagnostic uint8

const (
	NPMInputDiagnosticUnknown NPMInputDiagnostic = iota
	NPMInputDiagnosticNone
	NPMInputDiagnosticProfileUnqualified
	NPMInputDiagnosticShrinkwrapPresenceUnknown
	NPMInputDiagnosticPackageLockPresenceUnknown
	NPMInputDiagnosticUsabilityUnqualified
	NPMInputDiagnosticCandidateUnusable
	NPMInputDiagnosticNoRootLock
)

// NPMInputSelection retains both scalar records even if one does not govern.
// Profile is internal untrusted/private text, not public diagnostic material.
// No state proves producer compatibility, safe access, findings or global coverage.
type NPMInputSelection struct {
	Profile                 string
	ProfileQualified        bool
	Shrinkwrap, PackageLock NPMInputState
	Candidate               NPMInputCandidate
	State                   NPMInputSelectionState
	Diagnostic              NPMInputDiagnostic
}

// SelectNPMInput requires caller-qualified pairs from one explicit-root view.
// Both layouts are checked before abstention or precedence; fatal errors are
// whole-zero. The caller retains manifest/hidden/installed/source evidence.
func SelectNPMInput(profile string, shrinkwrap, packageLock NPMInputState) (NPMInputSelection, error) {
	if !validNPMInputState(shrinkwrap) || !validNPMInputState(packageLock) {
		return NPMInputSelection{}, &ParseError{Code: "invalid-shape"}
	}
	result := NPMInputSelection{
		Profile: profile, Shrinkwrap: shrinkwrap, PackageLock: packageLock,
		State:      NPMInputSelectionIndeterminate,
		Diagnostic: NPMInputDiagnosticProfileUnqualified,
	}
	switch profile {
	case "npm@8.19.4", "npm@10.9.4", "npm@11.6.2":
		result.ProfileQualified = true
	default:
		return result, nil
	}
	usability := shrinkwrap.Usability
	switch shrinkwrap.Presence {
	case NPMInputPresenceUnknown:
		result.Diagnostic = NPMInputDiagnosticShrinkwrapPresenceUnknown
		return result, nil
	case NPMInputPresencePresent:
		result.Candidate = NPMInputCandidateShrinkwrap
	case NPMInputPresenceAbsent:
		switch packageLock.Presence {
		case NPMInputPresenceUnknown:
			result.Diagnostic = NPMInputDiagnosticPackageLockPresenceUnknown
			return result, nil
		case NPMInputPresenceAbsent:
			result.State = NPMInputSelectionAbsent
			result.Diagnostic = NPMInputDiagnosticNoRootLock
			return result, nil
		case NPMInputPresencePresent:
			result.Candidate = NPMInputCandidatePackageLock
			usability = packageLock.Usability
		}
	}
	switch usability {
	case NPMInputUsabilityUnqualified:
		result.Diagnostic = NPMInputDiagnosticUsabilityUnqualified
	case NPMInputUsabilityUsable:
		result.State = NPMInputSelectionUsable
		result.Diagnostic = NPMInputDiagnosticNone
	default:
		result.State = NPMInputSelectionUnusable
		result.Diagnostic = NPMInputDiagnosticCandidateUnusable
	}
	return result, nil
}

func validNPMInputState(input NPMInputState) bool {
	if input.Usability > NPMInputUsabilityInvalid {
		return false
	}
	switch input.Presence {
	case NPMInputPresenceUnknown:
		return input.Usability == NPMInputUsabilityUnqualified ||
			input.Usability == NPMInputUsabilityUnreadable ||
			input.Usability == NPMInputUsabilityUnsafe
	case NPMInputPresenceAbsent:
		return input.Usability == NPMInputUsabilityUnqualified
	case NPMInputPresencePresent:
		return true
	default:
		return false
	}
}
