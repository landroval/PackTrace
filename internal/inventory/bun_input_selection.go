package inventory

// BunInputPresence is caller-qualified presence in one explicit-root view.
type BunInputPresence uint8

const (
	BunInputPresenceUnknown BunInputPresence = iota
	BunInputPresenceAbsent
	BunInputPresencePresent
)

// BunInputUsability is independent of presence and producer authentication.
type BunInputUsability uint8

const (
	BunInputUsabilityUnqualified BunInputUsability = iota
	BunInputUsabilityUsable
	BunInputUsabilityUnreadable
	BunInputUsabilityUnsafe
	BunInputUsabilityUnsupported
	BunInputUsabilityInvalid
)

// BunInputState retains classifications, not source/native authentication.
type BunInputState struct {
	Presence  BunInputPresence
	Usability BunInputUsability
}

// BunInputCandidate identifies a sole observed slot, not a usable tree.
type BunInputCandidate uint8

const (
	BunInputCandidateNone BunInputCandidate = iota
	BunInputCandidateText
	BunInputCandidateBinary
)

// BunInputSelectionState describes a decision conditional on supplied evidence.
type BunInputSelectionState uint8

const (
	BunInputSelectionUnknown BunInputSelectionState = iota
	BunInputSelectionUsable
	BunInputSelectionUnusable
	BunInputSelectionIndeterminate
	BunInputSelectionAbsent
)

// BunInputDiagnostic is a fixed primary reason, not every source problem.
type BunInputDiagnostic uint8

const (
	BunInputDiagnosticUnknown BunInputDiagnostic = iota
	BunInputDiagnosticNone
	BunInputDiagnosticProfileUnqualified
	BunInputDiagnosticTextPresenceUnknown
	BunInputDiagnosticBinaryPresenceUnknown
	BunInputDiagnosticConflictingInputs
	BunInputDiagnosticUsabilityUnqualified
	BunInputDiagnosticCandidateUnusable
	BunInputDiagnosticLegacyBinaryUnsupported
	BunInputDiagnosticNoRootLock
)

// BunInputSelection retains both scalar inputs. Profile is private caller text.
// No state establishes producer compatibility, safe access or global coverage.
type BunInputSelection struct {
	Profile          string
	ProfileQualified bool
	Text, Binary     BunInputState
	Candidate        BunInputCandidate
	State            BunInputSelectionState
	Diagnostic       BunInputDiagnostic
}

// SelectBunInput validates both layouts before abstention or a unique decision.
// Coexistence is indeterminate: no text/binary precedence has been qualified.
// Binary never becomes supported from a caller's usability classification.
func SelectBunInput(profile string, text, binary BunInputState) (BunInputSelection, error) {
	if !validBunInputState(text) || !validBunInputState(binary) {
		return BunInputSelection{}, &ParseError{Code: "invalid-shape"}
	}
	result := BunInputSelection{
		Profile: profile, Text: text, Binary: binary,
		State:      BunInputSelectionIndeterminate,
		Diagnostic: BunInputDiagnosticProfileUnqualified,
	}
	switch profile {
	case "bun@1.3.2", "bun@1.4.2":
		result.ProfileQualified = true
	default:
		return result, nil
	}
	if text.Presence == BunInputPresenceUnknown {
		result.Diagnostic = BunInputDiagnosticTextPresenceUnknown
		return result, nil
	}
	if binary.Presence == BunInputPresenceUnknown {
		result.Diagnostic = BunInputDiagnosticBinaryPresenceUnknown
		return result, nil
	}
	if text.Presence == BunInputPresenceAbsent && binary.Presence == BunInputPresenceAbsent {
		result.State = BunInputSelectionAbsent
		result.Diagnostic = BunInputDiagnosticNoRootLock
		return result, nil
	}
	if text.Presence == BunInputPresencePresent && binary.Presence == BunInputPresencePresent {
		result.Diagnostic = BunInputDiagnosticConflictingInputs
		return result, nil
	}
	if text.Presence == BunInputPresenceAbsent {
		result.Candidate = BunInputCandidateBinary
		result.State = BunInputSelectionUnusable
		result.Diagnostic = BunInputDiagnosticLegacyBinaryUnsupported
		return result, nil
	}
	result.Candidate = BunInputCandidateText
	switch text.Usability {
	case BunInputUsabilityUnqualified:
		result.Diagnostic = BunInputDiagnosticUsabilityUnqualified
	case BunInputUsabilityUsable:
		result.State = BunInputSelectionUsable
		result.Diagnostic = BunInputDiagnosticNone
	default:
		result.State = BunInputSelectionUnusable
		result.Diagnostic = BunInputDiagnosticCandidateUnusable
	}
	return result, nil
}

func validBunInputState(input BunInputState) bool {
	if input.Usability > BunInputUsabilityInvalid {
		return false
	}
	switch input.Presence {
	case BunInputPresenceUnknown:
		return input.Usability == BunInputUsabilityUnqualified ||
			input.Usability == BunInputUsabilityUnreadable ||
			input.Usability == BunInputUsabilityUnsafe
	case BunInputPresenceAbsent:
		return input.Usability == BunInputUsabilityUnqualified
	case BunInputPresencePresent:
		return true
	default:
		return false
	}
}
