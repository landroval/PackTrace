package integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"sort"
	"strings"
)

type BaselineKind uint8

const (
	BaselineUnknown BaselineKind = iota
	BaselineLockfile
	BaselineController
)

type AssuranceLevel uint8

const (
	AssuranceUnknown AssuranceLevel = iota
	AssuranceLockfile
	AssuranceIndependent
)

// BindingClaim is a caller assertion, NOT a source-authentication result.
type BindingClaim struct{ PackageID, Version, Origin, ExpectedSRI, SourceLocator, SourceHash, EvidenceID string }

// QualificationEvidence is a declared caller precondition, never proof of native acquisition.
type QualificationEvidence struct{ ControllerEvidenceID, Basis string }
type BindingInput struct {
	InstanceID           string
	Lockfile, Controller BindingClaim
	SelectedBaseline     BaselineKind
	SelectionReason      string
	RequiredAssurance    AssuranceLevel
	Qualification        QualificationEvidence
}

// ReferenceBinding cannot be made usable by JSON decoding or constructing exported fields.
type ReferenceBinding struct {
	instanceID                       string
	assurance                        AssuranceLevel
	fingerprint                      [32]byte
	selectedAlgorithm, selectedToken string
	expectedDigests                  [][]byte
	usable                           bool
}

func (b ReferenceBinding) InstanceID() string        { return b.instanceID }
func (b ReferenceBinding) Assurance() AssuranceLevel { return b.assurance }
func (b ReferenceBinding) Usable() bool              { return b.usable }
func (b ReferenceBinding) Algorithm() string         { return b.selectedAlgorithm }
func (b ReferenceBinding) ExpectedDigests() [][]byte {
	out := make([][]byte, len(b.expectedDigests))
	for i, d := range b.expectedDigests {
		out[i] = bytes.Clone(d)
	}
	return out
}

// ResolveReferenceBinding checks internal consistency, not authenticity or benignness.
// Conflict or missing required claims prevents any dependent reference comparison.
func ResolveReferenceBinding(in BindingInput) (ReferenceBinding, []Gap) {
	invalid := func() (ReferenceBinding, []Gap) {
		return ReferenceBinding{}, []Gap{{Code: GapBinding, InstanceID: in.InstanceID}}
	}
	if in.InstanceID == "" || in.Qualification.ControllerEvidenceID == "" || in.Qualification.Basis == "" || in.SelectionReason == "" || (in.SelectedBaseline != BaselineLockfile && in.SelectedBaseline != BaselineController) || (in.RequiredAssurance != AssuranceLockfile && in.RequiredAssurance != AssuranceIndependent) {
		return invalid()
	}
	lock, ok := validatedClaim(in.Lockfile)
	if !ok {
		return invalid()
	}
	selected := lock
	assurance := AssuranceLockfile
	if in.Controller != (BindingClaim{}) || in.SelectedBaseline == BaselineController || in.RequiredAssurance == AssuranceIndependent {
		ctrl, valid := validatedClaim(in.Controller)
		if !valid || in.Lockfile.PackageID != in.Controller.PackageID || in.Lockfile.Version != in.Controller.Version || in.Lockfile.Origin != in.Controller.Origin || !sameTokens(lock, ctrl) || (in.Lockfile.SourceLocator == in.Controller.SourceLocator && in.Lockfile.SourceHash != in.Controller.SourceHash) {
			return invalid()
		}
		if in.SelectedBaseline == BaselineController || in.RequiredAssurance == AssuranceIndependent {
			if in.Controller.EvidenceID == in.Lockfile.EvidenceID || in.Controller.SourceLocator == in.Lockfile.SourceLocator {
				return invalid()
			}
			assurance = AssuranceIndependent
		}
		if in.SelectedBaseline == BaselineController {
			selected = ctrl
		}
	}
	if in.RequiredAssurance == AssuranceIndependent && assurance != AssuranceIndependent {
		return invalid()
	}
	b := ReferenceBinding{instanceID: in.InstanceID, assurance: assurance, fingerprint: bindingFingerprint(in), selectedAlgorithm: selected.algorithm, selectedToken: selected.strongest, usable: true}
	for _, d := range selected.digests {
		b.expectedDigests = append(b.expectedDigests, bytes.Clone(d))
	}
	return b, nil
}

// Length framing preserves exact supplied claims, including non-selected tokens,
// provenance and caller qualification. It establishes coherence, not authority.
func bindingFingerprint(in BindingInput) [32]byte {
	h := sha256.New()
	h.Write([]byte{byte(in.SelectedBaseline), byte(in.RequiredAssurance)})
	fields := []string{in.InstanceID, in.SelectionReason, in.Qualification.ControllerEvidenceID, in.Qualification.Basis}
	for _, c := range []BindingClaim{in.Lockfile, in.Controller} {
		fields = append(fields, c.PackageID, c.Version, c.Origin, c.ExpectedSRI, c.SourceLocator, c.SourceHash, c.EvidenceID)
	}
	for _, s := range fields {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(s)))
		h.Write(size[:])
		io.WriteString(h, s)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type claimDigests struct {
	algorithm, strongest string
	digests              [][]byte
	tokens               []string
}

// validatedClaim rejects unsupported SRI tokens and incomplete source assertions.
func validatedClaim(c BindingClaim) (claimDigests, bool) {
	if c.PackageID == "" || c.Version == "" || c.Origin == "" || c.SourceLocator == "" || c.EvidenceID == "" {
		return claimDigests{}, false
	}
	if _, _, _, ok := parseDigestToken(c.SourceHash); !ok {
		return claimDigests{}, false
	}
	if len(c.ExpectedSRI) > 2048 {
		return claimDigests{}, false
	}
	tokens := strings.FieldsFunc(c.ExpectedSRI, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' })
	if len(tokens) == 0 || len(tokens) > 16 {
		return claimDigests{}, false
	}
	var result claimDigests
	rank := 0
	for _, token := range tokens {
		name, d, _, ok := parseDigestToken(token)
		if !ok {
			return claimDigests{}, false
		}
		result.tokens = append(result.tokens, token)
		strength := 1
		if name == "sha384" {
			strength = 2
		}
		if name == "sha512" {
			strength = 3
		}
		if strength > rank {
			rank = strength
			result.algorithm = name
			result.strongest = token
			result.digests = nil
		}
		if strength == rank {
			result.digests = append(result.digests, d)
		}
	}
	sort.Strings(result.tokens)
	sort.Slice(result.digests, func(i, j int) bool { return bytes.Compare(result.digests[i], result.digests[j]) < 0 })
	result.strongest = result.algorithm + "-" + base64.StdEncoding.EncodeToString(result.digests[0])
	return result, true
}
func sameTokens(a, b claimDigests) bool {
	if len(a.tokens) != len(b.tokens) {
		return false
	}
	for i := range a.tokens {
		if a.tokens[i] != b.tokens[i] {
			return false
		}
	}
	return true
}
