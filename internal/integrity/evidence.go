package integrity

import (
	"errors"
	"io"
)

type Limits struct {
	CompressedBytes, ExpandedBytes, AggregateExpandedBytes, FileBytes, ReferenceReadBytes, TotalNameBytes, NameBytes int64
	Entries, PathDepth                                                                                               int
}

var errIntegrityLimits = errors.New("invalid integrity limits")

// Zero selects the ceiling; positive values may only lower it.
func normalizedLimits(l Limits) (Limits, error) {
	values := []struct {
		value *int64
		max   int64
	}{
		{&l.CompressedBytes, 512 << 20}, {&l.ExpandedBytes, 2 << 30},
		{&l.AggregateExpandedBytes, 8 << 30}, {&l.FileBytes, 256 << 20},
		{&l.ReferenceReadBytes, 16 << 30}, {&l.TotalNameBytes, 16 << 20}, {&l.NameBytes, 4096},
	}
	for _, v := range values {
		if *v.value < 0 || *v.value > v.max {
			return Limits{}, errIntegrityLimits
		}
		if *v.value == 0 {
			*v.value = v.max
		}
	}
	if l.Entries < 0 || l.Entries > 100000 || l.PathDepth < 0 || l.PathDepth > 128 {
		return Limits{}, errIntegrityLimits
	}
	if l.Entries == 0 {
		l.Entries = 100000
	}
	if l.PathDepth == 0 {
		l.PathDepth = 128
	}
	return l, nil
}

type GapCode string

const (
	GapBinding     GapCode = "binding-unverified"
	GapReference   GapCode = "reference-unusable"
	GapObservation GapCode = "observation-unverified"
	GapOwnership   GapCode = "ownership-ambiguous"
	GapUnsupported GapCode = "unsupported-profile"
	GapTruncated   GapCode = "gap-list-truncated"
)

type Gap struct {
	Code                            GapCode
	InstanceID, EntryID, EvidenceID string
}

type ReferenceEntry struct {
	EntryID, Name string
	Type          EntryType
	Size          int64
	SHA256        [32]byte
}
type EntryType uint8

const (
	EntryUnknown EntryType = iota
	EntryFile
	EntryDirectory
	EntryLink
)

type ReferenceCatalog struct {
	instanceID                   string
	bindingFingerprint           [32]byte
	entries                      []ReferenceEntry // owned catalog; never expose mutable evidence
	CompressedRead, ExpandedRead int64
	verified                     bool
}

func (c ReferenceCatalog) InstanceID() string { return c.instanceID }

type ObservationStatus uint8

const (
	ObservationUnknown ObservationStatus = iota
	ObservationComplete
	ObservationUnreadable
	ObservationUnstable
	ObservationExcluded
)

type InstalledEntry struct {
	EvidenceID, InstanceID, OwnerInstanceID, Name, LinkTarget string
	Type                                                      EntryType
	Size                                                      int64
	SHA256                                                    [32]byte
	Status                                                    ObservationStatus
}
type ContextKind uint8

const (
	ContextUnknown ContextKind = iota
	ContextPatch
	ContextGenerated
)

type InstalledScope struct {
	InstanceID, OwnerInstanceID, EvidenceID, Prefix string
	Enumerated, OwnershipKnown                      bool
	Status                                          ObservationStatus
	Context                                         ContextKind
}
type InstalledSnapshot struct {
	Entries []InstalledEntry
	Scopes  []InstalledScope
}

type DifferenceKind uint8

const (
	DifferenceUnknown DifferenceKind = iota
	DifferenceUnchanged
	DifferenceModified
	DifferenceMissing
	DifferenceAdded
	DifferenceTypeChanged
)

type Difference struct {
	Kind                            DifferenceKind
	InstanceID, EntryID, EvidenceID string
}

// ScopedContext is a caller CLAIM associated with supplied scope evidence, not
// an explanation verified by this pipeline and never permission to erase drift.
type ScopedContext struct {
	Kind                   ContextKind
	InstanceID, EvidenceID string
}

type InstanceAssessment struct {
	InstanceID                 string
	Differences                []Difference
	Contexts                   []ScopedContext
	Gaps                       []Gap
	SuppliedComparisonComplete bool
	Assurance                  AssuranceLevel
}
type AssessmentRequest struct {
	Binding   BindingInput
	Archive   io.Reader
	Installed InstalledSnapshot
}
type Assessment struct {
	Instances                  []InstanceAssessment
	Gaps                       []Gap
	NativeQualification        string
	SuppliedComparisonComplete bool
}
type PortableDifference struct {
	Kind                      DifferenceKind
	Instance, Entry, Evidence int
}
type PortableGap struct {
	Code                      GapCode
	Instance, Entry, Evidence int
}
type PortableContext struct {
	Kind               ContextKind
	Instance, Evidence int
}
type PortableIntegrityResult struct {
	Differences                []PortableDifference
	Contexts                   []PortableContext
	Gaps                       []PortableGap
	NativeQualification        string
	SuppliedComparisonComplete bool
	Experimental               bool
}
