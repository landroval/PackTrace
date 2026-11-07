package integrityscan

// Policy material is PRIVATE worker-to-supervisor evidence. Never embed these
// types in a public report. The worker supplies facts, not exception decisions.
const MaxPolicyMaterials = 4096
const MaxPolicyMaterialBytes = 8 << 20

type ProjectEvidence struct {
	Scope          uint32 `json:"scope"`
	Manifest       uint32 `json:"manifest"`
	Lock           uint32 `json:"lock"`
	ManifestSHA256 string `json:"manifestSHA256"`
	LockSHA256     string `json:"lockSHA256"`
	Profile        string `json:"profile"`
	LockFile       string `json:"lockFile"`
}

// FindingScope is an exact selector. Empty advisory/file fields mean literal
// absence for that category, never a wildcard. Project is a content fingerprint.
type FindingScope struct {
	Project  string `json:"project"`
	Category string `json:"category"`
	Rule     string `json:"rule"`
	Class    string `json:"class"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	Origin   string `json:"origin"`
	Instance string `json:"instance"`
	Path     string `json:"path"`
	Advisory string `json:"advisory"`
	Change   string `json:"change"`
}

// EvidenceSide distinguishes absence from an observed empty file/directory.
// SHA256 is only a regular-file digest; LinkSHA256 hashes the link object text,
// not the referent. Directory sizes/digests are not content identity.
type EvidenceSide struct {
	State      string `json:"state"`
	Type       string `json:"type"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	LinkSHA256 string `json:"linkSHA256"`
}

type PolicyMaterial struct {
	Project              ProjectEvidence `json:"project"`
	Scope                FindingScope    `json:"scope"`
	Observation          uint32          `json:"observation"`
	Advisory             int             `json:"advisory"`
	Affected             int             `json:"affected"`
	Record               int             `json:"record"`
	Difference           int             `json:"difference"`
	ReferenceEntryID     string          `json:"referenceEntryID"`
	ObservedEntryID      string          `json:"observedEntryID"`
	SourceSHA256         string          `json:"sourceSHA256"`
	LockSourceSHA256     string          `json:"lockSourceSHA256"`
	OriginalSHA256       string          `json:"originalSHA256"`
	Profile              string          `json:"profile"`
	PhysicalTarget       string          `json:"physicalTarget"`
	DirectoryKind        string          `json:"directoryKind"`
	LinkSHA256           string          `json:"linkSHA256"`
	Expected             EvidenceSide    `json:"expected"`
	Observed             EvidenceSide    `json:"observed"`
	ReferenceSRI         string          `json:"referenceSRI"`
	ReferenceObservedSRI string          `json:"referenceObservedSRI"`
	Assurance            string          `json:"assurance"`
	ReferenceContext     string          `json:"referenceContext"`
}

// PolicyEvidenceEmitter returning nil at a material limit retains findings;
// its owner records the explicit limited closure instead of accepting by name.
type PolicyEvidenceEmitter func(PolicyMaterial) error
