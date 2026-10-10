package intel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"packtrace/internal/jsoninput"
)

type SnapshotOriginalStream struct {
	SHA256 [32]byte
	Reader io.Reader
}

type SnapshotNPMStreams struct {
	Block     io.Reader
	Catalog   io.Reader
	Originals []SnapshotOriginalStream
}

type SnapshotStreamState uint8

const (
	SnapshotStreamUnknown SnapshotStreamState = iota
	SnapshotStreamUnavailable
	SnapshotStreamBytesVerified
	SnapshotStreamStructured
)

type SnapshotDeclarationState uint8

const (
	SnapshotDeclarationUnknown SnapshotDeclarationState = iota
	SnapshotDeclarationGap
	SnapshotDeclarationVerified
)

type SnapshotOriginalState uint8

const (
	SnapshotOriginalUnknown SnapshotOriginalState = iota
	SnapshotOriginalUnavailable
	SnapshotOriginalVerified
)

type SnapshotOriginalProblem uint8

const (
	SnapshotOriginalProblemNone SnapshotOriginalProblem = iota
	SnapshotOriginalProblemMissing
	SnapshotOriginalProblemRead
	SnapshotOriginalProblemResource
	SnapshotOriginalProblemLength
	SnapshotOriginalProblemDigest
	SnapshotOriginalProblemParse
	SnapshotOriginalProblemProjection
)

type SnapshotBindingState uint8

const (
	SnapshotBindingUnknown SnapshotBindingState = iota
	SnapshotBindingGap
	SnapshotBindingEligible
)

type SnapshotBindingProblem uint8

const (
	SnapshotBindingProblemNone SnapshotBindingProblem = iota
	SnapshotBindingProblemOriginal
	SnapshotBindingProblemAffectedIndex
	SnapshotBindingProblemIdentity
)

type SnapshotGapKind uint8

const (
	SnapshotGapIndexCompleteness SnapshotGapKind = iota + 1
	SnapshotGapCorrection
	SnapshotGapActivity
	SnapshotGapSourceQualification
	SnapshotGapRegistryCorrespondence
	SnapshotGapFindingAuthority
	SnapshotGapGlobalStoreQuota
	SnapshotGapPreparationByteIdentity
	SnapshotGapResource
)

type SnapshotAffectedBinding struct {
	SourceOrdinal uint64
	AffectedIndex uint64
	State         SnapshotBindingState
	Problem       SnapshotBindingProblem
}

type SnapshotOriginalEvidence struct {
	SHA256   [32]byte
	Bytes    uint64
	State    SnapshotOriginalState
	Problem  SnapshotOriginalProblem
	Raw      []byte
	Header   OSVHeader
	Affected OSVAffectedProjection
	Identity OSVNPMIdentityProjection
	Times    OSVTimes
	Bindings []SnapshotAffectedBinding
}

type SnapshotNPMEvidence struct {
	ManifestSHA256 [32]byte
	IdentityHash   [32]byte
	Ecosystem      string
	Name           string
	BlockIndex     uint8
	BytesRead      uint64
	BlockState     SnapshotStreamState
	CatalogState   SnapshotStreamState
	Declaration    SnapshotDeclarationState
	Records        []SnapshotOriginalEvidence
	Gaps           []SnapshotGapKind
}

const (
	maxSnapshotReadBytes               uint64 = 8 << 30
	maxSnapshotJSONLLineBytes                 = 1 << 20
	maxSnapshotRetainedBindings               = 4_096
	maxSnapshotSuppliedOriginalStreams        = 1_024
	maxSnapshotUniqueOriginals                = 1_024
	maxSnapshotRetainedOriginalBytes   uint64 = 16 << 20
	maxSnapshotMetadataEntries         uint64 = 2_100_000
	maxSnapshotLogicalBytes            uint64 = 256 << 20
)

type snapshotReadBudget struct{ used uint64 }

func (b *snapshotReadBudget) remaining() uint64      { return maxSnapshotReadBytes - b.used }
func (b *snapshotReadBudget) canStart(n uint64) bool { return n <= b.remaining() }
func (b *snapshotReadBudget) charge(n uint64) bool {
	if n > b.remaining() {
		return false
	}
	b.used += n
	return true
}

type snapshotRetainedBudget struct {
	raw, metadata, logical uint64
}

func (b *snapshotRetainedBudget) metadataEntry() bool {
	if b.metadata == maxSnapshotMetadataEntries {
		return false
	}
	b.metadata++
	return true
}

func (b *snapshotRetainedBudget) logicalBytes(n uint64) bool {
	if n > maxSnapshotLogicalBytes-b.logical {
		return false
	}
	b.logical += n
	return true
}

func (b *snapshotRetainedBudget) reserveOriginal(raw, projection uint64) bool {
	if projection > ^uint64(0)-raw {
		return false
	}
	combined := raw + projection
	if raw > maxSnapshotRetainedOriginalBytes-b.raw || combined > maxSnapshotLogicalBytes-b.logical {
		return false
	}
	b.raw += raw
	b.logical += combined
	return true
}

type snapshotChunkSink func([]byte) string

func readSnapshotStream(ctx context.Context, r io.Reader, expected uint64, budget *snapshotReadBudget, sink snapshotChunkSink) ([32]byte, uint64, bool, string) {
	if r == nil {
		return [32]byte{}, 0, false, "invalid-shape"
	}
	if !budget.canStart(expected) {
		return [32]byte{}, 0, true, ""
	}
	h := sha256.New()
	buf := make([]byte, 32<<10)
	var observed uint64
	for {
		if ctx == nil {
			return [32]byte{}, 0, false, "invalid-shape"
		}
		select {
		case <-ctx.Done():
			return [32]byte{}, 0, false, "canceled"
		default:
		}
		remainingWithDetection := expected + 1 - observed
		request := uint64(len(buf))
		if request > remainingWithDetection {
			request = remainingWithDetection
		}
		if request > budget.remaining() {
			request = budget.remaining()
		}
		if request == 0 {
			return [32]byte{}, observed, true, ""
		}
		n, err := r.Read(buf[:int(request)])
		validCount := n >= 0 && n <= int(request)
		charged := true
		if validCount && n > 0 {
			charged = budget.charge(uint64(n))
			if charged {
				observed += uint64(n)
			}
		}
		// Charge valid returned bytes before cancellation; classify neither
		// returned content nor reader/count errors until this check.
		select {
		case <-ctx.Done():
			return [32]byte{}, observed, false, "canceled"
		default:
		}
		if !validCount {
			return [32]byte{}, observed, false, "read-failed"
		}
		if !charged {
			return [32]byte{}, observed, false, "limit-exceeded"
		}
		if observed > expected {
			return [32]byte{}, observed, false, "length-mismatch"
		}
		if n > 0 {
			_, _ = h.Write(buf[:n])
			if code := sink(buf[:n]); code != "" {
				return [32]byte{}, observed, false, code
			}
		}
		if err != nil {
			if err != io.EOF {
				return [32]byte{}, observed, false, "read-failed"
			}
			if observed != expected {
				return [32]byte{}, observed, false, "length-mismatch"
			}
			var sum [32]byte
			copy(sum[:], h.Sum(nil))
			return sum, observed, false, ""
		}
		if n == 0 {
			return [32]byte{}, observed, false, "read-failed"
		}
	}
}

func readSnapshotOriginalBytes(ctx context.Context, r io.Reader, expected uint64, budget *snapshotReadBudget) ([]byte, bool, string) {
	if expected > maxSnapshotObjectCheckBytes {
		return nil, false, "limit-exceeded"
	}
	data := make([]byte, 0, int(expected))
	_, _, resource, code := readSnapshotStream(ctx, r, expected, budget, func(chunk []byte) string {
		if uint64(len(data))+uint64(len(chunk)) <= expected {
			data = append(data, chunk...)
		}
		return ""
	})
	if code != "" || resource {
		return nil, resource, code
	}
	return data, false, ""
}

type snapshotJSONLState struct {
	line        []byte
	overLine    bool
	profileGap  bool
	rows        uint64
	prefix      [3]byte
	prefixBytes int
}

func snapshotPhysicalRowNext(rows *uint64) string {
	if *rows >= maxSnapshotManifestRecords {
		return "limit-exceeded"
	}
	*rows += 1
	return ""
}

func readSnapshotJSONL(ctx context.Context, r io.Reader, ref SnapshotObjectReference, budget *snapshotReadBudget, visit func([]byte, uint64) string) (SnapshotStreamState, bool, string) {
	s := snapshotJSONLState{line: make([]byte, 0, 512)}
	sum, observed, resource, code := readSnapshotStream(ctx, r, ref.Bytes, budget, func(chunk []byte) string {
		for _, c := range chunk {
			if s.prefixBytes < len(s.prefix) {
				s.prefix[s.prefixBytes] = c
				s.prefixBytes++
				if s.prefixBytes == len(s.prefix) && s.prefix == ([3]byte{0xef, 0xbb, 0xbf}) {
					return "invalid-shape"
				}
			}
			if c == '\r' {
				return "invalid-shape"
			}
			if c != '\n' {
				if !s.overLine {
					if len(s.line) == maxSnapshotJSONLLineBytes {
						s.overLine, s.profileGap = true, true
						s.line = s.line[:0]
					} else {
						s.line = append(s.line, c)
					}
				}
				continue
			}
			if !s.overLine && len(s.line) == 0 {
				return "invalid-shape"
			}
			physical := s.rows
			if code := snapshotPhysicalRowNext(&s.rows); code != "" {
				return code
			}
			if !s.overLine {
				if code := visit(s.line, physical); code != "" {
					return code
				}
			}
			s.line = s.line[:0]
			s.overLine = false
		}
		return ""
	})
	if code != "" {
		return SnapshotStreamUnknown, false, code
	}
	if resource {
		return SnapshotStreamUnavailable, true, ""
	}
	if observed != ref.Bytes {
		return SnapshotStreamUnknown, false, "length-mismatch"
	}
	if len(s.line) != 0 || s.overLine {
		return SnapshotStreamUnknown, false, "invalid-shape"
	}
	if sum != ref.SHA256 {
		return SnapshotStreamUnknown, false, "digest-mismatch"
	}
	if s.rows != ref.Records {
		return SnapshotStreamUnknown, false, "invalid-shape"
	}
	if s.profileGap {
		return SnapshotStreamBytesVerified, true, ""
	}
	return SnapshotStreamStructured, false, ""
}

type snapshotCatalogRow struct {
	ordinal uint64
	digest  [32]byte
	bytes   uint64
}

type snapshotBlockRow struct {
	identity        [32]byte
	ecosystem, name string
	ordinal         uint64
	digest          [32]byte
	bytes, affected uint64
}

type snapshotPendingBinding struct {
	ordinal, affected uint64
	digest            [32]byte
	bytes             uint64
	catalogBound      bool
}

func snapshotExactRow(line []byte, keys ...string) (map[string]json.RawMessage, string) {
	fields, code := jsoninput.Object(line, maxSnapshotJSONLLineBytes)
	if code != "" {
		return nil, code
	}
	if len(fields) != len(keys) {
		return nil, "invalid-shape"
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return nil, "invalid-shape"
		}
	}
	return fields, ""
}

func snapshotRowDigest(fields map[string]json.RawMessage, key string) ([32]byte, string) {
	value := projectOSVString(fields, key)
	if value.State != OSVFieldValue || len(value.Value) != 64 {
		return [32]byte{}, "invalid-shape"
	}
	raw, err := hex.DecodeString(value.Value)
	if err != nil || hex.EncodeToString(raw) != value.Value {
		return [32]byte{}, "invalid-shape"
	}
	var out [32]byte
	copy(out[:], raw)
	return out, ""
}

func snapshotRowVersion(fields map[string]json.RawMessage) string {
	value, code := snapshotManifestUint(fields["v"], 1)
	if code != "" || value != 1 {
		return "invalid-shape"
	}
	return ""
}

func parseSnapshotCatalogRow(line []byte) (snapshotCatalogRow, string) {
	fields, code := snapshotExactRow(line, "v", "sourceOrdinal", "sha256", "bytes")
	if code != "" {
		return snapshotCatalogRow{}, code
	}
	if code = snapshotRowVersion(fields); code != "" {
		return snapshotCatalogRow{}, code
	}
	ordinal, code := snapshotManifestUint(fields["sourceOrdinal"], maxSnapshotManifestRecords-1)
	if code != "" {
		return snapshotCatalogRow{}, code
	}
	digest, code := snapshotRowDigest(fields, "sha256")
	if code != "" {
		return snapshotCatalogRow{}, code
	}
	size, code := snapshotManifestUint(fields["bytes"], maxSnapshotObjectCheckBytes)
	if code != "" {
		return snapshotCatalogRow{}, code
	}
	if size == 0 {
		return snapshotCatalogRow{}, "invalid-shape"
	}
	return snapshotCatalogRow{ordinal: ordinal, digest: digest, bytes: size}, ""
}

func parseSnapshotBlockRow(line []byte) (snapshotBlockRow, string) {
	fields, code := snapshotExactRow(line, "v", "identityHash", "ecosystem", "name", "sourceOrdinal", "originalSHA256", "originalBytes", "affectedIndex")
	if code != "" {
		return snapshotBlockRow{}, code
	}
	if code = snapshotRowVersion(fields); code != "" {
		return snapshotBlockRow{}, code
	}
	identity, code := snapshotRowDigest(fields, "identityHash")
	if code != "" {
		return snapshotBlockRow{}, code
	}
	ecosystem, name := projectOSVString(fields, "ecosystem"), projectOSVString(fields, "name")
	if ecosystem.State != OSVFieldValue || ecosystem.Value != "npm" || name.State != OSVFieldValue || !validOSVNPMName(name.Value) {
		return snapshotBlockRow{}, "invalid-shape"
	}
	ordinal, code := snapshotManifestUint(fields["sourceOrdinal"], maxSnapshotManifestRecords-1)
	if code != "" {
		return snapshotBlockRow{}, code
	}
	digest, code := snapshotRowDigest(fields, "originalSHA256")
	if code != "" {
		return snapshotBlockRow{}, code
	}
	size, code := snapshotManifestUint(fields["originalBytes"], maxSnapshotObjectCheckBytes)
	if code != "" {
		return snapshotBlockRow{}, code
	}
	if size == 0 {
		return snapshotBlockRow{}, "invalid-shape"
	}
	affected, code := snapshotManifestUint(fields["affectedIndex"], ^uint64(0))
	if code != "" {
		return snapshotBlockRow{}, code
	}
	computed := snapshotNPMIdentityHash(name.Value)
	if identity != computed {
		return snapshotBlockRow{}, "invalid-shape"
	}
	return snapshotBlockRow{identity: identity, ecosystem: ecosystem.Value, name: name.Value, ordinal: ordinal, digest: digest, bytes: size, affected: affected}, ""
}

func snapshotNPMIdentityHash(name string) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("npm"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(name))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func compareSnapshotBlockRows(a, b snapshotBlockRow) int {
	if n := bytes.Compare(a.identity[:], b.identity[:]); n != 0 {
		return n
	}
	if n := bytes.Compare([]byte(a.ecosystem), []byte(b.ecosystem)); n != 0 {
		return n
	}
	if n := bytes.Compare([]byte(a.name), []byte(b.name)); n != 0 {
		return n
	}
	if a.ordinal < b.ordinal {
		return -1
	}
	if a.ordinal > b.ordinal {
		return 1
	}
	if a.affected < b.affected {
		return -1
	}
	if a.affected > b.affected {
		return 1
	}
	return 0
}

func snapshotBaselineGaps() []SnapshotGapKind {
	return []SnapshotGapKind{
		SnapshotGapIndexCompleteness, SnapshotGapCorrection, SnapshotGapActivity,
		SnapshotGapSourceQualification, SnapshotGapRegistryCorrespondence,
		SnapshotGapFindingAuthority, SnapshotGapGlobalStoreQuota,
		SnapshotGapPreparationByteIdentity,
	}
}

func snapshotAddGap(gaps []SnapshotGapKind, kind SnapshotGapKind) []SnapshotGapKind {
	for _, existing := range gaps {
		if existing == kind {
			return gaps
		}
	}
	return append(gaps, kind)
}

func validateSnapshotNPMReference(ref SnapshotObjectReference) string {
	if ref.Fields == nil || ref.Bytes > maxSnapshotManifestObjectBytes || ref.Records > maxSnapshotManifestRecords {
		return "invalid-shape"
	}
	if ref.Bytes == 0 && (ref.Records != 0 || ref.SHA256 != sha256.Sum256(nil)) {
		return "invalid-shape"
	}
	return ""
}

// The caller supplies an unchanged result from ParseSnapshotManifestV11.
// These cheap typed guards defend direct-reference fields/counters used for
// routing, allocation and budgets; they do not reparse raw manifest JSON or
// authenticate caller-fabricated evidence.
func validateSnapshotNPMManifest(manifest SnapshotManifest) string {
	if manifest.SchemaVersion != "1.1" || manifest.Fields == nil || manifest.Source.Fields == nil ||
		manifest.Source.ID == "" || manifest.Originals.Fields == nil || len(manifest.Blocks) != maxSnapshotManifestBlocks ||
		validateSnapshotNPMReference(manifest.Originals) != "" {
		return "invalid-shape"
	}
	lengths := map[[32]byte]uint64{manifest.Originals.SHA256: manifest.Originals.Bytes}
	blockCounts := make(map[[32]byte]uint64)
	remainingBytes := uint64(maxSnapshotManifestObjectBytes) - manifest.Originals.Bytes
	remainingRecords := uint64(maxSnapshotManifestRecords)
	for i, block := range manifest.Blocks {
		ref := block.Reference
		if block.Index != i || validateSnapshotNPMReference(ref) != "" {
			return "invalid-shape"
		}
		if length, shared := lengths[ref.SHA256]; shared {
			if length != ref.Bytes {
				return "invalid-shape"
			}
		} else {
			if ref.Bytes > remainingBytes {
				return "invalid-shape"
			}
			remainingBytes -= ref.Bytes
			lengths[ref.SHA256] = ref.Bytes
		}
		if count, shared := blockCounts[ref.SHA256]; shared && count != ref.Records {
			return "invalid-shape"
		}
		if ref.Records > remainingRecords {
			return "invalid-shape"
		}
		remainingRecords -= ref.Records
		blockCounts[ref.SHA256] = ref.Records
	}
	return ""
}

func snapshotAddDeclaration(lengths map[[32]byte]uint64, digest [32]byte, size uint64, remaining *uint64, retained *snapshotRetainedBudget, overflow *bool) string {
	if old, ok := lengths[digest]; ok {
		if old != size {
			return "invalid-shape"
		}
		return ""
	}
	if !retained.metadataEntry() || !retained.logicalBytes(40) {
		return "resource"
	}
	if size > *remaining {
		if overflow == nil {
			return "limit-exceeded"
		}
		*overflow = true
		*remaining = 0
	} else {
		*remaining -= size
	}
	lengths[digest] = size
	return ""
}

func snapshotProjectionLogicalBytes(header OSVHeader, affected OSVAffectedProjection, identity OSVNPMIdentityProjection, times OSVTimes) (uint64, bool) {
	var total uint64
	add := func(n int) bool {
		if uint64(n) > ^uint64(0)-total {
			return false
		}
		total += uint64(n)
		return true
	}
	addString := func(v OSVString) bool { return add(len(v.Value)) }
	if !addString(header.ID) || !addString(header.SchemaVersion) {
		return 0, false
	}
	for _, entry := range affected.Entries {
		if !addString(entry.Ecosystem) || !addString(entry.Name) || !addString(entry.PURL) {
			return 0, false
		}
		for _, version := range entry.Versions.Entries {
			if !addString(version) {
				return 0, false
			}
		}
		for _, r := range entry.Ranges.Entries {
			if !addString(r.Type) || !addString(r.Repo) {
				return 0, false
			}
			for _, event := range r.Events.Entries {
				for _, field := range event.Fields {
					if !add(len(field.Name)) || !addString(field.Value) {
						return 0, false
					}
				}
			}
		}
	}
	for _, entry := range identity.Entries {
		if !addString(entry.Ecosystem) || !addString(entry.Name) || !addString(entry.PURL) || !add(len(entry.PURLName)) {
			return 0, false
		}
		for _, problem := range entry.Problems {
			if !add(len(problem.Field)) {
				return 0, false
			}
		}
	}
	for _, value := range []OSVTimestamp{times.Modified, times.Published, times.Withdrawn} {
		if !add(len(value.Text)) {
			return 0, false
		}
	}
	return total, true
}

func ReadSnapshotNPMIdentity(ctx context.Context, manifest SnapshotManifest, name string, streams SnapshotNPMStreams) (SnapshotNPMEvidence, error) {
	fail := func(code string) (SnapshotNPMEvidence, error) {
		return SnapshotNPMEvidence{}, &ParseError{Code: code}
	}
	if ctx == nil {
		return fail("invalid-shape")
	}
	// Count every raw supplied slot, including nil and duplicates, before any
	// manifest-map inspection, result/map allocation, or stream read.
	if len(streams.Originals) > maxSnapshotSuppliedOriginalStreams {
		return fail("limit-exceeded")
	}
	if validateSnapshotNPMManifest(manifest) != "" || !validOSVNPMName(name) || streams.Block == nil || streams.Catalog == nil {
		return fail("invalid-shape")
	}
	identityHash := snapshotNPMIdentityHash(name)
	blockIndex := identityHash[0]
	out := SnapshotNPMEvidence{
		ManifestSHA256: manifest.SHA256, IdentityHash: identityHash,
		Ecosystem: "npm", Name: name, BlockIndex: blockIndex,
		Declaration: SnapshotDeclarationGap,
		Records:     make([]SnapshotOriginalEvidence, 0),
		Gaps:        snapshotBaselineGaps(),
	}
	readBudget := snapshotReadBudget{}
	retained := snapshotRetainedBudget{}
	if !retained.logicalBytes(uint64(len(name))) {
		out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
		return out, nil
	}

	pending := make([]snapshotPendingBinding, 0)
	var previous snapshotBlockRow
	havePrevious, selectionGap := false, false
	blockState, resource, code := readSnapshotJSONL(ctx, streams.Block, manifest.Blocks[int(blockIndex)].Reference, &readBudget, func(line []byte, _ uint64) string {
		row, code := parseSnapshotBlockRow(line)
		if code != "" {
			return code
		}
		if row.identity[0] != blockIndex {
			return "invalid-shape"
		}
		if havePrevious && compareSnapshotBlockRows(previous, row) >= 0 {
			return "invalid-shape"
		}
		previous, havePrevious = row, true
		if row.identity == identityHash && row.ecosystem == "npm" && row.name == name {
			if len(pending) == maxSnapshotRetainedBindings || !retained.metadataEntry() {
				selectionGap = true
				return ""
			}
			pending = append(pending, snapshotPendingBinding{ordinal: row.ordinal, affected: row.affected, digest: row.digest, bytes: row.bytes})
		}
		return ""
	})
	if code != "" {
		return fail(code)
	}
	out.BlockState, out.BytesRead = blockState, readBudget.used
	if resource || selectionGap {
		out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
		return out, nil
	}

	selected := make(map[uint64][]int, len(pending))
	for i := range pending {
		selected[pending[i].ordinal] = append(selected[pending[i].ordinal], i)
	}
	lengths := make(map[[32]byte]uint64)
	remainingDeclared := uint64(maxSnapshotManifestObjectBytes)
	addDirect := func(ref SnapshotObjectReference) string {
		return snapshotAddDeclaration(lengths, ref.SHA256, ref.Bytes, &remainingDeclared, &retained, nil)
	}
	if code = addDirect(manifest.Originals); code != "" {
		if code == "resource" {
			out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
			return out, nil
		}
		return fail(code)
	}
	for _, block := range manifest.Blocks {
		if code = addDirect(block.Reference); code != "" {
			if code == "resource" {
				out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
				return out, nil
			}
			return fail(code)
		}
	}
	declarationOverflow := false
	catalogState, resource, code := readSnapshotJSONL(ctx, streams.Catalog, manifest.Originals, &readBudget, func(line []byte, physical uint64) string {
		row, code := parseSnapshotCatalogRow(line)
		if code != "" {
			return code
		}
		if row.ordinal != physical {
			return "invalid-shape"
		}
		if code = snapshotAddDeclaration(lengths, row.digest, row.bytes, &remainingDeclared, &retained, &declarationOverflow); code != "" {
			return code
		}
		for _, index := range selected[row.ordinal] {
			if pending[index].digest != row.digest || pending[index].bytes != row.bytes {
				return "invalid-shape"
			}
			pending[index].catalogBound = true
		}
		return ""
	})
	if code != "" {
		if code == "resource" {
			out.CatalogState = SnapshotStreamUnavailable
			out.BytesRead = readBudget.used
			out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
			return out, nil
		}
		return fail(code)
	}
	out.CatalogState, out.BytesRead = catalogState, readBudget.used
	if resource {
		out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
		return out, nil
	}
	for _, binding := range pending {
		if !binding.catalogBound {
			return fail("invalid-shape")
		}
	}
	if declarationOverflow {
		return fail("limit-exceeded")
	}
	out.Declaration = SnapshotDeclarationVerified

	supplied := make(map[[32]byte]io.Reader, len(streams.Originals))
	for _, item := range streams.Originals {
		if item.Reader == nil {
			continue
		}
		if _, duplicate := supplied[item.SHA256]; duplicate {
			return fail("invalid-shape")
		}
		supplied[item.SHA256] = item.Reader
	}
	order := make([][32]byte, 0)
	grouped := make(map[[32]byte][]SnapshotAffectedBinding)
	expected := make(map[[32]byte]uint64)
	for _, item := range pending {
		if old, ok := expected[item.digest]; ok && old != item.bytes {
			return fail("invalid-shape")
		}
		if _, ok := grouped[item.digest]; !ok {
			if len(order) == maxSnapshotUniqueOriginals || !retained.metadataEntry() {
				out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
				out.BytesRead = readBudget.used
				return out, nil
			}
			order = append(order, item.digest)
			expected[item.digest] = item.bytes
		}
		grouped[item.digest] = append(grouped[item.digest], SnapshotAffectedBinding{
			SourceOrdinal: item.ordinal, AffectedIndex: item.affected,
			State: SnapshotBindingGap, Problem: SnapshotBindingProblemOriginal,
		})
	}

	for _, digest := range order {
		record := SnapshotOriginalEvidence{
			SHA256: digest, Bytes: expected[digest], State: SnapshotOriginalUnavailable,
			Bindings: append([]SnapshotAffectedBinding(nil), grouped[digest]...),
		}
		reader, ok := supplied[digest]
		if !ok {
			record.Problem = SnapshotOriginalProblemMissing
			out.Records = append(out.Records, record)
			continue
		}
		if record.Bytes > maxSnapshotRetainedOriginalBytes-retained.raw || record.Bytes > maxSnapshotLogicalBytes-retained.logical {
			record.Problem = SnapshotOriginalProblemResource
			out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
			out.Records = append(out.Records, record)
			continue
		}
		raw, resource, readCode := readSnapshotOriginalBytes(ctx, reader, record.Bytes, &readBudget)
		out.BytesRead = readBudget.used
		if readCode == "canceled" {
			return fail(readCode)
		}
		if resource || readCode == "limit-exceeded" {
			record.Problem = SnapshotOriginalProblemResource
			out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
			out.Records = append(out.Records, record)
			continue
		}
		if readCode == "read-failed" {
			record.Problem = SnapshotOriginalProblemRead
			out.Records = append(out.Records, record)
			continue
		}
		if readCode == "length-mismatch" {
			record.Problem = SnapshotOriginalProblemLength
			out.Records = append(out.Records, record)
			continue
		}
		if readCode != "" {
			return fail(readCode)
		}
		check, err := CheckSnapshotObject(SnapshotObjectReference{SHA256: digest, Bytes: record.Bytes}, raw)
		if err != nil {
			record.Problem = SnapshotOriginalProblemResource
			out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
			out.Records = append(out.Records, record)
			continue
		}
		if check.State == SnapshotObjectCheckLengthMismatch {
			record.Problem = SnapshotOriginalProblemLength
			out.Records = append(out.Records, record)
			continue
		}
		if check.State != SnapshotObjectCheckBytesEqual {
			record.Problem = SnapshotOriginalProblemDigest
			out.Records = append(out.Records, record)
			continue
		}
		doc, err := ParseOSVRecord(raw)
		if err != nil {
			record.Problem = SnapshotOriginalProblemParse
			out.Records = append(out.Records, record)
			continue
		}
		header, hErr := ProjectOSVHeader(doc)
		affected, aErr := ProjectOSVAffected(doc)
		identity, iErr := QualifyOSVNPMIdentities(header, affected)
		times, tErr := ProjectOSVTimes(doc)
		if hErr != nil || aErr != nil || iErr != nil || tErr != nil ||
			doc.SHA256 != digest || header.SourceSHA256 != digest || affected.SourceSHA256 != digest ||
			identity.SourceSHA256 != digest || times.SourceSHA256 != digest {
			record.Problem = SnapshotOriginalProblemProjection
			out.Records = append(out.Records, record)
			continue
		}
		projectionBytes, ok := snapshotProjectionLogicalBytes(header, affected, identity, times)
		if !ok || !retained.reserveOriginal(record.Bytes, projectionBytes) {
			record.Problem = SnapshotOriginalProblemResource
			out.Gaps = snapshotAddGap(out.Gaps, SnapshotGapResource)
			out.Records = append(out.Records, record)
			continue
		}
		record.Raw, record.Header, record.Affected, record.Identity, record.Times = raw, header, affected, identity, times
		record.State, record.Problem = SnapshotOriginalVerified, SnapshotOriginalProblemNone
		for i := range record.Bindings {
			binding := &record.Bindings[i]
			if binding.AffectedIndex >= uint64(len(identity.Entries)) || binding.AffectedIndex >= uint64(len(affected.Entries)) {
				binding.Problem = SnapshotBindingProblemAffectedIndex
				continue
			}
			entry := identity.Entries[int(binding.AffectedIndex)]
			if entry.Qualification != OSVNPMIdentityCandidate || entry.Ecosystem.State != OSVFieldValue ||
				entry.Ecosystem.Value != "npm" || entry.Name.State != OSVFieldValue || entry.Name.Value != name ||
				snapshotNPMIdentityHash(entry.Name.Value) != identityHash {
				binding.Problem = SnapshotBindingProblemIdentity
				continue
			}
			binding.State, binding.Problem = SnapshotBindingEligible, SnapshotBindingProblemNone
		}
		out.Records = append(out.Records, record)
	}
	return out, nil
}
