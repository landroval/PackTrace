package intel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sort"
)

// SnapshotVerifiedCatalog has no exported verified bit or mutable row access.
// It proves bounded catalog bytes/declarations for one manifest, not a source,
// physical root, publisher, index completeness, freshness or matching result.
type SnapshotVerifiedCatalog struct {
	manifest         [32]byte
	rows             []snapshotCatalogRow
	order            []uint32
	logical, entries uint64
	verified         bool
}

// Contains exposes only bounded digest/length membership, never mutable rows
// or publisher/source authority.
func (c *SnapshotVerifiedCatalog) Contains(digest [32]byte, size uint64) bool {
	if c == nil || !c.verified {
		return false
	}
	i := sort.Search(len(c.order), func(i int) bool { return bytes.Compare(c.rows[c.order[i]].digest[:], digest[:]) >= 0 })
	return i < len(c.order) && c.rows[c.order[i]].digest == digest && c.rows[c.order[i]].bytes == size
}

// Reference returns a scalar copy for a verified original ordinal.
func (c *SnapshotVerifiedCatalog) Reference(ordinal uint64) ([32]byte, uint64, bool) {
	if c == nil || !c.verified || ordinal >= uint64(len(c.rows)) {
		return [32]byte{}, 0, false
	}
	row := c.rows[ordinal]
	return row.digest, row.bytes, true
}

func snapshotCatalogFingerprint(m SnapshotManifest) [32]byte {
	h := sha256.New()
	h.Write(m.SHA256[:])
	h.Write([]byte(m.SchemaVersion))
	h.Write([]byte{0})
	h.Write([]byte(m.Source.ID))
	h.Write([]byte{0})
	var number [8]byte
	add := func(ref SnapshotObjectReference) {
		h.Write(ref.SHA256[:])
		binary.LittleEndian.PutUint64(number[:], ref.Bytes)
		h.Write(number[:])
		binary.LittleEndian.PutUint64(number[:], ref.Records)
		h.Write(number[:])
	}
	add(m.Originals)
	for _, b := range m.Blocks {
		binary.LittleEndian.PutUint64(number[:], uint64(b.Index))
		h.Write(number[:])
		add(b.Reference)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
func ReadSnapshotCatalog(ctx context.Context, manifest SnapshotManifest, input io.Reader) (*SnapshotVerifiedCatalog, error) {
	fail := func(code string) (*SnapshotVerifiedCatalog, error) { return nil, &ParseError{Code: code} }
	if ctx == nil || input == nil || validateSnapshotNPMManifest(manifest) != "" {
		return fail("invalid-shape")
	}
	retained := snapshotRetainedBudget{}
	readBudget := snapshotReadBudget{}
	rows := make([]snapshotCatalogRow, 0, int(manifest.Originals.Records))
	state, resource, code := readSnapshotJSONL(ctx, input, manifest.Originals, &readBudget, func(line []byte, physical uint64) string {
		row, code := parseSnapshotCatalogRow(line)
		if code != "" {
			return code
		}
		if row.ordinal != physical {
			return "invalid-shape"
		}
		if !retained.metadataEntry() || !retained.logicalBytes(52) {
			return "resource"
		}
		rows = append(rows, row)
		return ""
	})
	if code != "" {
		if code == "resource" {
			code = "limit-exceeded"
		}
		return fail(code)
	}
	if resource || state != SnapshotStreamStructured {
		return fail("limit-exceeded")
	}
	// One bounded row table plus integer aliases, not a second millions-sized
	// declaration map. Alias bytes are included in logical retention above.
	order := make([]uint32, len(rows))
	for i := range order {
		order[i] = uint32(i)
	}
	sort.Slice(order, func(i, j int) bool { return bytes.Compare(rows[order[i]].digest[:], rows[order[j]].digest[:]) < 0 })
	if ctx.Err() != nil {
		return fail("canceled")
	}
	direct := make(map[[32]byte]uint64)
	remaining := uint64(maxSnapshotManifestObjectBytes)
	add := func(digest [32]byte, size uint64) string {
		if old, ok := direct[digest]; ok {
			if old != size {
				return "invalid-shape"
			}
			return ""
		}
		if !retained.metadataEntry() || !retained.logicalBytes(40) {
			return "limit-exceeded"
		}
		if size > remaining {
			return "limit-exceeded"
		}
		remaining -= size
		direct[digest] = size
		return ""
	}
	if code := add(manifest.Originals.SHA256, manifest.Originals.Bytes); code != "" {
		return fail(code)
	}
	for _, b := range manifest.Blocks {
		if code := add(b.Reference.SHA256, b.Reference.Bytes); code != "" {
			return fail(code)
		}
	}
	var previous snapshotCatalogRow
	have := false
	for _, index := range order {
		row := rows[index]
		if have && row.digest == previous.digest {
			if row.bytes != previous.bytes {
				return fail("invalid-shape")
			}
			continue
		}
		previous = row
		have = true
		if old, ok := direct[row.digest]; ok {
			if old != row.bytes {
				return fail("invalid-shape")
			}
			continue
		}
		if row.bytes > remaining {
			return fail("limit-exceeded")
		}
		remaining -= row.bytes
	}
	return &SnapshotVerifiedCatalog{manifest: snapshotCatalogFingerprint(manifest), rows: rows, order: order, logical: retained.logical, entries: retained.metadata, verified: true}, nil
}
func (c *SnapshotVerifiedCatalog) bind(manifest SnapshotManifest, pending []snapshotPendingBinding, retained *snapshotRetainedBudget) string {
	if c == nil || !c.verified || c.manifest != snapshotCatalogFingerprint(manifest) {
		return "invalid-shape"
	}
	if c.entries > maxSnapshotMetadataEntries-retained.metadata || !retained.logicalBytes(c.logical) {
		return "resource"
	}
	retained.metadata += c.entries
	for i := range pending {
		p := &pending[i]
		if p.ordinal >= uint64(len(c.rows)) {
			return "invalid-shape"
		}
		row := c.rows[p.ordinal]
		if p.digest != row.digest || p.bytes != row.bytes {
			return "invalid-shape"
		}
		p.catalogBound = true
	}
	return ""
}

// SnapshotNPMIdentityBlock validates the existing identity profile before a
// store opens a block; it is routing metadata, not declaration authority.
func SnapshotNPMIdentityBlock(name string) (uint8, error) {
	if !validOSVNPMName(name) {
		return 0, &ParseError{Code: "invalid-shape"}
	}
	return snapshotNPMIdentityHash(name)[0], nil
}

func ReadSnapshotNPMIdentityWithCatalog(ctx context.Context, manifest SnapshotManifest, name string, catalog *SnapshotVerifiedCatalog, block io.Reader, originals []SnapshotOriginalStream) (SnapshotNPMEvidence, error) {
	return readSnapshotNPMIdentity(ctx, manifest, name, SnapshotNPMStreams{Block: block, Originals: originals}, catalog)
}
