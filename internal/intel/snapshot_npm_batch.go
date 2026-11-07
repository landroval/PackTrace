package intel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
)

// SnapshotNPMIdentityNames validates an entire window before a caller opens
// objects. The returned order is the index's canonical identity-hash order.
func SnapshotNPMIdentityNames(names []string) ([]string, uint8, error) {
	fail := func() ([]string, uint8, error) { return nil, 0, &ParseError{Code: "invalid-shape"} }
	if len(names) == 0 || len(names) > 64 {
		return fail()
	}
	sorted := append([]string(nil), names...)
	seen := make(map[string]bool, len(names))
	var bucket uint8
	for i, name := range sorted {
		b, err := SnapshotNPMIdentityBlock(name)
		if err != nil || seen[name] || i > 0 && b != bucket {
			return fail()
		}
		seen[name] = true
		bucket = b
	}
	sort.Slice(sorted, func(i, j int) bool {
		a, b := snapshotNPMIdentityHash(sorted[i]), snapshotNPMIdentityHash(sorted[j])
		return bytes.Compare(a[:], b[:]) < 0
	})
	return sorted, bucket, nil
}

// WalkSnapshotNPMIdentitiesWithCatalog reads the supplied original block once,
// verifies every row and EOF, and only then opens mandatory original streams.
// Evidence is callback-scoped: callers must not retain successive raw records.
// open must return a fresh original handle, never cached projection evidence.
func WalkSnapshotNPMIdentitiesWithCatalog(ctx context.Context, manifest SnapshotManifest, names []string, catalog *SnapshotVerifiedCatalog, block io.Reader, open func(SnapshotObjectReference) (io.ReadCloser, error), emit func(string, SnapshotNPMEvidence) error) error {
	fail := func(code string) error { return &ParseError{Code: code} }
	names, bucket, err := SnapshotNPMIdentityNames(names)
	if err != nil {
		return err
	}
	if ctx == nil || block == nil || open == nil || emit == nil || validateSnapshotNPMManifest(manifest) != "" || catalog == nil || !catalog.verified || catalog.manifest != snapshotCatalogFingerprint(manifest) {
		return fail("invalid-shape")
	}
	selected := make(map[string][]snapshotPendingBinding, len(names))
	for _, name := range names {
		selected[name] = nil
	}
	retained := snapshotRetainedBudget{}
	budget := snapshotReadBudget{}
	unique := make(map[[32]byte]uint64)
	count := 0
	limited := false
	var previous snapshotBlockRow
	have := false
	state, resource, code := readSnapshotJSONL(ctx, block, manifest.Blocks[int(bucket)].Reference, &budget, func(line []byte, _ uint64) string {
		row, code := parseSnapshotBlockRow(line)
		if code != "" {
			return code
		}
		if row.identity[0] != bucket || have && compareSnapshotBlockRows(previous, row) >= 0 {
			return "invalid-shape"
		}
		previous, have = row, true
		if _, ok := selected[row.name]; !ok {
			return ""
		}
		if old, ok := unique[row.digest]; ok && old != row.bytes {
			return "invalid-shape"
		}
		if limited {
			return ""
		}
		if count == maxSnapshotRetainedBindings || !retained.metadataEntry() || !retained.logicalBytes(128) {
			limited = true
			return ""
		}
		if _, ok := unique[row.digest]; !ok {
			if len(unique) == maxSnapshotUniqueOriginals {
				limited = true
				return ""
			}
			unique[row.digest] = row.bytes
		}
		count++
		selected[row.name] = append(selected[row.name], snapshotPendingBinding{ordinal: row.ordinal, affected: row.affected, digest: row.digest, bytes: row.bytes})
		return ""
	})
	if code != "" {
		return fail(code)
	}
	if resource || limited || state != SnapshotStreamStructured {
		return fail("limit-exceeded")
	}
	// Bind all selected rows once; catalog accounting is shared across the
	// window rather than multiplied by the number of active identities.
	all := make([]snapshotPendingBinding, 0, count)
	for _, name := range names {
		all = append(all, selected[name]...)
	}
	if code := catalog.bind(manifest, all, &retained); code != "" {
		if code == "resource" {
			code = "limit-exceeded"
		}
		return fail(code)
	}
	offset := 0
	for _, name := range names {
		n := len(selected[name])
		selected[name] = all[offset : offset+n]
		offset += n
	}
	blockBytes := budget.used
	for i, name := range names {
		if ctx.Err() != nil {
			return fail("canceled")
		}
		pending := selected[name]
		// Original handles are scoped to this identity, including all failure paths.
		streams := make([]SnapshotOriginalStream, 0, len(pending))
		closers := make([]io.ReadCloser, 0, len(pending))
		seen := make(map[[32]byte]bool)
		closeAll := func() error {
			var err error
			for _, r := range closers {
				err = errors.Join(err, r.Close())
			}
			return err
		}
		for _, p := range pending {
			if seen[p.digest] {
				continue
			}
			seen[p.digest] = true
			r, err := open(SnapshotObjectReference{SHA256: p.digest, Bytes: p.bytes})
			if err != nil {
				return errors.Join(err, closeAll())
			}
			if r == nil {
				return errors.Join(fail("invalid-shape"), closeAll())
			}
			closers = append(closers, r)
			streams = append(streams, SnapshotOriginalStream{SHA256: p.digest, Reader: r})
		}
		hash := snapshotNPMIdentityHash(name)
		out := SnapshotNPMEvidence{ManifestSHA256: manifest.SHA256, IdentityHash: hash, Ecosystem: "npm", Name: name, BlockIndex: bucket, BlockState: state, CatalogState: SnapshotStreamStructured, Declaration: SnapshotDeclarationVerified, Records: make([]SnapshotOriginalEvidence, 0), Gaps: snapshotBaselineGaps()}
		// Only one identity's original bytes/projections are live at a time. Selected
		// bindings and verified catalog metadata remain charged throughout the walk.
		identityRetained := retained
		before := budget.used
		out, err = hydrateSnapshotNPMIdentity(ctx, out, pending, streams, &budget, &identityRetained)
		err = errors.Join(err, closeAll())
		if err != nil {
			return err
		}
		out.BytesRead = budget.used - before
		if i == 0 {
			out.BytesRead += blockBytes
		}
		if ctx.Err() != nil {
			return fail("canceled")
		}
		if err := emit(name, out); err != nil {
			return err
		}
	}
	return nil
}
