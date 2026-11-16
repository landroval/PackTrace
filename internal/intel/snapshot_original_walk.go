package intel

import (
	"context"
	"errors"
	"io"
)

// WalkSnapshotCatalogOriginals verifies and projects EVERY catalog original.
// Unlike identity lookup this can establish routing for records omitted from an
// index. It grants no source/category authority. Originals are callback-scoped;
// catalog metadata and all reads share the existing parser ceilings.
func WalkSnapshotCatalogOriginals(ctx context.Context, manifest SnapshotManifest, catalog *SnapshotVerifiedCatalog, open func(SnapshotObjectReference) (io.ReadCloser, error), emit func(uint64, SnapshotOriginalEvidence) error) error {
	fail := func(code string) error { return &ParseError{Code: code} }
	if ctx == nil || open == nil || emit == nil || catalog == nil {
		return fail("invalid-shape")
	}
	retained := snapshotRetainedBudget{}
	if code := catalog.bind(manifest, nil, &retained); code != "" {
		return fail(code)
	}
	if len(catalog.rows) > maxSnapshotUniqueOriginals {
		return fail("limit-exceeded")
	}
	budget := snapshotReadBudget{}
	for ordinal, row := range catalog.rows {
		if ctx.Err() != nil {
			return fail("canceled")
		}
		r, err := open(SnapshotObjectReference{SHA256: row.digest, Bytes: row.bytes})
		if err != nil {
			return err
		}
		if r == nil {
			return fail("invalid-shape")
		}
		raw, resource, code := readSnapshotOriginalBytes(ctx, r, row.bytes, &budget)
		closeErr := r.Close()
		if resource && code == "" {
			code = "limit-exceeded"
		}
		if code != "" || closeErr != nil {
			if code != "" {
				return errors.Join(fail(code), closeErr)
			}
			return closeErr
		}
		check, err := CheckSnapshotObject(SnapshotObjectReference{SHA256: row.digest, Bytes: row.bytes}, raw)
		if err != nil || check.State != SnapshotObjectCheckBytesEqual {
			return fail("invalid-shape")
		}
		doc, err := ParseOSVRecord(raw)
		if err != nil {
			return err
		}
		header, he := ProjectOSVHeader(doc)
		affected, ae := ProjectOSVAffected(doc)
		identity, ie := QualifyOSVNPMIdentities(header, affected)
		times, te := ProjectOSVTimes(doc)
		if he != nil || ae != nil || ie != nil || te != nil {
			return fail("invalid-shape")
		}
		logical, ok := snapshotProjectionLogicalBytes(header, affected, identity, times)
		current := retained
		if !ok || !current.reserveOriginal(row.bytes, logical) {
			return fail("limit-exceeded")
		}
		record := SnapshotOriginalEvidence{SHA256: row.digest, Bytes: row.bytes, State: SnapshotOriginalVerified, Raw: raw, Header: header, Affected: affected, Identity: identity, Times: times}
		if err := emit(uint64(ordinal), record); err != nil {
			return err
		}
	}
	return ctx.Err()
}
