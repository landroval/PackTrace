package intelstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"packtrace/internal/intel"
	"packtrace/internal/nativefs"
)

func (s *Store) Import(ctx context.Context, input *nativefs.File, options ImportOptions) (result OperationResult, failure error) {
	if s == nil || ctx == nil || input == nil {
		return result, ErrUnavailable
	}
	var expected *ID
	if options.TrustedSnapshotDigest != "" {
		id, e := parseSnapshotPin(options.TrustedSnapshotDigest)
		if e != nil {
			return result, e
		}
		expected = &id
	}
	tx, e := s.begin(ctx, operationImport, &Budget{})
	if e != nil {
		return result, e
	}
	defer func() {
		if failure != nil {
			tx.mu.Lock()
			tx.failed = failure
			tx.mu.Unlock()
		}
		failure = errors.Join(failure, tx.Close())
	}()
	archive := &bundleInput{ctx: tx.work, file: input}
	header, e := archive.next()
	if e != nil {
		return result, ErrCorrupt
	}
	descriptorRaw, e := archive.small(header, "descriptor.json", 4096)
	if e != nil {
		return result, e
	}
	id := ID(sha256.Sum256(descriptorRaw))
	if expected != nil && *expected != id {
		return result, ErrUntrusted
	}
	descriptor, e := parseGenerationDescriptor(descriptorRaw)
	if e != nil {
		return result, e
	}
	header, e = archive.next()
	if e != nil {
		return result, ErrCorrupt
	}
	manifestRaw, e := archive.small(header, "manifest.json", 1<<20)
	if e != nil || sha256.Sum256(manifestRaw) != descriptor.Manifest.SHA256 || uint64(len(manifestRaw)) != descriptor.Manifest.Bytes {
		return result, ErrCorrupt
	}
	manifest, e := intel.ParseSnapshotManifestV11(manifestRaw)
	if e != nil {
		return result, ErrCorrupt
	}
	header, e = archive.next()
	if e != nil {
		return result, ErrCorrupt
	}
	if _, e := archive.object(tx, header, "object-set", descriptor.ObjectSet); e != nil {
		return result, e
	}
	set, e := s.openObjectSet(tx.work, descriptor.ObjectSet)
	if e != nil {
		return result, e
	}
	for {
		ref, ok, e := set.next()
		if e != nil {
			set.Close()
			return result, e
		}
		if !ok {
			break
		}
		header, e = archive.next()
		if e != nil {
			set.Close()
			return result, ErrCorrupt
		}
		if _, e := archive.object(tx, header, "objects/"+hex.EncodeToString(ref.SHA256[:]), ref); e != nil {
			set.Close()
			return result, e
		}
	}
	if e := set.Close(); e != nil {
		return result, e
	}
	if _, e := archive.next(); e != io.EOF {
		return result, ErrCorrupt
	}
	if e := input.Stable(); e != nil {
		return result, ErrCorrupt
	}
	draft, e := rebuildImported(tx.work, tx, descriptor, manifest)
	if e != nil {
		return result, e
	}
	sealed, e := tx.seal(tx.work, draft)
	if e != nil {
		return result, e
	}
	if sealed != id {
		return result, ErrCorrupt
	}
	if e := input.Stable(); e != nil {
		return result, ErrCorrupt
	}
	// Import never calls attestLocal, never copies a key/MAC control and never
	// turns an expected input digest into persistent source-acquisition authority.
	if e := tx.activate(tx.work, sealed); e != nil {
		return result, e
	}
	return OperationResult{Generation: sealed, Records: tx.prep.record.Records, Memberships: tx.prep.record.Memberships}, nil
}
func rebuildImported(ctx context.Context, t *Transaction, descriptor generationDescriptor, manifest intel.SnapshotManifest) (generationDraft, error) {
	raw, e := t.store.readRef(ctx, descriptor.Provenance, 32<<10)
	if e != nil {
		return generationDraft{}, e
	}
	prepRef := descriptor.Provenance
	var receipt sourceReceipt
	source := false
	if json.Unmarshal(raw, &receipt) == nil && receipt.Version == 1 && receipt.Source == "osv-npm" {
		source = true
		prepRef = receipt.Preparation
		raw, e = t.store.readRef(ctx, prepRef, 512<<10)
		if e != nil {
			return generationDraft{}, e
		}
	}
	if !source {
		return generationDraft{}, ErrUntrusted
	}
	var prep preparationRecord
	if json.Unmarshal(raw, &prep) != nil || prep.Version != 1 || prep.Records != manifest.Originals.Records || prep.SourceIDs.Bytes > 512<<20 {
		return generationDraft{}, ErrCorrupt
	}
	catalogInput, e := t.store.objectReader(ctx, ObjectRef{manifest.Originals.SHA256, manifest.Originals.Bytes})
	if e != nil {
		return generationDraft{}, e
	}
	catalog, e := intel.ReadSnapshotCatalog(ctx, manifest, catalogInput)
	closed := catalogInput.Close()
	if e != nil || closed != nil {
		return generationDraft{}, errors.Join(e, closed)
	}
	ids, e := t.store.objectReader(ctx, prep.SourceIDs)
	if e != nil {
		return generationDraft{}, e
	}
	scan := newSourceIDCursor(ids)
	defer ids.Close()
	t.prep = &preparationState{record: preparationRecord{Version: 1, Source: "caller-supplied"}}
	for ordinal := uint64(0); ordinal < manifest.Originals.Records; ordinal++ {
		digest, size, ok := catalog.Reference(ordinal)
		if !ok || size > 4<<20 {
			return generationDraft{}, ErrCorrupt
		}
		ref := ObjectRef{digest, size}
		row, e := scan.next()
		if e != nil || row == nil || row.Original != ref {
			return generationDraft{}, ErrCorrupt
		}
		original, e := t.existingAdvisory(ctx, ref)
		if e != nil {
			return generationDraft{}, e
		}
		forced := sourceObserved
		if row.Disposition == sourceUnresolved {
			forced = sourceUnresolved
		}
		if e := prepareOriginal(ctx, t, row.ID, original, &ref, forced); e != nil {
			return generationDraft{}, e
		}
	}
	if row, e := scan.next(); e != nil || row != nil {
		return generationDraft{}, ErrCorrupt
	}
	if e := ids.Close(); e != nil {
		return generationDraft{}, e
	}
	rebuilt, e := buildIndexes(ctx, t)
	if e != nil {
		return rebuilt, e
	}
	if rebuilt.Provenance != prepRef {
		return generationDraft{}, ErrCorrupt
	}
	rebuiltManifestRaw, e := t.store.readRef(ctx, rebuilt.Manifest, 1<<20)
	if e != nil {
		return rebuilt, e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(rebuiltManifestRaw, &fields) != nil {
		return rebuilt, ErrCorrupt
	}
	fields["source"] = manifest.Fields["source"]
	rebound, e := json.Marshal(fields)
	if e != nil {
		return rebuilt, ErrCorrupt
	}
	rebuiltManifest, e := t.put(ctx, bytes.NewReader(rebound), uint64(len(rebound)))
	if e != nil {
		return rebuilt, e
	}
	if rebuiltManifest != descriptor.Manifest {
		return rebuilt, ErrCorrupt
	}
	if source && !licenseProfile(receipt, t.prep.record) {
		return rebuilt, ErrUntrusted
	}
	// Keep bounded auxiliary references, not every original in a heap map. The
	// verified catalog supplies digest+length membership through integer aliases.
	set, e := t.store.openObjectSet(ctx, descriptor.ObjectSet)
	if e != nil {
		return rebuilt, e
	}
	var extras []ObjectRef
	for {
		ref, ok, e := set.next()
		if e != nil {
			set.Close()
			return rebuilt, e
		}
		if !ok {
			break
		}
		if !catalog.Contains(ref.SHA256, ref.Bytes) {
			if len(extras) >= 1024 {
				set.Close()
				return rebuilt, ErrLimit
			}
			extras = append(extras, ref)
		}
	}
	if e := set.Close(); e != nil {
		return rebuilt, e
	}
	return generationDraft{Manifest: descriptor.Manifest, Objects: extras, Cursor: descriptor.Cursor, Provenance: descriptor.Provenance}, nil
}
