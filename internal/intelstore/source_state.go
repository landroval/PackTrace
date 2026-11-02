package intelstore

import (
	"context"
	"encoding/json"
	"packtrace/internal/intel"
)

type sourceState struct {
	id          ID
	descriptor  generationDescriptor
	receipt     sourceReceipt
	preparation preparationRecord
	manifest    intel.SnapshotManifest
	draft       generationDraft
}

func (s *Store) loadSourceState(ctx context.Context, id ID) (sourceState, error) {
	var state sourceState
	state.id = id
	// A source id, valid graph or copied receipt is not permission to emit its
	// IDs to the network. The local native-store-bound acquisition seal is first.
	if e := s.verifyLocal(ctx, id); e != nil {
		return state, ErrUntrusted
	}
	header, e := s.explicitHeader(ctx, id)
	if e != nil {
		return state, e
	}
	raw, e := s.readRef(ctx, header.Descriptor, 4096)
	if e != nil {
		return state, e
	}
	if !strictObject(raw, 4096, "Version", "Manifest", "ObjectSet", "Cursor", "Provenance") || json.Unmarshal(raw, &state.descriptor) != nil || state.descriptor.Version != 1 {
		return state, ErrCorrupt
	}
	raw, e = s.readRef(ctx, state.descriptor.Provenance, 32<<10)
	if e != nil {
		return state, e
	}
	if json.Unmarshal(raw, &state.receipt) != nil || state.receipt.Version != 1 || state.receipt.Source != "osv-npm" || state.receipt.PublisherAuthentication != "not-established" || state.receipt.Acquisition != "https-generation-bound" && state.receipt.Acquisition != "https-osv-incremental" {
		return state, ErrUntrusted
	}
	raw, e = s.readRef(ctx, state.receipt.Preparation, 512<<10)
	if e != nil {
		return state, e
	}
	if json.Unmarshal(raw, &state.preparation) != nil || state.preparation.Version != 1 || state.preparation.Records > 2_000_000 || state.preparation.Memberships > 2_000_000 || state.preparation.UnknownPublisherRecords != 0 || state.preparation.GitHubRecords > state.preparation.Records || state.preparation.OpenSSFRecords > state.preparation.Records || state.preparation.GitHubRecords+state.preparation.OpenSSFRecords != state.preparation.Records || state.preparation.SourceIDs.Bytes > 512<<20 {
		return state, ErrCorrupt
	}
	raw, e = s.readRef(ctx, state.descriptor.Manifest, 1<<20)
	if e != nil {
		return state, e
	}
	state.manifest, e = intel.ParseSnapshotManifestV11(raw)
	if e != nil || state.manifest.Originals.Records != state.preparation.Records {
		return state, ErrCorrupt
	}
	refs := []ObjectRef{state.descriptor.Manifest, state.receipt.Preparation, state.preparation.SourceIDs, state.receipt.Metadata, {SHA256: state.manifest.Originals.SHA256, Bytes: state.manifest.Originals.Bytes}}
	for _, block := range state.manifest.Blocks {
		refs = append(refs, ObjectRef{block.Reference.SHA256, block.Reference.Bytes})
	}
	for _, attribution := range state.receipt.Attributions {
		refs = append(refs, attribution.Text)
	}
	seen := make(map[[32]byte]uint64)
	var extras []ObjectRef
	for _, r := range refs {
		if zeroRef(r) {
			return state, ErrCorrupt
		}
		if old, ok := seen[r.SHA256]; ok {
			if old != r.Bytes {
				return state, ErrCorrupt
			}
			continue
		}
		seen[r.SHA256] = r.Bytes
		extras = append(extras, r)
	}
	state.draft = generationDraft{Manifest: state.descriptor.Manifest, Objects: extras, Provenance: state.receipt.Preparation, Cursor: state.descriptor.Cursor}
	return state, nil
}
