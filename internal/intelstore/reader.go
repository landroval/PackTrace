package intelstore

import (
	"context"
	"errors"
	"packtrace/internal/intel"
	"sync"
	"time"
)

type Snapshot struct {
	mu            sync.Mutex
	store         *Store
	pin           *Pin
	manifest      intel.SnapshotManifest
	descriptor    generationDescriptor
	descriptorRef ObjectRef
	catalog       *intel.SnapshotVerifiedCatalog
	closed        bool
}

func (s *Store) ReadPinned(ctx context.Context, selected *ID) (*Snapshot, error) {
	pin, e := s.Pin(ctx, selected)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Snapshot, error) { return nil, errors.Join(e, pin.Close()) }
	header, e := s.explicitHeader(ctx, pin.ID())
	if e != nil {
		return fail(e)
	}
	raw, e := s.readRef(ctx, header.Descriptor, 4096)
	if e != nil {
		return fail(e)
	}
	descriptor, e := parseGenerationDescriptor(raw)
	if e != nil {
		return fail(e)
	}
	raw, e = s.readRef(ctx, descriptor.Manifest, 1<<20)
	if e != nil {
		return fail(e)
	}
	manifest, e := intel.ParseSnapshotManifestV11(raw)
	if e != nil {
		return fail(ErrCorrupt)
	}
	input, e := s.objectReader(ctx, ObjectRef{manifest.Originals.SHA256, manifest.Originals.Bytes})
	if e != nil {
		return fail(e)
	}
	catalog, e := intel.ReadSnapshotCatalog(ctx, manifest, input)
	closeErr := input.Close()
	if e != nil || closeErr != nil {
		return fail(errors.Join(e, closeErr))
	}
	return &Snapshot{store: s, pin: pin, manifest: manifest, descriptor: descriptor, descriptorRef: header.Descriptor, catalog: catalog}, nil
}
func (s *Snapshot) Observe(ctx context.Context, now time.Time, expected *ID) (Observation, error) {
	if s == nil {
		return Observation{}, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Observation{}, ErrUnavailable
	}
	return s.store.Observe(ctx, s.pin, now, expected)
}

type lazyOriginal struct {
	ctx    context.Context
	store  *Store
	ref    ObjectRef
	reader *objectReader
	closed bool
}

func (r *lazyOriginal) Read(p []byte) (int, error) {
	if r.closed {
		return 0, ErrUnavailable
	}
	if r.ref.Bytes > 4<<20 {
		return 0, ErrLimit
	}
	if r.reader == nil {
		reader, e := r.store.objectReader(r.ctx, r.ref)
		if e != nil {
			return 0, e
		}
		r.reader = reader
	}
	return r.reader.Read(p)
}
func (r *lazyOriginal) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	if r.reader != nil {
		return r.reader.Close()
	}
	return nil
}
func (s *Snapshot) ReadIdentity(ctx context.Context, name string) (intel.SnapshotNPMEvidence, error) {
	if s == nil || ctx == nil {
		return intel.SnapshotNPMEvidence{}, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.pin.ID() == (ID{}) {
		return intel.SnapshotNPMEvidence{}, ErrUnavailable
	}
	if s.pin.lease.Stable(ctx) != nil {
		return intel.SnapshotNPMEvidence{}, ErrBinding
	}
	index, e := intel.SnapshotNPMIdentityBlock(name)
	if e != nil {
		return intel.SnapshotNPMEvidence{}, e
	}
	reference := s.manifest.Blocks[index].Reference
	ref := ObjectRef{reference.SHA256, reference.Bytes}
	read := func(originals []intel.SnapshotOriginalStream) (intel.SnapshotNPMEvidence, error) {
		block, e := s.store.objectReader(ctx, ref)
		if e != nil {
			return intel.SnapshotNPMEvidence{}, e
		}
		got, e := intel.ReadSnapshotNPMIdentityWithCatalog(ctx, s.manifest, name, s.catalog, block, originals)
		return got, errors.Join(e, block.Close(), s.pin.lease.Stable(ctx))
	}
	preview, e := read(nil)
	if e != nil {
		return intel.SnapshotNPMEvidence{}, e
	}
	if len(preview.Records) == 0 || preview.BlockState != intel.SnapshotStreamStructured {
		return preview, nil
	}
	// Store objects are capped512MiB, so two block passes plus the unchanged
	//1024 lazy originals capped4MiB stay inside the existing8GiB identity cap.
	readers := make([]*lazyOriginal, 0, len(preview.Records))
	streams := make([]intel.SnapshotOriginalStream, 0, len(preview.Records))
	for _, record := range preview.Records {
		reader := &lazyOriginal{ctx: ctx, store: s.store, ref: ObjectRef{record.SHA256, record.Bytes}}
		readers = append(readers, reader)
		streams = append(streams, intel.SnapshotOriginalStream{SHA256: record.SHA256, Reader: reader})
	}
	got, e := read(streams)
	for _, r := range readers {
		e = errors.Join(e, r.Close())
	}
	if e != nil {
		return intel.SnapshotNPMEvidence{}, e
	}
	if preview.BytesRead > (8<<30)-got.BytesRead {
		return intel.SnapshotNPMEvidence{}, ErrLimit
	}
	got.BytesRead += preview.BytesRead
	return got, nil
}
func (s *Snapshot) Close() error {
	if s == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	s.closed = true
	s.catalog = nil
	return s.pin.Close()
}
