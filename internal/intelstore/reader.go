package intelstore

import (
	"context"
	"errors"
	"io"
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
	return s.readPinned(ctx, selected, nil)
}

// ReadPinnedLimited charges additional parent admission reads (including failed
// descriptor/manifest/catalog reads) against the comparison's remaining budget.
func (s *Store) ReadPinnedLimited(ctx context.Context, selected *ID, remaining uint64) (*Snapshot, uint64, error) {
	if remaining > 8<<30 {
		return nil, 0, ErrLimit
	}
	budget := &identityReadBudget{remaining: remaining}
	snapshot, err := s.readPinned(ctx, selected, budget)
	return snapshot, budget.consumed, errors.Join(err, budget.err)
}

func (s *Store) readRefBudget(ctx context.Context, ref ObjectRef, limit uint64, budget *identityReadBudget) (raw []byte, err error) {
	if budget == nil {
		return s.readRef(ctx, ref, limit)
	}
	if ref.Bytes > limit {
		return nil, ErrLimit
	}
	r, err := s.objectReader(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	return io.ReadAll(identityIndexReader{r, budget})
}

func (s *Store) readPinned(ctx context.Context, selected *ID, budget *identityReadBudget) (*Snapshot, error) {
	readRef := func(ref ObjectRef, limit uint64) ([]byte, error) {
		return s.readRefBudget(ctx, ref, limit, budget)
	}
	pin, e := s.Pin(ctx, selected)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Snapshot, error) { return nil, errors.Join(e, pin.Close()) }
	header, e := s.explicitHeader(ctx, pin.ID())
	if e != nil {
		return fail(e)
	}
	raw, e := readRef(header.Descriptor, 4096)
	if e != nil {
		return fail(e)
	}
	descriptor, e := parseGenerationDescriptor(raw)
	if e != nil {
		return fail(e)
	}
	raw, e = readRef(descriptor.Manifest, 1<<20)
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
	catalog, e := intel.ReadSnapshotCatalog(ctx, manifest, identityIndexReader{input, budget})
	closeErr := input.Close()
	if e != nil || closeErr != nil {
		return fail(errors.Join(e, closeErr))
	}
	return &Snapshot{store: s, pin: pin, manifest: manifest, descriptor: descriptor, descriptorRef: header.Descriptor, catalog: catalog}, nil
}

// ObserveLimited charges the independently repeated descriptor, manifest and
// source-provenance object reads, including failures, to the caller's remaining
// comparison allowance. Generation seal/pin/native metadata retain their own caps.
func (s *Snapshot) ObserveLimited(ctx context.Context, now time.Time, expected *ID, remaining uint64) (Observation, uint64, error) {
	if s == nil || remaining > 8<<30 {
		return Observation{}, 0, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Observation{}, 0, ErrUnavailable
	}
	budget := &identityReadBudget{remaining: remaining}
	got, err := s.store.observe(ctx, s.pin, now, expected, budget)
	err = errors.Join(err, budget.err)
	if err != nil {
		got = Observation{}
	}
	return got, budget.consumed, err
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
	budget *identityReadBudget
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
	return r.budget.read(r.reader, p)
}

// identityReadBudget charges actual object bytes, including reads that fail.
// At the exact boundary only an already fully consumed object's real EOF check
// is allowed: nativefs never reads beyond the selected inode's initial size.
// This preserves objectReader's digest, extra-content and stability validation.
type identityReadBudget struct {
	remaining, consumed uint64
	err                 error
}

func (b *identityReadBudget) read(r *objectReader, p []byte) (int, error) {
	if b == nil {
		return r.Read(p)
	}
	if b.remaining == 0 && r.count < r.ref.Bytes {
		b.err = ErrLimit
		return 0, ErrLimit
	}
	if b.remaining > 0 && uint64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := r.Read(p)
	b.remaining -= uint64(n)
	b.consumed += uint64(n)
	return n, err
}

type identityIndexReader struct {
	reader *objectReader
	budget *identityReadBudget
}

func (r identityIndexReader) Read(p []byte) (int, error) {
	return r.budget.read(r.reader, p)
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
	return s.readIdentity(ctx, name, nil)
}

// ReadIdentityLimited bounds both index passes and all original-object reads.
// Catalog acquisition is separate. Consumed is returned even on failure.
func (s *Snapshot) ReadIdentityLimited(ctx context.Context, name string, remaining uint64) (intel.SnapshotNPMEvidence, uint64, error) {
	if remaining > 8<<30 {
		return intel.SnapshotNPMEvidence{}, 0, ErrLimit
	}
	budget := &identityReadBudget{remaining: remaining}
	got, err := s.readIdentity(ctx, name, budget)
	err = errors.Join(err, budget.err)
	if ctx != nil {
		err = errors.Join(err, ctx.Err())
	}
	if err != nil {
		got = intel.SnapshotNPMEvidence{}
	}
	return got, budget.consumed, err
}

func (s *Snapshot) readIdentity(ctx context.Context, name string, budget *identityReadBudget) (intel.SnapshotNPMEvidence, error) {
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
		got, e := intel.ReadSnapshotNPMIdentityWithCatalog(ctx, s.manifest, name, s.catalog, identityIndexReader{block, budget}, originals)
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
		reader := &lazyOriginal{ctx: ctx, store: s.store, ref: ObjectRef{record.SHA256, record.Bytes}, budget: budget}
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

// ErrIdentityWalkStopped lets a callback finish a window without hydrating its
// remaining identities. Close, budget, context and lease failures still fail it.
var ErrIdentityWalkStopped = errors.New("intel: identity-walk-stopped")

// WalkIdentities verifies one complete original index block for a validated
// window, then hydrates and emits one identity at a time. Consumed includes
// actual block/original bytes on every failure path. Callbacks must not retain
// successive evidence or reenter this Snapshot (the generation lock is held).
func (s *Snapshot) WalkIdentities(ctx context.Context, names []string, remaining uint64, emit func(string, intel.SnapshotNPMEvidence) error) (consumed uint64, err error) {
	if remaining > 8<<30 {
		return 0, ErrLimit
	}
	names, index, err := intel.SnapshotNPMIdentityNames(names)
	if err != nil {
		return 0, err
	}
	if s == nil || ctx == nil || emit == nil {
		return 0, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.pin.ID() == (ID{}) {
		return 0, ErrUnavailable
	}
	if err := s.pin.lease.Stable(ctx); err != nil {
		return 0, ErrBinding
	}
	budget := &identityReadBudget{remaining: remaining}
	defer func() {
		consumed = budget.consumed
		err = errors.Join(err, budget.err, ctx.Err(), s.pin.lease.Stable(ctx))
	}()
	reference := s.manifest.Blocks[index].Reference
	block, err := s.store.objectReader(ctx, ObjectRef{reference.SHA256, reference.Bytes})
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, block.Close()) }()
	err = intel.WalkSnapshotNPMIdentitiesWithCatalog(ctx, s.manifest, names, s.catalog, identityIndexReader{block, budget}, func(ref intel.SnapshotObjectReference) (io.ReadCloser, error) {
		return &lazyOriginal{ctx: ctx, store: s.store, ref: ObjectRef{ref.SHA256, ref.Bytes}, budget: budget}, nil
	}, emit)
	if err == ErrIdentityWalkStopped {
		err = nil // Deferred actual-reader close and lease checks still run.
	}
	return budget.consumed, err
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
