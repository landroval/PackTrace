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
	"strconv"
)

type generationDraft struct {
	Manifest           ObjectRef
	Objects            []ObjectRef
	Cursor, Provenance ObjectRef
}
type generationDescriptor struct {
	Version                                 int
	Manifest, ObjectSet, Cursor, Provenance ObjectRef
}
type sealedHeader struct {
	Version    int       `json:"version"`
	ID         string    `json:"id"`
	Descriptor ObjectRef `json:"descriptor"`
}
type sealedGeneration struct {
	header sealedHeader
	digest [32]byte
}

func objectPath(ref ObjectRef) string {
	key := hex.EncodeToString(ref.SHA256[:])
	return "objects/" + key[:2] + "/" + key
}
func zeroRef(r ObjectRef) bool { return r == (ObjectRef{}) }

func (s *Store) readRef(ctx context.Context, ref ObjectRef, cap uint64) ([]byte, error) {
	if ref.Bytes > cap || cap > 512<<20 {
		return nil, ErrLimit
	}
	f, e := s.root.OpenInput(ctx, objectPath(ref), int64(ref.Bytes))
	if e != nil {
		return nil, ErrCorrupt
	}
	data, e := io.ReadAll(f)
	stable, closed := f.Stable(), f.Close()
	if e != nil || stable != nil || closed != nil || uint64(len(data)) != ref.Bytes || sha256.Sum256(data) != ref.SHA256 {
		return nil, ErrCorrupt
	}
	return data, nil
}
func (s *Store) verifyRef(ctx context.Context, ref ObjectRef) error {
	if ref.Bytes > 512<<20 {
		return ErrLimit
	}
	f, e := s.root.OpenInput(ctx, objectPath(ref), int64(ref.Bytes))
	if e != nil {
		return ErrCorrupt
	}
	h := sha256.New()
	n, e := io.Copy(h, f)
	stable, closed := f.Stable(), f.Close()
	if e != nil || stable != nil || closed != nil || uint64(n) != ref.Bytes || !bytes.Equal(h.Sum(nil), ref.SHA256[:]) {
		return ErrCorrupt
	}
	return nil
}

type refLines struct {
	refs    []ObjectRef
	index   int
	pending []byte
}

func (r *refLines) Read(p []byte) (int, error) {
	if len(r.pending) == 0 {
		if r.index == len(r.refs) {
			return 0, io.EOF
		}
		v := r.refs[r.index]
		r.index++
		r.pending = []byte("1 " + hex.EncodeToString(v.SHA256[:]) + " " + strconv.FormatUint(v.Bytes, 10) + "\n")
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
func (t *Transaction) writeImmutable(ctx context.Context, path string, data []byte) error {
	if uint64(len(data))+4096 > t.held {
		return ErrLimit
	}
	// Existing immutable bytes may only be reused after the original lease and
	// exact expected payload are verified; a same-named file is not enough.
	meta, e := t.store.root.OpenMetadata(ctx, path)
	if e == nil {
		e = errors.Join(meta.Stable(), meta.Close())
		if e != nil {
			return ErrCorrupt
		}
		f, e := t.store.root.OpenInput(ctx, path, int64(len(data)))
		if e != nil {
			return ErrCorrupt
		}
		b, e := io.ReadAll(f)
		st, cl := f.Stable(), f.Close()
		if e != nil || st != nil || cl != nil || !bytes.Equal(b, data) {
			return ErrCorrupt
		}
		return nil
	}
	f, e := t.store.owner.CopyExclusive(ctx, path, bytes.NewReader(data), uint64(len(data)))
	if f != nil {
		n := uint64(f.Size())
		if n > t.held {
			f.Close()
			return ErrLimit
		}
		t.held -= n
		t.written += n
		if e == nil {
			e = f.Stable()
		}
		e = errors.Join(e, f.Close())
	}
	if e != nil {
		return ErrUnavailable
	}
	return nil
}

func (t *Transaction) seal(ctx context.Context, draft generationDraft) (ID, error) {
	if t == nil {
		return ID{}, ErrCorrupt
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.failed != nil || ctx == nil || t.work.Err() != nil || ctx.Err() != nil || len(draft.Objects) > 1024 {
		return ID{}, ErrCorrupt
	}
	// The manifest and every object actually present are checked under this
	// original exclusive writer. This is storage closure, not source authenticity.
	set := make(map[[32]byte]uint64, len(draft.Objects))
	refs := append([]ObjectRef(nil), draft.Objects...)
	for _, v := range refs {
		if old, ok := set[v.SHA256]; ok {
			if old != v.Bytes {
				return ID{}, ErrCorrupt
			}
			return ID{}, ErrCorrupt
		}
		set[v.SHA256] = v.Bytes
		if e := t.store.verifyRef(t.work, v); e != nil {
			return ID{}, e
		}
	}
	contains := func(v ObjectRef) bool { n, ok := set[v.SHA256]; return ok && n == v.Bytes }
	if !contains(draft.Manifest) || !zeroRef(draft.Cursor) && !contains(draft.Cursor) || !zeroRef(draft.Provenance) && !contains(draft.Provenance) {
		return ID{}, ErrCorrupt
	}
	raw, e := t.store.readRef(t.work, draft.Manifest, 1<<20)
	if e != nil {
		return ID{}, e
	}
	manifest, e := intel.ParseSnapshotManifestV11(raw)
	if e != nil {
		return ID{}, ErrCorrupt
	}
	if !contains(ObjectRef{manifest.Originals.SHA256, manifest.Originals.Bytes}) {
		return ID{}, ErrCorrupt
	}
	for _, b := range manifest.Blocks {
		if !contains(ObjectRef{b.Reference.SHA256, b.Reference.Bytes}) {
			return ID{}, ErrCorrupt
		}
	}
	objectSet, e := t.buildObjectSetLocked(t.work, ObjectRef{manifest.Originals.SHA256, manifest.Originals.Bytes}, manifest.Originals.Records, refs)
	if e != nil {
		return ID{}, e
	}
	descriptor := generationDescriptor{1, draft.Manifest, objectSet, draft.Cursor, draft.Provenance}
	encoded, e := json.Marshal(descriptor)
	if e != nil {
		return ID{}, ErrCorrupt
	}
	descriptorRef, e := t.putLocked(t.work, bytes.NewReader(encoded), uint64(len(encoded)))
	if e != nil {
		return ID{}, e
	}
	id := ID(descriptorRef.SHA256)
	key := hex.EncodeToString(id[:])
	base := "generations/" + key
	if e := t.store.owner.Mkdir(t.work, base); e != nil {
		return ID{}, ErrUnavailable
	}
	if e := t.writeImmutable(t.work, base+"/manifest.json", raw); e != nil {
		return ID{}, e
	}
	if e := t.writeImmutable(t.work, base+"/read.lock", nil); e != nil {
		return ID{}, e
	}
	header := sealedHeader{1, key, descriptorRef}
	body, e := json.Marshal(header)
	if e != nil || len(body) > 4096 {
		return ID{}, ErrCorrupt
	}
	if e := t.writeImmutable(t.work, base+"/sealed.json", body); e != nil {
		return ID{}, e
	}
	if t.sealed == nil {
		t.sealed = make(map[ID]sealedGeneration)
	}
	t.sealed[id] = sealedGeneration{header, sha256.Sum256(body)}
	return id, nil
}
