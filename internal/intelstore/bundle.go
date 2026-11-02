package intelstore

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"packtrace/internal/intel"
	"time"
)

type ImportOptions struct{ TrustedSnapshotDigest string }

func parseSnapshotPin(text string) (ID, error) {
	id, e := intel.ParseSnapshotDigest(text)
	if e != nil {
		return ID{}, ErrUntrusted
	}
	return ID(id), nil
}
func parseObjectRef(raw []byte, optional bool) (ObjectRef, error) {
	var result ObjectRef
	if !strictObject(raw, 1024, "SHA256", "Bytes") {
		return result, ErrCorrupt
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return result, ErrCorrupt
	}
	var digest []byte
	value := bytes.TrimSpace(fields["SHA256"])
	if len(value) == 0 || value[0] != '[' || json.Unmarshal(value, &digest) != nil || len(digest) != 32 || json.Unmarshal(fields["Bytes"], &result.Bytes) != nil || result.Bytes > 512<<20 {
		return result, ErrCorrupt
	}
	copy(result.SHA256[:], digest)
	if result.SHA256 == ([32]byte{}) && (!optional || result.Bytes != 0) {
		return ObjectRef{}, ErrCorrupt
	}
	return result, nil
}
func parseGenerationDescriptor(raw []byte) (generationDescriptor, error) {
	var result generationDescriptor
	if !strictObject(raw, 4096, "Version", "Manifest", "ObjectSet", "Cursor", "Provenance") {
		return result, ErrCorrupt
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(fields["Version"], &result.Version) != nil || result.Version != 1 {
		return result, ErrCorrupt
	}
	for _, field := range []struct {
		key      string
		ref      *ObjectRef
		optional bool
	}{{"Manifest", &result.Manifest, false}, {"ObjectSet", &result.ObjectSet, false}, {"Cursor", &result.Cursor, true}, {"Provenance", &result.Provenance, true}} {
		ref, e := parseObjectRef(fields[field.key], field.optional)
		if e != nil {
			return generationDescriptor{}, e
		}
		*field.ref = ref
	}
	return result, nil
}

type objectSetCursor struct {
	input *objectReader
	scan  *bufio.Scanner
	last  [32]byte
	have  bool
	count uint64
}

func (s *Store) openObjectSet(ctx context.Context, ref ObjectRef) (*objectSetCursor, error) {
	r, e := s.objectReader(ctx, ref)
	if e != nil {
		return nil, e
	}
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 4096), 1024)
	return &objectSetCursor{input: r, scan: scan}, nil
}
func (c *objectSetCursor) next() (ObjectRef, bool, error) {
	if !c.scan.Scan() {
		return ObjectRef{}, false, c.scan.Err()
	}
	ref, e := parseObjectSetLine(c.scan.Bytes())
	if e != nil || c.have && bytes.Compare(ref.SHA256[:], c.last[:]) <= 0 {
		return ObjectRef{}, false, ErrCorrupt
	}
	if c.count >= 2_001_024 {
		return ObjectRef{}, false, ErrLimit
	}
	c.count++
	c.last = ref.SHA256
	c.have = true
	return ref, true, nil
}
func (c *objectSetCursor) Close() error { return c.input.Close() }

type bundleWriter struct {
	ctx  context.Context
	out  io.Writer
	used uint64
}

func (w *bundleWriter) Write(p []byte) (int, error) {
	if e := w.ctx.Err(); e != nil {
		return 0, e
	}
	if uint64(len(p)) > (16<<30)-w.used {
		return 0, ErrLimit
	}
	n, e := w.out.Write(p)
	if n < 0 || n > len(p) {
		return 0, ErrCorrupt
	}
	w.used += uint64(n)
	if e != nil || n != len(p) {
		return n, ErrUnavailable
	}
	return n, nil
}

// Export streams only a pinned generation. Arbitrary caller Writer code can
// block; production callers still require the terminable preparation role.
func (s *Store) Export(ctx context.Context, snapshot *Snapshot, out io.Writer) (failure error) {
	if s == nil || snapshot == nil || ctx == nil || out == nil {
		return ErrUnavailable
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	work, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	ctx = work
	snapshot.mu.Lock()
	defer snapshot.mu.Unlock()
	if snapshot.closed || snapshot.store != s {
		return ErrBinding
	}
	if e := snapshot.pin.lease.Stable(ctx); e != nil {
		return e
	}
	descriptorRaw, e := s.readRef(ctx, snapshot.descriptorRef, 4096)
	if e != nil {
		return e
	}
	manifestRaw, e := s.readRef(ctx, snapshot.descriptor.Manifest, 1<<20)
	if e != nil {
		return e
	}
	// Preflight the exact finite object set and padded USTAR footprint before
	// touching caller output. A later I/O failure is still a failed export.
	footprint := uint64(1024)
	members := uint64(3)
	add := func(n uint64) bool {
		padded := uint64(512) + ((n+511)/512)*512
		if padded > (16<<30)-footprint {
			return false
		}
		footprint += padded
		return true
	}
	for _, n := range []uint64{uint64(len(descriptorRaw)), uint64(len(manifestRaw)), snapshot.descriptor.ObjectSet.Bytes} {
		if !add(n) {
			return ErrLimit
		}
	}
	set, e := s.openObjectSet(ctx, snapshot.descriptor.ObjectSet)
	if e != nil {
		return e
	}
	for {
		ref, ok, e := set.next()
		if e != nil {
			set.Close()
			return e
		}
		if !ok {
			break
		}
		members++
		if members > 2_001_024 || !add(ref.Bytes) {
			set.Close()
			return ErrLimit
		}
	}
	if e := set.Close(); e != nil {
		return e
	}
	writer := &bundleWriter{ctx: ctx, out: out}
	archive := tar.NewWriter(writer)
	header := func(name string, size uint64) error {
		return archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(size), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0).UTC()})
	}
	control := func(name string, data []byte) error {
		if e := header(name, uint64(len(data))); e != nil {
			return e
		}
		_, e := archive.Write(data)
		return e
	}
	if e := control("descriptor.json", descriptorRaw); e != nil {
		return e
	}
	if e := control("manifest.json", manifestRaw); e != nil {
		return e
	}
	object := func(name string, ref ObjectRef) error {
		if e := header(name, ref.Bytes); e != nil {
			return e
		}
		r, e := s.objectReader(ctx, ref)
		if e != nil {
			return e
		}
		n, e := io.Copy(archive, r)
		closeErr := r.Close()
		if e != nil || closeErr != nil || uint64(n) != ref.Bytes {
			return errors.Join(ErrCorrupt, e, closeErr)
		}
		return nil
	}
	if e := object("object-set", snapshot.descriptor.ObjectSet); e != nil {
		return e
	}
	set, e = s.openObjectSet(ctx, snapshot.descriptor.ObjectSet)
	if e != nil {
		return e
	}
	defer func() { failure = errors.Join(failure, set.Close()) }()
	for {
		ref, ok, e := set.next()
		if e != nil {
			return e
		}
		if !ok {
			break
		}
		if e := object("objects/"+hex.EncodeToString(ref.SHA256[:]), ref); e != nil {
			return e
		}
	}
	if e := archive.Close(); e != nil {
		return e
	}
	if writer.used != footprint {
		return ErrCorrupt
	}
	return snapshot.pin.lease.Stable(ctx)
}
