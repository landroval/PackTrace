package intelstore

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"

	"packtrace/internal/nativefs"
)

type objectReader struct {
	file  *nativefs.File
	ref   ObjectRef
	sum   hash.Hash
	count uint64
	done  bool
}

func (s *Store) objectReader(ctx context.Context, ref ObjectRef) (*objectReader, error) {
	if ref.Bytes > 512<<20 {
		return nil, ErrLimit
	}
	f, e := s.root.OpenInput(ctx, objectPath(ref), int64(ref.Bytes))
	if e != nil {
		return nil, ErrCorrupt
	}
	return &objectReader{file: f, ref: ref, sum: sha256.New()}, nil
}
func (r *objectReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	n, e := r.file.Read(p)
	if n > 0 {
		r.sum.Write(p[:n])
		r.count += uint64(n)
	}
	if errors.Is(e, io.EOF) {
		r.done = true
		st, cl := r.file.Stable(), r.file.Close()
		if st != nil || cl != nil || r.count != r.ref.Bytes || !bytes.Equal(r.sum.Sum(nil), r.ref.SHA256[:]) {
			return n, ErrCorrupt
		}
	}
	return n, e
}
func (r *objectReader) Close() error {
	if r == nil || r.done {
		return nil
	}
	r.done = true
	return r.file.Close()
}

type concatenated struct {
	ctx     context.Context
	store   *Store
	refs    []ObjectRef
	at      int
	current *objectReader
}

func (r *concatenated) Read(p []byte) (int, error) {
	for {
		if r.current == nil {
			if r.at == len(r.refs) {
				return 0, io.EOF
			}
			next, e := r.store.objectReader(r.ctx, r.refs[r.at])
			if e != nil {
				return 0, e
			}
			r.at++
			r.current = next
		}
		n, e := r.current.Read(p)
		if errors.Is(e, io.EOF) {
			r.current = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, e
	}
}
func (r *concatenated) Close() error {
	if r.current != nil {
		return r.current.Close()
	}
	return nil
}
func concatObjects(ctx context.Context, t *Transaction, refs []ObjectRef) (ObjectRef, error) {
	var size uint64
	for _, v := range refs {
		if v.Bytes > 512<<20-size {
			return ObjectRef{}, ErrLimit
		}
		size += v.Bytes
	}
	reader := &concatenated{ctx: ctx, store: t.store, refs: refs}
	ref, e := t.put(ctx, reader, size)
	return ref, errors.Join(e, reader.Close())
}

type indexCursor struct {
	reader  *objectReader
	scanner *bufio.Scanner
	row     indexRow
	raw     []byte
	decode  func([]byte) (indexRow, error)
}
type rowHeap []*indexCursor

func (h rowHeap) Len() int           { return len(h) }
func (h rowHeap) Less(i, j int) bool { return rowLess(h[i].row, h[j].row) }
func (h rowHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *rowHeap) Push(v any)        { *h = append(*h, v.(*indexCursor)) }
func (h *rowHeap) Pop() any          { old := *h; v := old[len(old)-1]; *h = old[:len(old)-1]; return v }
func (c *indexCursor) advance() (bool, error) {
	if !c.scanner.Scan() {
		if e := c.scanner.Err(); e != nil {
			return false, e
		}
		return false, nil
	}
	c.raw = append(c.raw[:0], c.scanner.Bytes()...)
	var err error
	c.row, err = c.decode(c.raw)
	if err != nil {
		return false, err
	}
	return true, nil
}

type mergedRows struct {
	cursors []*indexCursor
	queue   rowHeap
	pending []byte
	failed  error
}

func newMergedRows(ctx context.Context, s *Store, refs []ObjectRef) (*mergedRows, error) {
	return newSortedRows(ctx, s, refs, func(raw []byte) (indexRow, error) {
		var row indexRow
		if json.Unmarshal(raw, &row) != nil {
			return row, ErrCorrupt
		}
		return row, nil
	})
}
func newSortedRows(ctx context.Context, s *Store, refs []ObjectRef, decode func([]byte) (indexRow, error)) (*mergedRows, error) {
	if len(refs) > 32 {
		return nil, ErrLimit
	}
	m := &mergedRows{}
	for _, ref := range refs {
		reader, e := s.objectReader(ctx, ref)
		if e != nil {
			m.Close()
			return nil, e
		}
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		c := &indexCursor{reader: reader, scanner: scanner, decode: decode}
		m.cursors = append(m.cursors, c)
		ok, e := c.advance()
		if e != nil {
			m.Close()
			return nil, e
		}
		if ok {
			heap.Push(&m.queue, c)
		}
	}
	return m, nil
}
func (m *mergedRows) Read(p []byte) (int, error) {
	if m.failed != nil {
		return 0, m.failed
	}
	if len(m.pending) == 0 {
		if len(m.queue) == 0 {
			return 0, io.EOF
		}
		c := heap.Pop(&m.queue).(*indexCursor)
		m.pending = append(append(m.pending[:0], c.raw...), '\n')
		ok, e := c.advance()
		if e != nil {
			m.failed = e
			return 0, e
		}
		if ok {
			heap.Push(&m.queue, c)
		}
	}
	n := copy(p, m.pending)
	m.pending = m.pending[n:]
	return n, nil
}
func (m *mergedRows) Close() error {
	var e error
	for _, c := range m.cursors {
		e = errors.Join(e, c.reader.Close())
	}
	return e
}
func mergePartition(ctx context.Context, t *Transaction, refs []ObjectRef) (ObjectRef, error) {
	if len(refs) == 0 {
		return t.put(ctx, bytes.NewReader(nil), 0)
	}
	if len(refs) == 1 {
		return refs[0], nil
	}
	for len(refs) > 1 {
		var next []ObjectRef
		for i := 0; i < len(refs); i += 32 {
			end := i + 32
			if end > len(refs) {
				end = len(refs)
			}
			group := refs[i:end]
			var size uint64
			for _, r := range group {
				if r.Bytes > 512<<20-size {
					return ObjectRef{}, ErrLimit
				}
				size += r.Bytes
			}
			m, e := newMergedRows(ctx, t.store, group)
			if e != nil {
				return ObjectRef{}, e
			}
			ref, e := t.put(ctx, m, size)
			closeErr := m.Close()
			if e != nil || closeErr != nil {
				return ObjectRef{}, errors.Join(e, closeErr)
			}
			next = append(next, ref)
		}
		refs = next
	}
	return refs[0], nil
}
func buildIndexes(ctx context.Context, t *Transaction) (generationDraft, error) {
	if t == nil || t.prep == nil {
		return generationDraft{}, ErrCorrupt
	}
	p := t.prep
	if e := p.flush(ctx, t); e != nil {
		return generationDraft{}, e
	}
	catalog, e := concatObjects(ctx, t, p.catRuns)
	if e != nil {
		return generationDraft{}, e
	}
	sourceIDs, e := concatObjects(ctx, t, p.idRuns)
	if e != nil {
		return generationDraft{}, e
	}
	p.record.SourceIDs = sourceIDs
	blocks := make([]any, 256)
	objects := []ObjectRef{catalog, sourceIDs}
	empty, e := t.put(ctx, bytes.NewReader(nil), 0)
	if e != nil {
		return generationDraft{}, e
	}
	for i := 0; i < 256; i++ {
		ref := empty
		if len(p.runs[i]) != 0 {
			ref, e = mergePartition(ctx, t, p.runs[i])
			if e != nil {
				return generationDraft{}, e
			}
		}
		objects = append(objects, ref)
		blocks[i] = map[string]any{"index": i, "sha256": hex.EncodeToString(ref.SHA256[:]), "bytes": ref.Bytes, "records": p.counts[i]}
	}
	provenanceBytes, e := json.Marshal(p.record)
	if e != nil {
		return generationDraft{}, ErrCorrupt
	}
	provenance, e := t.put(ctx, bytes.NewReader(provenanceBytes), uint64(len(provenanceBytes)))
	if e != nil {
		return generationDraft{}, e
	}
	objects = append(objects, provenance)
	manifestBytes, e := json.Marshal(map[string]any{"schemaVersion": "1.1", "source": map[string]any{"id": "caller-supplied-osv-npm", "acquisitionMethod": "caller-supplied"}, "originals": map[string]any{"sha256": hex.EncodeToString(catalog.SHA256[:]), "bytes": catalog.Bytes, "records": p.record.Records}, "blocks": blocks})
	if e != nil {
		return generationDraft{}, ErrCorrupt
	}
	manifest, e := t.put(ctx, bytes.NewReader(manifestBytes), uint64(len(manifestBytes)))
	if e != nil {
		return generationDraft{}, e
	}
	objects = append(objects, manifest)
	unique := make(map[[32]byte]uint64, len(objects))
	dedup := objects[:0]
	for _, r := range objects {
		if old, ok := unique[r.SHA256]; ok {
			if old != r.Bytes {
				return generationDraft{}, ErrCorrupt
			}
			continue
		}
		unique[r.SHA256] = r.Bytes
		dedup = append(dedup, r)
	}
	return generationDraft{Manifest: manifest, Objects: dedup, Provenance: provenance}, nil
}
