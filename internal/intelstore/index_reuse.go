package intelstore

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"

	"packtrace/internal/intel"
	"packtrace/internal/nativefs"
)

// inBase distinguishes a previous-known record missing from a full archive
// from a changed record already represented by this candidate's catalog.
type indexUpdateAction struct {
	updateAction
	inBase bool
}
type indexActionWalk func(func(indexUpdateAction) error) error

// Each spool retains at most12MiB; fresh projection runs flush below32MiB.
// Together with one changed record and parser scratch they stay below the
// existing64MiB run working allowance. Files/residues retain normal quota.
type indexMetadataSpool struct {
	buffer bytes.Buffer
	runs   []ObjectRef
}

func (s *indexMetadataSpool) add(ctx context.Context, t *Transaction, row any) error {
	raw, e := json.Marshal(row)
	if e != nil {
		return ErrCorrupt
	}
	if len(raw) > 32<<10 {
		return ErrLimit
	}
	if s.buffer.Len()+len(raw)+1 > 12<<20 {
		if e := s.flush(ctx, t); e != nil {
			return e
		}
	}
	s.buffer.Write(raw)
	s.buffer.WriteByte('\n')
	return nil
}
func (s *indexMetadataSpool) flush(ctx context.Context, t *Transaction) error {
	if s.buffer.Len() == 0 {
		return nil
	}
	if len(s.runs) >= 1024 {
		return ErrLimit
	}
	ref, e := t.put(ctx, bytes.NewReader(s.buffer.Bytes()), uint64(s.buffer.Len()))
	if e != nil {
		return e
	}
	s.runs = append(s.runs, ref)
	s.buffer.Reset()
	return nil
}
func (s *indexMetadataSpool) finish(ctx context.Context, t *Transaction) (ObjectRef, error) {
	if e := s.flush(ctx, t); e != nil {
		return ObjectRef{}, e
	}
	return concatObjects(ctx, t, s.runs)
}

func preparationCounters(p *preparationRecord) []*uint64 {
	return []*uint64{&p.Records, &p.Memberships, &p.IdentityGaps, &p.OutsideNPM, &p.GitHubRecords, &p.OpenSSFRecords, &p.UnknownPublisherRecords, &p.EEFRecords, &p.GSDRecords, &p.TemporalGaps, &p.DispositionGaps}
}
func changePreparationCounters(base *preparationRecord, add, remove preparationRecord) error {
	b, a, r := preparationCounters(base), preparationCounters(&add), preparationCounters(&remove)
	for i := range b {
		if *r[i] > *b[i] {
			return ErrCorrupt
		}
		v := *b[i] - *r[i]
		if *a[i] > ^uint64(0)-v {
			return ErrLimit
		}
		*b[i] = v + *a[i]
	}
	if base.Records > 2_000_000 || base.Memberships > 2_000_000 {
		return ErrLimit
	}
	return nil
}

// The strict row parser is shared with the consumer. A row is not reusable
// until its bucket/order and exact original catalog linkage have also passed.
type indexRowsRewrite struct {
	input                   *objectReader
	scan                    *bufio.Scanner
	catalog                 *intel.SnapshotVerifiedCatalog
	references              []ObjectRef // fresh, bounded changed-record ordinals only
	bucket                  byte
	expected, rows, emitted uint64
	previous                indexRow
	havePrevious            bool
	pending                 []byte
	rewrite                 func(indexRow) (indexRow, bool, error)
}

func newIndexRowsRewrite(ctx context.Context, s *Store, ref ObjectRef, expected uint64, bucket byte, catalog *intel.SnapshotVerifiedCatalog, references []ObjectRef, rewrite func(indexRow) (indexRow, bool, error)) (*indexRowsRewrite, error) {
	input, e := s.objectReader(ctx, ref)
	if e != nil {
		return nil, e
	}
	scan := bufio.NewScanner(input)
	scan.Buffer(make([]byte, 64<<10), 1<<20)
	return &indexRowsRewrite{input: input, scan: scan, catalog: catalog, references: references, bucket: bucket, expected: expected, rewrite: rewrite}, nil
}
func (r *indexRowsRewrite) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if !r.scan.Scan() {
			if e := r.scan.Err(); e != nil {
				return 0, e
			}
			if r.rows != r.expected {
				return 0, ErrCorrupt
			}
			return 0, io.EOF
		}
		parsed, e := intel.ParseSnapshotNPMIndexRow(r.scan.Bytes())
		if e != nil {
			return 0, ErrCorrupt
		}
		row := indexRow(parsed)
		key, e := hex.DecodeString(row.IdentityHash[:2])
		if e != nil || key[0] != r.bucket || r.havePrevious && !rowLess(r.previous, row) {
			return 0, ErrCorrupt
		}
		r.previous, r.havePrevious = row, true
		r.rows++
		if r.rows > r.expected {
			return 0, ErrCorrupt
		}
		var ref ObjectRef
		var ok bool
		if r.catalog != nil {
			ref.SHA256, ref.Bytes, ok = r.catalog.Reference(row.SourceOrdinal)
		} else if row.SourceOrdinal < uint64(len(r.references)) {
			ref, ok = r.references[row.SourceOrdinal], true
		}
		if !ok || row.OriginalBytes != ref.Bytes || row.OriginalSHA256 != hex.EncodeToString(ref.SHA256[:]) {
			return 0, ErrCorrupt
		}
		out, keep, e := r.rewrite(row)
		if e != nil {
			return 0, e
		}
		if !keep {
			continue
		}
		raw, e := json.Marshal(out)
		if e != nil {
			return 0, ErrCorrupt
		}
		r.pending = append(raw, '\n')
		r.emitted++
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
func (r *indexRowsRewrite) Close() error { return r.input.Close() }
func storeRewrittenRows(ctx context.Context, t *Transaction, r *indexRowsRewrite) (ObjectRef, error) {
	// Ordinal decimal growth is bounded by the unchanged512MiB metadata object
	// ceiling. The normal streaming writer detects/charges an overflow sentinel.
	max := r.input.ref.Bytes + r.expected*6 // At most six extra ordinal digits (unchanged2M-record ceiling).
	if max > 512<<20 {
		max = 512 << 20
	}
	ref, e := t.put(ctx, r, max)
	return ref, errors.Join(e, r.Close())
}

// reuseIndexDraft is only for this original writer's prepared candidate or a
// locally authenticated source generation. Import deliberately never calls it:
// untrusted transports must still rebuild every projection from actual originals.
// Hash/order/catalog checks close reused metadata, not publisher authenticity;
// seal independently verifies every mandatory original, including unchanged ones.
func reuseIndexDraft(ctx context.Context, t *Transaction, base generationDraft, prep preparationRecord, inputs []ObjectRef, walk indexActionWalk, fetch sourceFetch) (draft generationDraft, failure error) {
	if t == nil || ctx == nil || walk == nil || fetch == nil || len(inputs) == 0 || len(inputs) > 3 {
		return draft, ErrCorrupt
	}
	// A prior streaming checksum receipt is not authority for a reopened name.
	// Retain the actual metadata objects BEFORE the no-network verification pass;
	// check those same originals before every fetch and at semantic closure.
	var leases []*nativefs.MetadataLease
	defer func() {
		for _, l := range leases {
			failure = errors.Join(failure, l.Close())
		}
		if failure != nil {
			t.mu.Lock()
			t.failed = failure
			t.mu.Unlock()
		}
	}()
	stable := func() error {
		for _, l := range leases {
			if e := l.Stable(); e != nil {
				return ErrBinding
			}
		}
		return nil
	}
	for _, ref := range inputs {
		l, e := t.store.root.OpenMetadata(ctx, objectPath(ref))
		if e != nil {
			return draft, e
		}
		leases = append(leases, l)
		if l.Entry().Kind != nativefs.KindRegular || l.Entry().Size < 0 || uint64(l.Entry().Size) != ref.Bytes {
			return draft, ErrCorrupt
		}
	}
	if e := walk(func(indexUpdateAction) error { return nil }); e != nil {
		return draft, e
	}
	if e := stable(); e != nil {
		return draft, e
	}
	raw, e := t.store.readRef(ctx, base.Manifest, 1<<20)
	if e != nil {
		return draft, e
	}
	manifest, e := intel.ParseSnapshotManifestV11(raw)
	if e != nil || manifest.Originals.Records != prep.Records {
		return draft, ErrCorrupt
	}
	cr, e := t.store.objectReader(ctx, ObjectRef{manifest.Originals.SHA256, manifest.Originals.Bytes})
	if e != nil {
		return draft, e
	}
	catalog, e := intel.ReadSnapshotCatalog(ctx, manifest, cr)
	closeErr := cr.Close()
	if e != nil || closeErr != nil {
		return draft, errors.Join(e, closeErr)
	}
	fresh := &preparationState{record: preparationRecord{Version: 1, Source: "caller-supplied"}}
	t.prep = fresh
	record := prep
	var removed preparationRecord
	var originals, ids indexMetadataSpool
	changed := make(map[uint64]bool)
	var insertions, ordinals []uint64
	var references []ObjectRef
	var oldSeen, total, actions uint64
	e = walk(func(a indexUpdateAction) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if a.inBase {
			if a.Old == nil {
				return ErrCorrupt
			}
			sha, size, ok := catalog.Reference(oldSeen)
			if !ok || a.Old.Original != (ObjectRef{sha, size}) {
				return ErrCorrupt
			}
		} else if !a.Fetch {
			return ErrCorrupt
		}
		var row sourceIDRow
		if a.Fetch {
			if actions >= 9999 {
				return ErrLimit
			}
			actions++
			if e := stable(); e != nil {
				return e
			}
			if a.inBase {
				// Only changed old originals are reprojected to subtract exact gap counts.
				previous := &preparationState{record: preparationRecord{Version: 1, Source: "caller-supplied"}}
				t.prep = previous
				raw, e := t.existingAdvisory(ctx, a.Old.Original)
				if e != nil {
					t.prep = fresh
					return e
				}
				forced := sourceObserved
				if a.Old.Disposition == sourceUnresolved {
					forced = sourceUnresolved
				}
				e = prepareOriginal(ctx, t, a.ID, raw, &a.Old.Original, forced)
				t.prep = fresh
				if e != nil {
					return e
				}
				if previous.last != *a.Old {
					return ErrCorrupt
				}
				if e := changePreparationCounters(&removed, previous.record, preparationRecord{}); e != nil {
					return e
				}
				changed[oldSeen] = true
			}
			if e := applySourceAction(ctx, t, a.updateAction, fetch); e != nil {
				return e
			}
			row = fresh.last
			references = append(references, row.Original)
			ordinals = append(ordinals, total)
			if fresh.buffered > 31<<20 {
				if e := fresh.flush(ctx, t); e != nil {
					return e
				}
			}
		} else {
			row = *a.Old
		}
		if !a.inBase {
			insertions = append(insertions, oldSeen)
		} else {
			oldSeen++
		}
		if total >= 2_000_000 {
			return ErrLimit
		}
		if e := originals.add(ctx, t, struct {
			V       int    `json:"v"`
			Ordinal uint64 `json:"sourceOrdinal"`
			SHA     string `json:"sha256"`
			Bytes   uint64 `json:"bytes"`
		}{1, total, hex.EncodeToString(row.Original.SHA256[:]), row.Original.Bytes}); e != nil {
			return e
		}
		if e := ids.add(ctx, t, row); e != nil {
			return e
		}
		total++
		return nil
	})
	if e != nil {
		return draft, e
	}
	if oldSeen != prep.Records {
		return draft, ErrCorrupt
	}
	if e := stable(); e != nil {
		return draft, e
	}
	if e := changePreparationCounters(&record, fresh.record, removed); e != nil {
		return draft, e
	}
	if record.Records != total {
		return draft, ErrCorrupt
	}
	if e := fresh.flush(ctx, t); e != nil {
		return draft, e
	}
	catalogRef, e := originals.finish(ctx, t)
	if e != nil {
		return draft, e
	}
	sourceIDs, e := ids.finish(ctx, t)
	if e != nil {
		return draft, e
	}
	var blocks [256]ObjectRef
	var counts [256]uint64
	var memberships uint64
	emptyDigest := sha256.Sum256(nil)
	for i := range blocks {
		old := manifest.Blocks[i].Reference
		oldRef := ObjectRef{old.SHA256, old.Bytes}
		// Empty partitions have no rows to remove/remap. Keep their canonical
		// reference; seal still verifies the actual mandatory empty object.
		unchanged := len(changed) == 0 && len(insertions) == 0
		empty := old.Records == 0 && old.Bytes == 0 && old.SHA256 == emptyDigest
		if fresh.counts[i] == 0 && (unchanged || empty) {
			blocks[i], counts[i] = oldRef, old.Records
			memberships += counts[i]
			continue
		}
		rewrite, e := newIndexRowsRewrite(ctx, t.store, oldRef, old.Records, byte(i), catalog, nil, func(row indexRow) (indexRow, bool, error) {
			if changed[row.SourceOrdinal] {
				return row, false, nil
			}
			row.SourceOrdinal += uint64(sort.Search(len(insertions), func(i int) bool { return insertions[i] > row.SourceOrdinal }))
			return row, true, nil
		})
		if e != nil {
			return draft, e
		}
		retained, e := storeRewrittenRows(ctx, t, rewrite)
		if e != nil {
			return draft, e
		}
		refs := []ObjectRef{retained}
		counts[i] = rewrite.emitted
		if fresh.counts[i] != 0 {
			merged, e := mergePartition(ctx, t, fresh.runs[i])
			if e != nil {
				return draft, e
			}
			next, e := newIndexRowsRewrite(ctx, t.store, merged, fresh.counts[i], byte(i), nil, references, func(row indexRow) (indexRow, bool, error) {
				if row.SourceOrdinal >= uint64(len(ordinals)) {
					return row, false, ErrCorrupt
				}
				row.SourceOrdinal = ordinals[row.SourceOrdinal]
				return row, true, nil
			})
			if e != nil {
				return draft, e
			}
			updated, e := storeRewrittenRows(ctx, t, next)
			if e != nil {
				return draft, e
			}
			refs = append(refs, updated)
			counts[i] += next.emitted
		}
		blocks[i], e = mergePartition(ctx, t, refs)
		if e != nil {
			return draft, e
		}
		memberships += counts[i]
	}
	if memberships != record.Memberships {
		return draft, ErrCorrupt
	}
	if e := stable(); e != nil {
		return draft, e
	}
	t.prep = &preparationState{record: record}
	return finishIndexes(ctx, t, record, catalogRef, sourceIDs, blocks, counts)
}
