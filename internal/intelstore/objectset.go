package intelstore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
)

func parseObjectSetLine(raw []byte) (ObjectRef, error) {
	parts := strings.Split(string(raw), " ")
	if len(parts) != 3 || parts[0] != "1" {
		return ObjectRef{}, ErrCorrupt
	}
	id, e := parseID(parts[1])
	if e != nil {
		return ObjectRef{}, e
	}
	n, e := strconv.ParseUint(parts[2], 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != parts[2] || n > 512<<20 {
		return ObjectRef{}, ErrCorrupt
	}
	return ObjectRef{[32]byte(id), n}, nil
}
func refSortRow(raw []byte) (indexRow, error) {
	r, e := parseObjectSetLine(raw)
	if e != nil {
		return indexRow{}, e
	}
	return indexRow{IdentityHash: hex.EncodeToString(r.SHA256[:])}, nil
}

type verifiedRefSet struct {
	ctx     context.Context
	store   *Store
	scan    *bufio.Scanner
	last    ObjectRef
	have    bool
	count   uint64
	pending []byte
}

func (r *verifiedRefSet) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if !r.scan.Scan() {
			if e := r.scan.Err(); e != nil {
				return 0, e
			}
			return 0, io.EOF
		}
		current, e := parseObjectSetLine(r.scan.Bytes())
		if e != nil {
			return 0, e
		}
		if r.have {
			comparison := bytes.Compare(current.SHA256[:], r.last.SHA256[:])
			if comparison < 0 || comparison == 0 && current.Bytes != r.last.Bytes {
				return 0, ErrCorrupt
			}
			if comparison == 0 {
				continue
			}
		}
		if r.count >= 2_001_024 {
			return 0, ErrLimit
		}
		if e := r.store.verifyRef(r.ctx, current); e != nil {
			return 0, e
		}
		r.count++
		r.last = current
		r.have = true
		r.pending = append(append(r.pending[:0], r.scan.Bytes()...), '\n')
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// Original reachability is derived from the bounded catalog, not a caller's
// possibly incomplete list or a million-element heap slice. At most65536 refs
// are sorted per run; the total2M+1024 ceiling needs no more than32 merge heads.
func (t *Transaction) buildObjectSetLocked(ctx context.Context, catalog ObjectRef, records uint64, extras []ObjectRef) (ObjectRef, error) {
	if records > 2_000_000 || len(extras) > 1024 {
		return ObjectRef{}, ErrLimit
	}
	var refs []ObjectRef
	var runs []ObjectRef
	flush := func() error {
		if len(refs) == 0 {
			return nil
		}
		sort.Slice(refs, func(i, j int) bool { return bytes.Compare(refs[i].SHA256[:], refs[j].SHA256[:]) < 0 })
		var length uint64
		for _, r := range refs {
			length += uint64(68 + len(strconv.FormatUint(r.Bytes, 10)))
		}
		run, e := t.putLocked(ctx, &refLines{refs: refs}, length)
		if e != nil {
			return e
		}
		runs = append(runs, run)
		if len(runs) > 32 {
			return ErrLimit
		}
		refs = nil
		return nil
	}
	input, e := t.store.objectReader(ctx, catalog)
	if e != nil {
		return ObjectRef{}, e
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	var ordinal uint64
	for scanner.Scan() {
		if ordinal >= records || !strictObject(scanner.Bytes(), 1<<20, "v", "sourceOrdinal", "sha256", "bytes") {
			input.Close()
			return ObjectRef{}, ErrCorrupt
		}
		var row struct {
			V       int    `json:"v"`
			Ordinal uint64 `json:"sourceOrdinal"`
			SHA     string `json:"sha256"`
			Bytes   uint64 `json:"bytes"`
		}
		if json.Unmarshal(scanner.Bytes(), &row) != nil || row.V != 1 || row.Ordinal != ordinal || row.Bytes > 4<<20 {
			input.Close()
			return ObjectRef{}, ErrCorrupt
		}
		id, e := parseID(row.SHA)
		if e != nil {
			input.Close()
			return ObjectRef{}, e
		}
		refs = append(refs, ObjectRef{[32]byte(id), row.Bytes})
		ordinal++
		if len(refs) == 65536 {
			if e := flush(); e != nil {
				input.Close()
				return ObjectRef{}, e
			}
		}
	}
	readErr, closeErr := scanner.Err(), input.Close()
	if readErr != nil || closeErr != nil || ordinal != records {
		return ObjectRef{}, ErrCorrupt
	}
	for _, r := range extras {
		refs = append(refs, r)
		if len(refs) == 65536 {
			if e := flush(); e != nil {
				return ObjectRef{}, e
			}
		}
	}
	if e := flush(); e != nil {
		return ObjectRef{}, e
	}
	merged, e := newSortedRows(ctx, t.store, runs, refSortRow)
	if e != nil {
		return ObjectRef{}, e
	}
	scan := bufio.NewScanner(merged)
	scan.Buffer(make([]byte, 64<<10), 1024)
	verified := &verifiedRefSet{ctx: ctx, store: t.store, scan: scan}
	var length uint64
	for _, run := range runs {
		length += run.Bytes
	}
	result, e := t.putLocked(ctx, verified, length)
	return result, errors.Join(e, merged.Close())
}
