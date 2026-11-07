package intelstore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"
)

type changeGroup struct {
	ID, Modified      string
	NPM, Empty, Other bool
}
type groupedChanges struct {
	scan    *bufio.Scanner
	look    *changeRow
	ended   bool
	pending []byte
}

func (g *groupedChanges) next() (changeGroup, error) {
	var result changeGroup
	for {
		var row changeRow
		if g.look != nil {
			row = *g.look
			g.look = nil
		} else {
			if g.ended {
				return result, io.EOF
			}
			if !g.scan.Scan() {
				g.ended = true
				if e := g.scan.Err(); e != nil {
					return result, e
				}
				if result.ID == "" {
					return result, io.EOF
				}
				return result, nil
			}
			if json.Unmarshal(g.scan.Bytes(), &row) != nil {
				return result, ErrCorrupt
			}
		}
		if result.ID != "" && row.ID != result.ID {
			if row.ID < result.ID {
				return result, ErrCorrupt
			}
			g.look = &row
			return result, nil
		}
		if result.ID == "" {
			result.ID, result.Modified = row.ID, row.Modified
		} else if result.Modified != row.Modified {
			return result, ErrCorrupt
		}
		switch row.Directory {
		case "npm":
			result.NPM = true
		case "[EMPTY]":
			result.Empty = true
		default:
			result.Other = true
		}
	}
}
func (g *groupedChanges) Read(p []byte) (int, error) {
	if len(g.pending) == 0 {
		row, e := g.next()
		if e != nil {
			return 0, e
		}
		raw, e := json.Marshal(row)
		if e != nil {
			return 0, ErrCorrupt
		}
		g.pending = append(raw, '\n')
	}
	n := copy(p, g.pending)
	g.pending = g.pending[n:]
	return n, nil
}
func collectChanges(ctx context.Context, t *Transaction, input io.Reader, now, cutoff time.Time) (ObjectRef, cursorPoint, error) {
	var rows []changeRow
	var used, total uint64
	var runs []ObjectRef
	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].ID != rows[j].ID {
				return rows[i].ID < rows[j].ID
			}
			return rows[i].Directory < rows[j].Directory
		})
		var data bytes.Buffer
		for _, row := range rows {
			raw, _ := json.Marshal(row)
			data.Write(raw)
			data.WriteByte('\n')
		}
		ref, e := t.put(ctx, bytes.NewReader(data.Bytes()), uint64(data.Len()))
		if e != nil {
			return e
		}
		runs = append(runs, ref)
		total += ref.Bytes
		rows = nil
		used = 0
		if len(runs) > 32 {
			return ErrLimit
		}
		return nil
	}
	point, e := walkChanges(ctx, input, now, func(row changeRow) error {
		// Always replay all ties/overlap, never a timestamp-only ID shortcut.
		stamp := row.Modified
		if !cutoff.IsZero() {
			v, e := time.ParseInLocation(time.RFC3339Nano, stamp, time.UTC)
			if e != nil {
				return ErrCorrupt
			}
			if v.Before(cutoff) {
				return nil
			}
		}
		raw, _ := json.Marshal(row)
		if used+uint64(len(raw)+128) > 64<<20 {
			if e := flush(); e != nil {
				return e
			}
		}
		rows = append(rows, row)
		used += uint64(len(raw) + 128)
		return nil
	})
	if e != nil {
		return ObjectRef{}, cursorPoint{}, e
	}
	if e := flush(); e != nil {
		return ObjectRef{}, cursorPoint{}, e
	}
	merged, e := newSortedRows(ctx, t.store, runs, func(raw []byte) (indexRow, error) {
		var row changeRow
		if json.Unmarshal(raw, &row) != nil {
			return indexRow{}, ErrCorrupt
		}
		return indexRow{IdentityHash: row.ID, Name: row.Directory}, nil
	})
	if e != nil {
		return ObjectRef{}, cursorPoint{}, e
	}
	scan := bufio.NewScanner(merged)
	scan.Buffer(make([]byte, 4096), 32<<10)
	grouped := &groupedChanges{scan: scan}
	bound := total*4 + 1024
	if bound > 512<<20 {
		bound = 512 << 20
	}
	ref, e := t.put(ctx, grouped, bound)
	e = errors.Join(e, merged.Close())
	if e != nil {
		return ObjectRef{}, cursorPoint{}, e
	}
	return ref, point, nil
}
