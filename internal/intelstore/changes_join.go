package intelstore

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"packtrace/internal/intel"
	"packtrace/internal/jsoninput"
)

type updateAction struct {
	ID     string
	Old    *sourceIDRow
	Change *changeGroup
	Fetch  bool
}

func parseSourceIDRow(raw []byte) (sourceIDRow, error) {
	var row sourceIDRow
	fields, code := jsoninput.Object(raw, 32<<10)
	if code != "" || len(fields) != 4 || !strictObject(raw, 32<<10, "ID", "Modified", "Original", "Disposition") {
		return row, ErrCorrupt
	}
	for _, field := range []struct {
		key string
		out any
	}{{"ID", &row.ID}, {"Modified", &row.Modified}, {"Disposition", &row.Disposition}} {
		if json.Unmarshal(fields[field.key], field.out) != nil {
			return row, ErrCorrupt
		}
	}
	if !publicRecordID(row.ID) || row.Disposition > sourceUnresolved {
		return row, ErrCorrupt
	}
	if row.Modified != "" {
		stamp := intel.ProjectOSVTimestampText(row.Modified)
		if stamp.State != intel.TimestampValue {
			return row, ErrCorrupt
		}
	}
	ref, e := parseObjectRef(fields["Original"], false)
	if e != nil || ref.Bytes > 4<<20 {
		return row, ErrCorrupt
	}
	row.Original = ref
	return row, nil
}

type sourceIDCursor struct {
	scan  *bufio.Scanner
	last  string
	count uint64
}

func newSourceIDCursor(input io.Reader) *sourceIDCursor {
	scan := bufio.NewScanner(input)
	scan.Buffer(make([]byte, 4096), 32<<10)
	return &sourceIDCursor{scan: scan}
}
func (c *sourceIDCursor) next() (*sourceIDRow, error) {
	if !c.scan.Scan() {
		if e := c.scan.Err(); e != nil {
			return nil, e
		}
		return nil, nil
	}
	if c.count >= 2_000_000 {
		return nil, ErrLimit
	}
	row, e := parseSourceIDRow(c.scan.Bytes())
	if e != nil || row.ID <= c.last {
		return nil, ErrCorrupt
	}
	c.last = row.ID
	c.count++
	return &row, nil
}

type changeGroupCursor struct {
	scan *bufio.Scanner
	last string
}

func (c *changeGroupCursor) next() (*changeGroup, error) {
	if !c.scan.Scan() {
		if e := c.scan.Err(); e != nil {
			return nil, e
		}
		return nil, nil
	}
	if !strictObject(c.scan.Bytes(), 32<<10, "ID", "Modified", "NPM", "Empty", "Other") {
		return nil, ErrCorrupt
	}
	var row changeGroup
	if json.Unmarshal(c.scan.Bytes(), &row) != nil || !listingRecordID(row.ID) || row.NPM && !publicRecordID(row.ID) || row.ID <= c.last || !row.NPM && !row.Empty && !row.Other {
		return nil, ErrCorrupt
	}
	stamp := intel.ProjectOSVTimestampText(row.Modified)
	if stamp.State != intel.TimestampValue {
		return nil, ErrCorrupt
	}
	c.last = row.ID
	return &row, nil
}
func joinSourceChanges(ctx context.Context, old, changes io.Reader, emit func(updateAction) error) error {
	if ctx == nil || old == nil || changes == nil || emit == nil {
		return ErrUnavailable
	}
	oldBound := &io.LimitedReader{R: old, N: (512 << 20) + 1}
	changeBound := &io.LimitedReader{R: changes, N: (512 << 20) + 1}
	oldScan, changeScan := bufio.NewScanner(oldBound), bufio.NewScanner(changeBound)
	oldScan.Buffer(make([]byte, 4096), 32<<10)
	changeScan.Buffer(make([]byte, 4096), 32<<10)
	previous := &sourceIDCursor{scan: oldScan}
	next := &changeGroupCursor{scan: changeScan}
	left, e := previous.next()
	if e != nil {
		return e
	}
	right, e := next.next()
	if e != nil {
		return e
	}
	var count uint64
	for left != nil || right != nil {
		if e := ctx.Err(); e != nil {
			return e
		}
		var action updateAction
		if right == nil || left != nil && left.ID < right.ID {
			action = updateAction{ID: left.ID, Old: left, Fetch: left.Disposition == sourceUnresolved}
			left, e = previous.next()
		} else if left == nil || right.ID < left.ID {
			if right.NPM {
				action = updateAction{ID: right.ID, Change: right, Fetch: true}
			}
			right, e = next.next()
		} else {
			action = updateAction{ID: left.ID, Old: left, Change: right, Fetch: true}
			left, e = previous.next()
			if e == nil {
				right, e = next.next()
			}
		}
		if e != nil {
			return e
		}
		if action.ID == "" {
			continue
		}
		if count >= 2_000_000 {
			return ErrLimit
		}
		count++
		if e := emit(action); e != nil {
			return e
		}
	}
	if oldBound.N <= 0 || changeBound.N <= 0 {
		return ErrLimit
	}
	return nil
}
