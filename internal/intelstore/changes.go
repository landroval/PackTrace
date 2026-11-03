package intelstore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"packtrace/internal/intel"
	"strings"
	"time"
	"unicode/utf8"
)

type cursorPoint struct{ Modified, ID string }
type changeRow struct{ Modified, Directory, ID string }

func committedCursor(old, candidate cursorPoint, activated bool) cursorPoint {
	if !activated {
		return old
	}
	return candidate
}
func walkChanges(ctx context.Context, input io.Reader, now time.Time, emit func(changeRow) error) (cursorPoint, error) {
	if ctx == nil || input == nil || emit == nil {
		return cursorPoint{}, ErrUnavailable
	}
	bounded := &io.LimitedReader{R: input, N: (256 << 20) + 1}
	scan := bufio.NewScanner(bounded)
	scan.Buffer(make([]byte, 4096), 4096)
	var point cursorPoint
	var previous time.Time
	havePrevious := false
	var newest time.Time
	var lineReader bytes.Reader
	buffer := bufio.NewReader(&lineReader)
	reader := csv.NewReader(buffer)
	reader.FieldsPerRecord = 2
	reader.ReuseRecord = true
	for scan.Scan() {
		if e := ctx.Err(); e != nil {
			return cursorPoint{}, e
		}
		line := scan.Bytes()
		if len(line) == 0 || !utf8.Valid(line) {
			return cursorPoint{}, ErrCorrupt
		}
		// Preserve the strict single-line grammar and second-read EOF check, but
		// reuse the stdlib parser/buffer instead of allocating a page per row.
		lineReader.Reset(line)
		buffer.Reset(&lineReader)
		fields, e := reader.Read()
		if e != nil {
			return cursorPoint{}, ErrCorrupt
		}
		if _, e := reader.Read(); e != io.EOF {
			return cursorPoint{}, ErrCorrupt
		}
		stamp := intel.ProjectOSVTimestampText(fields[0])
		if stamp.State != intel.TimestampValue || stamp.Value.After(now) || havePrevious && stamp.Value.After(previous) {
			return cursorPoint{}, ErrUntrusted
		}
		previous = stamp.Value
		havePrevious = true
		slash := strings.LastIndexByte(fields[1], '/')
		if slash < 0 {
			return cursorPoint{}, ErrCorrupt
		}
		directory, id := fields[1][:slash], fields[1][slash+1:]
		if len(directory) == 0 || len(directory) > 128 || !publicRecordID(id) {
			return cursorPoint{}, ErrCorrupt
		}
		for _, component := range strings.Split(directory, "/") {
			if component == "" || component == "." || component == ".." || strings.ContainsAny(component, "\\\x00\r\n") {
				return cursorPoint{}, ErrCorrupt
			}
		}
		modified := stamp.Value.Format(time.RFC3339Nano)
		row := changeRow{modified, directory, id}
		if point.Modified == "" || stamp.Value.After(newest) || stamp.Value.Equal(newest) && id > point.ID {
			newest = stamp.Value
			point = cursorPoint{modified, id}
		}
		if e := emit(row); e != nil {
			return cursorPoint{}, e
		}
	}
	if scan.Err() != nil {
		return cursorPoint{}, ErrCorrupt
	}
	if bounded.N <= 0 {
		return cursorPoint{}, ErrLimit
	}
	return point, nil
}
