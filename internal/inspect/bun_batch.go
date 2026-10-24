package inspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"packtrace/internal/inventory"
	"packtrace/internal/jsoninput"
)

// ReadBunBatch preflights one supplied text bun.lock and every advisory before
// reusing ReadBun per record. Whole-wire, lockfile and budget failures are fatal
// and private; an unusable advisory is a positional gap, not a dropped sibling.
func ReadBunBatch(in io.Reader) (BatchResult, error) {
	data, e := io.ReadAll(io.LimitReader(in, maxWireBytes+1))
	if e != nil {
		return BatchResult{}, errors.New("inspect-bun-batch: read-failed")
	}
	if len(data) > maxWireBytes {
		return BatchResult{}, errors.New("inspect-bun-batch: limit-exceeded")
	}
	fields, code := jsoninput.Object(data, maxWireBytes)
	if code != "" || len(fields) != 2 {
		return BatchResult{}, errors.New("inspect-bun-batch: invalid-input")
	}
	var text string
	var ads []json.RawMessage
	if json.Unmarshal(fields["lockfile_text"], &text) != nil || text == "" || json.Unmarshal(fields["advisories"], &ads) != nil || len(ads) == 0 {
		return BatchResult{}, errors.New("inspect-bun-batch: invalid-input")
	}
	if len(ads) > 16 {
		return BatchResult{}, errors.New("inspect-bun-batch: limit-exceeded")
	}
	locked, e := inventory.ParseBunLock([]byte(text))
	if e != nil {
		return BatchResult{}, errors.New("inspect-bun-batch: invalid-lockfile")
	}
	// Same lockfile caps as ReadBun, checked once instead of per advisory.
	if len(locked.Packages) > 64 || len(locked.Workspaces) > 64 {
		return BatchResult{}, errors.New("inspect-bun-batch: limit-exceeded")
	}
	projected, e := inventory.ProjectBunLock(locked)
	if e != nil {
		return BatchResult{}, errors.New("inspect-bun-batch: invalid-lockfile")
	}
	count := 0
	for _, r := range projected.Records {
		if r.Kind != inventory.BunKindRoot {
			count++
		}
	}
	usable, ok := preflightAdvisories(ads, count)
	if !ok {
		return BatchResult{}, errors.New("inspect-bun-batch: limit-exceeded")
	}
	result := newBatchResult("packtrace.inspect.bun-batch.v1", count)
	for i, raw := range ads {
		appendBatchAdvisory(&result, usable[i], func() (Result, error) {
			packet := append([]byte(`{"lockfile_text":`), fields["lockfile_text"]...)
			packet = append(packet, []byte(`,"advisory":`)...)
			packet = append(packet, raw...)
			packet = append(packet, '}')
			return ReadBun(bytes.NewReader(packet))
		})
	}
	return result, nil
}
