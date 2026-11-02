package intelstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"packtrace/internal/jsoninput"
	"packtrace/internal/nativefs"
	"strings"
)

// An acquired original EX writer lease excludes every legitimate earlier writer.
// Complete native lengths establish retained bytes; no old PID is reopened, no
// death/cleanup is inferred, and nothing is deleted to release unused capacity.
func (s *Store) reconcileReservations(ctx context.Context, writer *nativefs.OwnedLock) error {
	if writer.Matches(ctx, s.root, "writer.lock", true) != nil {
		return ErrUnavailable
	}
	dir, e := s.root.OpenDirectoryMetadata(ctx, "staging")
	if e != nil {
		return ErrUnavailable
	}
	defer dir.Close()
	for {
		batch, e := dir.Next()
		if e != nil && !errors.Is(e, io.EOF) {
			return ErrUnavailable
		}
		for _, entry := range batch {
			id := strings.TrimPrefix(entry.Name, "staging/")
			decoded, decodeErr := hex.DecodeString(id)
			if decodeErr != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != id || entry.Kind != nativefs.KindDirectory {
				return ErrOwnership
			}
			if e := s.checkReservation(ctx, entry.Name); e != nil {
				return e
			}
		}
		if errors.Is(e, io.EOF) {
			break
		}
	}
	return writer.Matches(ctx, s.root, "writer.lock", true)
}
func (s *Store) checkReservation(ctx context.Context, path string) error {
	f, e := s.root.OpenInput(ctx, path+"/intent.json", 4096)
	if e != nil {
		// A crash before intent publication admits no acquisition. Only an empty
		// directory or its bounded uncommitted intent.tmp can be classified here.
		d, e := s.root.OpenDirectoryMetadata(ctx, path)
		if e != nil {
			return ErrUnavailable
		}
		defer d.Close()
		for {
			batch, e := d.Next()
			if e != nil && !errors.Is(e, io.EOF) {
				return ErrUnavailable
			}
			for _, v := range batch {
				if v.Name != path+"/intent.tmp" || v.Kind != nativefs.KindRegular || v.Size < 0 || v.Size > 4096 {
					return ErrCorrupt
				}
			}
			if errors.Is(e, io.EOF) {
				return nil
			}
		}
	}
	data, readErr := io.ReadAll(f)
	stableErr, closeErr := f.Stable(), f.Close()
	if readErr != nil || stableErr != nil || closeErr != nil {
		return ErrCorrupt
	}
	fields, code := jsoninput.Object(data, 4096)
	if code != "" || len(fields) != 6 {
		return ErrCorrupt
	}
	for _, key := range []string{"version", "instance", "operation", "reservation", "previousUsed", "reconciliation"} {
		raw, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return ErrCorrupt
		}
	}
	var r reservationJournal
	if json.Unmarshal(data, &r) != nil || r.Version != 1 || r.Instance != hex.EncodeToString(s.instance[:]) || r.Operation > uint8(operationImport) || r.Reservation < 8192 || r.Reservation > 16<<30 || r.PreviousUsed > 32<<30 || r.Reconciliation != "exclusive-lease-and-complete-native-lengths" {
		return ErrCorrupt
	}
	return nil
}
