package intelstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"packtrace/internal/jsoninput"
)

type activationRecord struct {
	Version      int    `json:"version"`
	Epoch        string `json:"epoch"`
	Current      string `json:"current"`
	Seal         string `json:"seal"`
	Previous     string `json:"previous"`
	PreviousSeal string `json:"previousSeal"`
}

func parseID(text string) (ID, error) {
	var id ID
	b, e := hex.DecodeString(text)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != text {
		return id, ErrCorrupt
	}
	copy(id[:], b)
	if id == (ID{}) {
		return ID{}, ErrCorrupt
	}
	return id, nil
}
func (s *Store) readSmall(ctx context.Context, name string, max int64) ([]byte, error) {
	f, e := s.root.OpenInput(ctx, name, max)
	if e != nil {
		return nil, ErrUnavailable
	}
	b, e := io.ReadAll(f)
	st, cl := f.Stable(), f.Close()
	if e != nil || st != nil || cl != nil {
		return nil, ErrCorrupt
	}
	return b, nil
}
func strictObject(data []byte, cap int, keys ...string) bool {
	fields, code := jsoninput.Object(data, cap)
	if code != "" || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		v, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return false
		}
	}
	return true
}
func (s *Store) checkHeader(ctx context.Context, id ID, want string) (sealedHeader, error) {
	key := hex.EncodeToString(id[:])
	raw, e := s.readSmall(ctx, "generations/"+key+"/sealed.json", 4096)
	if e != nil || !strictObject(raw, 4096, "version", "id", "descriptor") {
		return sealedHeader{}, ErrCorrupt
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != want {
		return sealedHeader{}, ErrCorrupt
	}
	var header sealedHeader
	if json.Unmarshal(raw, &header) != nil || header.Version != 1 || header.ID != key || header.Descriptor.SHA256 != [32]byte(id) || header.Descriptor.Bytes > 4096 {
		return sealedHeader{}, ErrCorrupt
	}
	return header, nil
}
func (s *Store) parseSelection(ctx context.Context, data []byte) (activationRecord, error) {
	if !strictObject(data, 4096, "version", "epoch", "current", "seal", "previous", "previousSeal") {
		return activationRecord{}, ErrCorrupt
	}
	var r activationRecord
	if json.Unmarshal(data, &r) != nil || r.Version != 1 {
		return r, ErrCorrupt
	}
	if _, e := parseID(r.Epoch); e != nil {
		return r, e
	}
	current, e := parseID(r.Current)
	if e != nil {
		return r, e
	}
	if _, e := parseID(r.Seal); e != nil {
		return r, e
	}
	if r.Previous != "" {
		if _, e := parseID(r.Previous); e != nil {
			return r, e
		}
		if _, e := parseID(r.PreviousSeal); e != nil {
			return r, e
		}
	} else if r.PreviousSeal != "" {
		return r, ErrCorrupt
	}
	if _, e := s.checkHeader(ctx, current, r.Seal); e != nil {
		return r, e
	}
	return r, nil
}
func (s *Store) readSelection(ctx context.Context) (activationRecord, bool, error) {
	for i, name := range []string{"activation/current.json", "activation/previous.json"} {
		data, e := s.readSmall(ctx, name, 4096)
		if e != nil {
			continue
		}
		record, e := s.parseSelection(ctx, data)
		if e == nil {
			return record, i == 1, nil
		}
	}
	return activationRecord{}, false, ErrUnavailable
}
func (s *Store) emptyActivation(ctx context.Context) bool {
	d, e := s.root.OpenDirectoryMetadata(ctx, "activation")
	if e != nil {
		return false
	}
	defer d.Close()
	batch, e := d.Next()
	return len(batch) == 0 && errors.Is(e, io.EOF)
}
func (t *Transaction) replaceSelection(ctx context.Context, name string, data []byte) error {
	if uint64(len(data))+4096 > t.held {
		return ErrLimit
	}
	t.sequence++
	temp := t.path + "/selector-" + hex.EncodeToString([]byte{byte(t.sequence >> 8), byte(t.sequence)})
	f, e := t.store.owner.CopyExclusive(ctx, temp, bytes.NewReader(data), uint64(len(data)))
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
		if e == nil {
			e = t.store.owner.Publish(ctx, f, name, true)
		}
		e = errors.Join(e, f.Close())
	}
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func (t *Transaction) activate(ctx context.Context, id ID) error {
	if t == nil {
		return ErrCorrupt
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.store == nil || t.failed != nil || ctx == nil || t.work == nil || t.work.Err() != nil {
		return ErrCorrupt
	}
	candidate, ok := t.sealed[id]
	if !ok {
		return ErrCorrupt
	}
	if t.writer.Matches(ctx, t.store.root, "writer.lock", true) != nil {
		return ErrUnavailable
	}
	gate, gateErr := t.store.root.TryOwnedLock(t.work, "locks/selection.lock", true)
	if gateErr != nil {
		return ErrBusy
	}
	defer gate.Close()
	sealKey := hex.EncodeToString(candidate.digest[:])
	if _, e := t.store.checkHeader(t.work, id, sealKey); e != nil {
		return e
	}
	old, _, e := t.store.readSelection(t.work)
	if e != nil && !t.store.emptyActivation(t.work) {
		return ErrCorrupt
	}
	next := activationRecord{Version: 1, Epoch: hex.EncodeToString(t.id[:]), Current: hex.EncodeToString(id[:]), Seal: sealKey}
	if e == nil {
		next.Previous, next.PreviousSeal = old.Current, old.Seal
		raw, err := json.Marshal(old)
		if err != nil {
			return ErrCorrupt
		}
		if err := t.replaceSelection(t.work, "activation/previous.json", raw); err != nil {
			return err
		}
	}
	raw, e := json.Marshal(next)
	if e != nil {
		return ErrCorrupt
	}
	if e := t.replaceSelection(t.work, "activation/current.json", raw); e != nil {
		return e
	}
	return ctx.Err()
}
