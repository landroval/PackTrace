package intelstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"packtrace/internal/nativefs"
)

type Pin struct {
	mu       sync.Mutex
	store    *Store
	lease    *nativefs.OwnedLock
	id       ID
	fallback bool
	closed   bool
}

func (s *Store) ensureSelectionGate(ctx context.Context) error {
	m, e := s.root.OpenMetadata(ctx, "locks/selection.lock")
	if e == nil {
		entry := m.Entry()
		e = errors.Join(m.Stable(), m.Close())
		if e != nil || entry.Kind != nativefs.KindRegular || entry.Size != 0 {
			return ErrCorrupt
		}
		return nil
	}
	f, e := s.owner.CopyExclusive(ctx, "locks/selection.lock", bytes.NewReader(nil), 0)
	if f != nil {
		e = errors.Join(e, f.Stable(), f.Close())
	}
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) explicitHeader(ctx context.Context, id ID) (sealedHeader, error) {
	key := hex.EncodeToString(id[:])
	b, e := s.readSmall(ctx, "generations/"+key+"/sealed.json", 4096)
	if e != nil {
		return sealedHeader{}, e
	}
	digest := sha256.Sum256(b)
	header, e := s.checkHeader(ctx, id, hex.EncodeToString(digest[:]))
	if e != nil {
		return header, e
	}
	// Explicit ID binds actual descriptor bytes, not a self-declared header field.
	if _, e := s.readRef(ctx, header.Descriptor, 4096); e != nil {
		return header, e
	}
	return header, nil
}
func (s *Store) Pin(ctx context.Context, selected *ID) (*Pin, error) {
	if s == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	s.mu.Lock()
	if s.root == nil {
		s.mu.Unlock()
		return nil, ErrUnavailable
	}
	s.readers++
	s.mu.Unlock()
	fail := func(e error) (*Pin, error) { s.mu.Lock(); s.readers--; s.mu.Unlock(); return nil, e }
	gate, e := s.root.TryOwnedLock(ctx, "locks/selection.lock", false)
	if e != nil {
		return fail(ErrUnavailable)
	}
	var id ID
	var fallback bool
	if selected == nil {
		record, f, e := s.readSelection(ctx)
		if e != nil {
			gate.Close()
			return fail(e)
		}
		id, e = parseID(record.Current)
		fallback = f
		if e != nil {
			gate.Close()
			return fail(e)
		}
	} else {
		id = *selected
		if _, e := s.explicitHeader(ctx, id); e != nil {
			gate.Close()
			return fail(e)
		}
	}
	retired, e := s.generationRetired(ctx, id)
	if e != nil || retired {
		gate.Close()
		return fail(ErrUnavailable)
	}
	key := hex.EncodeToString(id[:])
	lease, e := s.root.TryOwnedLock(ctx, "generations/"+key+"/read.lock", false)
	closeErr := gate.Close()
	if e != nil || closeErr != nil {
		if lease != nil {
			lease.Close()
		}
		return fail(ErrUnavailable)
	}
	return &Pin{store: s, lease: lease, id: id, fallback: fallback}, nil
}
func (p *Pin) ID() ID {
	if p == nil {
		return ID{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.lease == nil {
		return ID{}
	}
	return p.id
}
func (p *Pin) Close() error {
	if p == nil {
		return ErrUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.store == nil || p.lease == nil {
		return ErrUnavailable
	}
	p.closed = true
	e := p.lease.Close()
	p.store.mu.Lock()
	p.store.readers--
	p.store.mu.Unlock()
	return e
}

type durablePin struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Pinned  bool   `json:"pinned"`
}

func (s *Store) SetPinned(ctx context.Context, id ID, pinned bool) (failure error) {
	tx, e := s.begin(ctx, operationMaintenance, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		return e
	}
	defer func() { failure = errors.Join(failure, tx.Close()) }()
	if _, e := s.explicitHeader(ctx, id); e != nil {
		return e
	}
	if pinned {
		retired, e := s.generationRetired(ctx, id)
		if e != nil {
			return e
		}
		if retired {
			return ErrUntrusted
		}
	}
	key := hex.EncodeToString(id[:])
	data, _ := json.Marshal(durablePin{1, key, pinned})
	return tx.replaceSelection(tx.work, "pins/"+key+".json", data)
}
func (s *Store) isPinned(ctx context.Context, id ID) (bool, error) {
	if s == nil || ctx == nil {
		return false, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return false, ErrUnavailable
	}
	key := hex.EncodeToString(id[:])
	path := "pins/" + key + ".json"
	m, e := s.root.OpenMetadata(ctx, path)
	if e != nil {
		dir, err := s.root.OpenDirectoryMetadata(ctx, "pins")
		if err != nil {
			return false, ErrUnavailable
		}
		for {
			batch, err := dir.Next()
			if err != nil && !errors.Is(err, io.EOF) {
				dir.Close()
				return false, ErrUnavailable
			}
			for _, entry := range batch {
				if entry.Name == path {
					dir.Close()
					return false, ErrCorrupt
				}
			}
			if errors.Is(err, io.EOF) {
				if dir.Close() != nil {
					return false, ErrUnavailable
				}
				return false, nil
			}
		}
	}
	if e := errors.Join(m.Stable(), m.Close()); e != nil {
		return false, ErrCorrupt
	}
	data, e := s.readSmall(ctx, path, 4096)
	if e != nil || !strictObject(data, 4096, "version", "id", "pinned") {
		return false, ErrCorrupt
	}
	var p durablePin
	if json.Unmarshal(data, &p) != nil || p.Version != 1 || p.ID != key {
		return false, ErrCorrupt
	}
	return p.Pinned, nil
}
