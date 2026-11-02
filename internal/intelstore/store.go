// Package intelstore owns explicit intelligence storage. A store identity or
// marker does not establish advisory authenticity, freshness or matching coverage.
package intelstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"packtrace/internal/jsoninput"
	"packtrace/internal/nativefs"
)

type ID [32]byte
type Mode uint8

const (
	ReadOnly Mode = iota
	CreateOwned
)

var (
	ErrUnavailable = errors.New("intel: store-unavailable")
	ErrOwnership   = errors.New("intel: store-ownership")
	ErrBinding     = errors.New("intel: store-binding")
	ErrLimit       = errors.New("intel: store-limit")
	ErrCorrupt     = errors.New("intel: store-corrupt")
	ErrBusy        = errors.New("intel: store-busy")
	ErrUntrusted   = errors.New("intel: store-untrusted")
)

type Store struct {
	mu         sync.Mutex
	root       *nativefs.Root
	owner      *nativefs.OwnedDirectory
	mode       Mode
	identity   [32]byte
	instance   [32]byte
	active     bool
	quotaLimit uint64 // private testable ceiling; production default is32GiB
}

type storeMarker struct {
	Version  int    `json:"version"`
	Instance string `json:"instance"`
	Root     string `json:"root"`
}

func Open(ctx context.Context, path string, mode Mode) (*Store, error) {
	if ctx == nil || mode != ReadOnly && mode != CreateOwned {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var owned *nativefs.OwnedDirectory
	var err error
	fresh := false
	if mode == CreateOwned {
		owned, err = nativefs.OpenOwnedDirectory(ctx, path, true)
		fresh = err == nil
	}
	if owned == nil {
		owned, err = nativefs.OpenOwnedDirectory(ctx, path, false)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if mode == CreateOwned {
			return nil, ErrOwnership
		}
		return nil, ErrUnavailable
	}
	s := &Store{root: owned.ReadRoot(), owner: owned, mode: mode}
	fail := func(err error) (*Store, error) { return nil, errors.Join(err, s.Close()) }
	s.identity, err = s.root.OwnedIdentity(ctx)
	if err != nil {
		return fail(ErrOwnership)
	}
	if fresh {
		if _, err := rand.Read(s.instance[:]); err != nil {
			return fail(ErrUnavailable)
		}
		data, err := json.Marshal(storeMarker{Version: 1, Instance: hex.EncodeToString(s.instance[:]), Root: hex.EncodeToString(s.identity[:])})
		if err != nil || owned.WriteControl(ctx, "store.json", data) != nil {
			return fail(ErrUnavailable)
		}
	}
	if err := s.readMarker(ctx); err != nil {
		return fail(err)
	}
	if mode == CreateOwned {
		for _, name := range []string{"objects", "generations", "activation", "locks", "pins", "staging"} {
			if err := owned.Mkdir(ctx, name); err != nil {
				return fail(ErrOwnership)
			}
		}
	}
	return s, nil
}

// OpenExternal borrows a proven disjoint read root. The original target must
// remain open; this method never initializes state or acquires a write owner.
func OpenExternal(ctx context.Context, target *nativefs.Root, path string) (*Store, error) {
	if ctx == nil || target == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := target.OpenExternalRoot(ctx, path)
	if err != nil {
		return nil, ErrBinding
	}
	s := &Store{root: r, mode: ReadOnly}
	s.identity, err = r.OwnedIdentity(ctx)
	if err == nil {
		err = s.readMarker(ctx)
	}
	if err != nil {
		closeErr := s.Close()
		if ctx.Err() != nil {
			return nil, errors.Join(ctx.Err(), closeErr)
		}
		return nil, errors.Join(ErrBinding, closeErr)
	}
	return s, nil
}

func (s *Store) readMarker(ctx context.Context) error {
	f, err := s.root.OpenInput(ctx, "store.json", 4096)
	if err != nil {
		return ErrOwnership
	}
	data, readErr := io.ReadAll(f)
	stableErr := f.Stable()
	closeErr := f.Close()
	if readErr != nil || stableErr != nil || closeErr != nil {
		return ErrCorrupt
	}
	fields, code := jsoninput.Object(data, 4096)
	if code != "" || len(fields) != 3 {
		return ErrCorrupt
	}
	var m storeMarker
	if json.Unmarshal(data, &m) != nil || m.Version != 1 {
		return ErrCorrupt
	}
	id, err := hex.DecodeString(m.Root)
	if err != nil || len(id) != 32 || hex.EncodeToString(id) != m.Root || m.Root != hex.EncodeToString(s.identity[:]) {
		return ErrBinding
	}
	instance, err := hex.DecodeString(m.Instance)
	if err != nil || len(instance) != 32 || hex.EncodeToString(instance) != m.Instance {
		return ErrCorrupt
	}
	copy(s.instance[:], instance)
	if s.instance == ([32]byte{}) {
		return ErrCorrupt
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return ErrUnavailable
	}
	if s.active {
		return ErrBusy
	}
	var err error
	if s.owner != nil {
		err = s.owner.Close()
	} else {
		err = s.root.Close()
	}
	s.root = nil
	s.owner = nil
	return err
}
