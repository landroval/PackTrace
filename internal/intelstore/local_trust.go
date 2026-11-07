package intelstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// This authenticates a local controller action to this physical owned store.
// It is neither a publisher signature nor an organizational approval. The key
// and generation sidecar are never part of the portable package object graph.
func (s *Store) localMAC(ctx context.Context, id ID) ([]byte, error) {
	key, e := s.readSmall(ctx, "acquisition.key", 32)
	if e != nil || len(key) != 32 {
		return nil, ErrUntrusted
	}
	identity, e := s.root.OwnedIdentity(ctx)
	if e != nil || identity != s.identity {
		return nil, ErrBinding
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("PackTrace:local-osv-acquisition:v1\x00"))
	mac.Write(identity[:])
	mac.Write(s.instance[:])
	mac.Write(id[:])
	return mac.Sum(nil), nil
}
func (t *Transaction) attestLocal(ctx context.Context, id ID) error {
	if t == nil || ctx == nil {
		return ErrUnavailable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.failed != nil || t.work.Err() != nil {
		return ErrUnavailable
	}
	if t.kind != operationSync {
		return ErrUntrusted
	}
	if t.writer.Matches(ctx, t.store.root, "writer.lock", true) != nil {
		return ErrUnavailable
	}
	if _, ok := t.sealed[id]; !ok {
		return ErrUntrusted
	}
	mac, e := t.store.localMAC(ctx, id)
	if e != nil {
		return e
	}
	return t.writeImmutable(ctx, "generations/"+hex.EncodeToString(id[:])+"/local-acquisition.mac", mac)
}
func (s *Store) verifyLocal(ctx context.Context, id ID) error {
	if s == nil || ctx == nil {
		return ErrUnavailable
	}
	expected, e := s.localMAC(ctx, id)
	if e != nil {
		return e
	}
	observed, e := s.readSmall(ctx, "generations/"+hex.EncodeToString(id[:])+"/local-acquisition.mac", 32)
	if e != nil || len(observed) != 32 || !hmac.Equal(expected, observed) {
		return ErrUntrusted
	}
	return nil
}
