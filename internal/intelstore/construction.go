package intelstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"packtrace/internal/intel"
)

const constructionProfile = "osv-npm-all-slots-index-v1"

var ErrNoConstructionProof = errors.New("intel: legacy-without-construction-proof")

func newPreparation(version int) preparationRecord {
	p := preparationRecord{Version: version, Source: "caller-supplied"}
	if version == 2 {
		p.Proof = &constructionProof{Profile: constructionProfile, Routable: true}
	}
	return p
}

func parsePreparation(raw []byte) (preparationRecord, error) {
	var p preparationRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil || dec.Decode(new(any)) != io.EOF || (p.Version != 1 && p.Version != 2) || p.Version == 1 && p.Proof != nil || p.Version == 2 && (p.Proof == nil || p.Proof.Profile != constructionProfile) {
		return preparationRecord{}, ErrCorrupt
	}
	// Canonical equality also rejects duplicate fields, missing fields and alternate
	// spelling: v1's existing canonical bytes and IDs are not rewritten.
	canonical, err := json.Marshal(p)
	if err != nil || !bytes.Equal(canonical, raw) {
		return preparationRecord{}, ErrCorrupt
	}
	return p, nil
}

func constructionCommitment(catalog ObjectRef, records uint64, refs [256]ObjectRef, counts [256]uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte("PackTrace:original-index-construction:v1\x00"))
	number := func(n uint64) { var b [8]byte; binary.BigEndian.PutUint64(b[:], n); h.Write(b[:]) }
	h.Write(catalog.SHA256[:])
	number(catalog.Bytes)
	number(records)
	for i, ref := range refs {
		number(uint64(i))
		h.Write(ref.SHA256[:])
		number(ref.Bytes)
		number(counts[i])
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
func proofMatches(p preparationRecord, m intel.SnapshotManifest) bool {
	if p.Version != 2 || p.Proof == nil || p.Proof.Profile != constructionProfile || !p.Proof.Routable || p.Records != m.Originals.Records || len(m.Blocks) != 256 {
		return false
	}
	var refs [256]ObjectRef
	var counts [256]uint64
	for i, b := range m.Blocks {
		refs[i] = ObjectRef{b.Reference.SHA256, b.Reference.Bytes}
		counts[i] = b.Reference.Records
	}
	return p.Proof.Commitment == constructionCommitment(ObjectRef{m.Originals.SHA256, m.Originals.Bytes}, m.Originals.Records, refs, counts)
}

// Control reads are charged even on read/stability/close failure. These bytes
// share the comparison allowance; there is no additional proof/key allowance.
func (s *Store) validationControl(ctx context.Context, path string, budget *identityReadBudget) ([]byte, error) {
	f, err := s.root.OpenInput(ctx, path, 32)
	if err != nil {
		return nil, ErrUntrusted
	}
	var raw []byte
	if budget == nil {
		raw, err = io.ReadAll(f)
	} else {
		// Bound before reading, then account every actual byte, including failure.
		raw, err = io.ReadAll(io.LimitReader(f, int64(budget.remaining)))
		budget.remaining -= uint64(len(raw))
		budget.consumed += uint64(len(raw))
		if len(raw) != 32 {
			err = errors.Join(err, ErrLimit)
		}
	}
	err = errors.Join(err, f.Stable(), f.Close())
	if err != nil || len(raw) != 32 {
		return nil, errors.Join(ErrUntrusted, err)
	}
	return raw, nil
}
func (s *Store) validationMAC(ctx context.Context, id ID, budget *identityReadBudget) ([]byte, error) {
	key, err := s.validationControl(ctx, "acquisition.key", budget)
	if err != nil {
		return nil, err
	}
	identity, err := s.root.OwnedIdentity(ctx)
	if err != nil || identity != s.identity {
		return nil, ErrBinding
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("PackTrace:local-original-index-validation:v1\x00"))
	mac.Write(identity[:])
	mac.Write(s.instance[:])
	mac.Write(id[:])
	mac.Write([]byte(constructionProfile))
	return mac.Sum(nil), nil
}
func validationPath(id ID) string {
	return "generations/" + hex.EncodeToString(id[:]) + "/original-index-validation.mac"
}

// Only full construction/exact import rebuild sets constructed. Neither a
// received proof, seal, pin nor acquisition marker can enable this operation.
func (t *Transaction) attestValidation(ctx context.Context, id ID) error {
	if t == nil {
		return ErrUnavailable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if ctx == nil || t.closed || t.failed != nil || t.work.Err() != nil || ctx.Err() != nil || (t.kind != operationImport && t.kind != operationSync) || zeroRef(t.constructed) {
		return ErrUntrusted
	}
	if t.writer.Matches(ctx, t.store.root, "writer.lock", true) != nil {
		return ErrBinding
	}
	sealed, ok := t.sealed[id]
	if !ok {
		return ErrUntrusted
	}
	raw, err := t.store.readRef(ctx, sealed.header.Descriptor, 4096)
	if err != nil {
		return err
	}
	d, err := parseGenerationDescriptor(raw)
	if err != nil {
		return err
	}
	raw, err = t.store.readRef(ctx, d.Provenance, 32<<10)
	if err != nil {
		return err
	}
	var receipt sourceReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Preparation != t.constructed {
		return ErrUntrusted
	}
	raw, err = t.store.readRef(ctx, t.constructed, 512<<10)
	if err != nil {
		return err
	}
	p, err := parsePreparation(raw)
	if err != nil {
		return err
	}
	raw, err = t.store.readRef(ctx, d.Manifest, 1<<20)
	if err != nil {
		return err
	}
	m, err := intel.ParseSnapshotManifestV11(raw)
	if err != nil || !proofMatches(p, m) {
		return ErrUntrusted
	}
	mac, err := t.store.validationMAC(ctx, id, nil)
	if err != nil {
		return err
	}
	return t.writeImmutable(ctx, validationPath(id), mac)
}

// ValidateConstruction checks only code-derived index construction. Caller must
// independently require source authority and replay relevant original semantics.
// No writes, timestamp changes, implicit repair or legacy proof inference.
func (s *Snapshot) ValidateConstruction(ctx context.Context, remaining uint64) (consumed uint64, err error) {
	if s == nil || ctx == nil || remaining > 8<<30 {
		return 0, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.pin.lease.Stable(ctx) != nil {
		return 0, ErrBinding
	}
	budget := &identityReadBudget{remaining: remaining}
	defer func() {
		consumed = budget.consumed
		err = errors.Join(err, budget.err, ctx.Err(), s.pin.lease.Stable(ctx))
	}()
	raw, err := s.store.readRefBudget(ctx, s.descriptor.Provenance, 32<<10, budget)
	if err != nil {
		return 0, err
	}
	var receipt sourceReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Version != 1 || receipt.Source != "osv-npm" {
		return 0, ErrUntrusted
	}
	raw, err = s.store.readRefBudget(ctx, receipt.Preparation, 512<<10, budget)
	if err != nil {
		return 0, err
	}
	p, err := parsePreparation(raw)
	if err != nil {
		return 0, err
	}
	if p.Version == 1 {
		return 0, ErrNoConstructionProof
	}
	if !proofMatches(p, s.manifest) {
		return 0, ErrUntrusted
	}
	expected, err := s.store.validationMAC(ctx, s.pin.ID(), budget)
	if err != nil {
		return 0, err
	}
	observed, err := s.store.validationControl(ctx, validationPath(s.pin.ID()), budget)
	if err != nil || !hmac.Equal(expected, observed) {
		return 0, errors.Join(ErrUntrusted, err)
	}
	return budget.consumed, nil
}
