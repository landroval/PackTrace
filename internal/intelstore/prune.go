package intelstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"packtrace/internal/nativefs"
	"sort"
	"strings"
	"time"
)

type Preview struct {
	Token                                            ID
	Generations, Candidates, Bytes, QuarantinedBytes uint64
	ReproducibilityRisk, Limited                     bool
}
type PruneResult struct {
	Token                                                     ID
	Generations, RemovedFiles, RemovedBytes, QuarantinedFiles uint64
	Partial                                                   bool
}
type pruneCandidate struct {
	name        string
	fingerprint [32]byte
	bytes       uint64
}
type pruneGeneration struct {
	id      ID
	lease   *nativefs.OwnedLock
	retired bool
}
type pruneReference struct {
	bytes uint64
	seen  bool
}
type pruneState struct {
	preview     Preview
	hash        hash.Hash
	candidates  []pruneCandidate
	generations []pruneGeneration
	protected   map[[32]byte]pruneReference
	controls    []pruneCandidate
	metadata    uint64
	failure     error
}

// Logical retained metadata shares256MiB;48MiB remains for bounded sorted
// directory/pin/generation scratch. This is not a Go heap/RSS hard limit.
func (p *pruneState) retainMetadata(bytes uint64) bool {
	if p.failure != nil {
		return false
	}
	if bytes > (208<<20)-p.metadata {
		p.failure = ErrLimit
		return false
	}
	p.metadata += bytes
	return true
}

func (p *pruneState) Close() error {
	var e error
	for _, gen := range p.generations {
		e = errors.Join(e, gen.lease.Close())
	}
	p.generations = nil
	return e
}
func (p *pruneState) fact(v any) {
	raw, _ := json.Marshal(v)
	p.hash.Write(raw)
	p.hash.Write([]byte{'\n'})
}
func (s *Store) pruneDirectory(ctx context.Context, name string) ([]nativefs.Entry, error) {
	dir, e := s.root.OpenDirectoryMetadata(ctx, name)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer dir.Close()
	var entries []nativefs.Entry
	for {
		batch, e := dir.Next()
		if e != nil && !errors.Is(e, io.EOF) {
			return nil, ErrUnavailable
		}
		if len(entries)+len(batch) > 100_000 {
			return nil, ErrLimit
		}
		entries = append(entries, batch...)
		if errors.Is(e, io.EOF) {
			break
		}
	}
	if e := dir.Close(); e != nil {
		return nil, ErrUnavailable
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}
func (s *Store) pruneMetadata(ctx context.Context, name string, retirable bool) (pruneCandidate, error) {
	m, e := s.root.OpenMetadata(ctx, name)
	if e != nil {
		return pruneCandidate{}, ErrUnavailable
	}
	defer m.Close()
	entry := m.Entry()
	if entry.Size < 0 {
		return pruneCandidate{}, ErrCorrupt
	}
	var fp [32]byte
	if retirable {
		fp, e = s.owner.RetirementFingerprint(ctx, m)
	} else {
		fp, e = m.Fingerprint()
	}
	if e != nil {
		return pruneCandidate{}, ErrOwnership
	}
	return pruneCandidate{name, fp, uint64(entry.Size)}, nil
}
func (p *pruneState) add(c pruneCandidate, eligible bool) {
	chosen := eligible && len(p.candidates) < 100_000
	if eligible && !chosen {
		p.preview.Limited = true
	}
	p.fact(struct {
		Name        string
		Fingerprint [32]byte
		Bytes       uint64
		Candidate   bool
	}{c.name, c.fingerprint, c.bytes, chosen})
	if chosen {
		if !p.retainMetadata(uint64(len(c.name)) + 64) {
			return
		}
		p.candidates = append(p.candidates, c)
		p.preview.Candidates++
		p.preview.Bytes += c.bytes
	}
}
func (s *Store) generationRetired(ctx context.Context, id ID) (bool, error) {
	path := "generations/" + hex.EncodeToString(id[:])
	entries, e := s.pruneDirectory(ctx, path)
	if e != nil {
		return false, e
	}
	for _, v := range entries {
		if v.Name == path+"/retired" {
			if v.Kind != nativefs.KindRegular || v.Size != 0 {
				return false, ErrCorrupt
			}
			if _, e := s.pruneMetadata(ctx, v.Name, true); e != nil {
				return false, e
			}
			return true, nil
		}
	}
	return false, nil
}
func (s *Store) pruneState(ctx context.Context) (state *pruneState, failure error) {
	state = &pruneState{hash: sha256.New(), protected: make(map[[32]byte]pruneReference)}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, state.Close())
		}
	}()
	identity, e := s.root.OwnedIdentity(ctx)
	if e != nil {
		return state, ErrBinding
	}
	limit := s.quotaLimit
	if limit == 0 {
		limit = 32 << 30
	}
	state.fact(struct {
		Version        int
		Root           [32]byte
		Instance       [32]byte
		Quota, Staging uint64
	}{1, identity, s.instance, limit, 16 << 30})
	selectors, e := s.pruneDirectory(ctx, "activation")
	if e != nil {
		return state, e
	}
	for _, v := range selectors {
		if (v.Name != "activation/current.json" && v.Name != "activation/previous.json") || v.Kind != nativefs.KindRegular || v.Size > 4096 {
			return state, ErrCorrupt
		}
		c, e := s.pruneMetadata(ctx, v.Name, true)
		if e != nil {
			return state, e
		}
		if !state.retainMetadata(uint64(len(c.name)) + 64) {
			return state, ErrLimit
		}
		state.controls = append(state.controls, c)
		state.add(c, false)
	}
	selection, fallback, e := s.readSelection(ctx)
	if e != nil && !s.emptyActivation(ctx) {
		return state, e
	}
	state.fact(struct {
		Selection activationRecord
		Fallback  bool
	}{selection, fallback})
	pins, e := s.pruneDirectory(ctx, "pins")
	if e != nil {
		return state, e
	}
	pinned := make(map[ID]bool)
	for _, v := range pins {
		key := strings.TrimPrefix(v.Name, "pins/")
		if v.Kind != nativefs.KindRegular || !strings.HasSuffix(key, ".json") {
			return state, ErrOwnership
		}
		id, e := parseID(strings.TrimSuffix(key, ".json"))
		if e != nil {
			return state, ErrOwnership
		}
		on, e := s.isPinned(ctx, id)
		if e != nil {
			return state, e
		}
		pinned[id] = on
		c, e := s.pruneMetadata(ctx, v.Name, true)
		if e != nil {
			return state, e
		}
		if !state.retainMetadata(uint64(len(c.name)) + 64) {
			return state, ErrLimit
		}
		state.controls = append(state.controls, c)
		state.add(c, false)
	}
	generations, e := s.pruneDirectory(ctx, "generations")
	if e != nil {
		return state, e
	}
	var retained []ID
	for _, v := range generations {
		key := strings.TrimPrefix(v.Name, "generations/")
		id, e := parseID(key)
		if e != nil || v.Kind != nativefs.KindDirectory {
			return state, ErrOwnership
		}
		retired, e := s.generationRetired(ctx, id)
		if e != nil {
			return state, e
		}
		// ponytail: keep zero-byte retired stubs/empty directories; add native
		// empty-directory retirement if namespace churn reaches100k entries.
		if retired {
			files, e := s.pruneDirectory(ctx, v.Name)
			if e != nil {
				return state, e
			}
			empty := len(files) == 2
			for _, f := range files {
				leaf := strings.TrimPrefix(f.Name, v.Name+"/")
				if f.Kind != nativefs.KindRegular || f.Size != 0 || (leaf != "read.lock" && leaf != "retired") {
					empty = false
				}
			}
			if empty {
				if key == selection.Current || key == selection.Previous || pinned[id] {
					return state, ErrCorrupt
				}
				lease, e := s.pruneGenerationLease(ctx, v.Name+"/read.lock")
				if e != nil {
					return state, ErrUnavailable
				}
				for _, f := range files {
					c, e := s.pruneMetadata(ctx, f.Name, true)
					if e != nil {
						lease.Close()
						return state, e
					}
					state.add(c, false)
				}
				if e := lease.Close(); e != nil {
					return state, e
				}
				state.fact(struct {
					Generation ID
					Reason     string
				}{id, "retired-empty"})
				continue
			}
		}
		reason := ""
		if key == selection.Current || key == selection.Previous || pinned[id] {
			reason = "selection-or-pin"
		}
		var lease *nativefs.OwnedLock
		if reason == "" {
			lease, e = s.pruneGenerationLease(ctx, v.Name+"/read.lock")
			if errors.Is(e, nativefs.ErrBusy) {
				reason = "reader"
			} else if e != nil {
				return state, ErrUnavailable
			}
			if reason == "" && len(state.generations) >= 128 {
				reason = "batch-limit"
				if e := lease.Close(); e != nil {
					return state, e
				}
				lease = nil
				state.preview.Limited = true
			}
		}
		protected := reason != ""
		state.fact(struct {
			Generation ID
			Reason     string
			Retired    bool
		}{id, reason, retired})
		if protected {
			if retired {
				return state, ErrCorrupt
			}
			retained = append(retained, id)
			delete(pinned, id)
		} else {
			state.generations = append(state.generations, pruneGeneration{id, lease, retired})
			if !retired {
				state.preview.Generations++
			}
		}
		files, e := s.pruneDirectory(ctx, v.Name)
		if e != nil {
			return state, e
		}
		sealed := false
		for _, f := range files {
			leaf := strings.TrimPrefix(f.Name, v.Name+"/")
			limit := int64(4096)
			if leaf == "manifest.json" {
				limit = 1 << 20
			}
			if f.Kind != nativefs.KindRegular || f.Size < 0 || f.Size > limit {
				return state, ErrOwnership
			}
			if leaf != "manifest.json" && leaf != "sealed.json" && leaf != "read.lock" && leaf != "local-acquisition.mac" && leaf != "retired" {
				return state, ErrOwnership
			}
			if leaf == "sealed.json" {
				sealed = true
			}
			c, e := s.pruneMetadata(ctx, f.Name, true)
			if e != nil {
				return state, e
			}
			if protected {
				if !state.retainMetadata(uint64(len(c.name)) + 64) {
					return state, ErrLimit
				}
				state.controls = append(state.controls, c)
			}
			state.add(c, !protected && leaf != "read.lock" && leaf != "retired")
		}
		if !sealed && !retired {
			return state, ErrCorrupt
		}
	}
	for _, on := range pinned {
		if on {
			return state, ErrCorrupt
		}
	}
	for _, id := range retained {
		if e := s.protectGeneration(ctx, state, id); e != nil {
			return state, e
		}
	}
	prefixes, e := s.pruneDirectory(ctx, "objects")
	if e != nil {
		return state, e
	}
	for _, prefix := range prefixes {
		key := strings.TrimPrefix(prefix.Name, "objects/")
		if prefix.Kind != nativefs.KindDirectory || !lowerHex(key, 2) {
			return state, ErrOwnership
		}
		files, e := s.pruneDirectory(ctx, prefix.Name)
		if e != nil {
			return state, e
		}
		for _, file := range files {
			name := strings.TrimPrefix(file.Name, prefix.Name+"/")
			if file.Kind != nativefs.KindRegular || !lowerHex(name, 64) || name[:2] != key || file.Size < 0 || file.Size > 512<<20 {
				return state, ErrOwnership
			}
			digest, e := parseID(name)
			if e != nil {
				return state, e
			}
			ref, protected := state.protected[[32]byte(digest)]
			if protected {
				if ref.bytes != uint64(file.Size) {
					return state, ErrCorrupt
				}
				ref.seen = true
				state.protected[[32]byte(digest)] = ref
			}
			c, e := s.pruneMetadata(ctx, file.Name, true)
			if e != nil {
				return state, e
			}
			state.add(c, !protected)
		}
	}
	for _, ref := range state.protected {
		if !ref.seen {
			return state, ErrCorrupt
		}
	}
	state.metadata -= uint64(len(state.protected)) * 48
	state.protected = nil
	staging, e := s.pruneDirectory(ctx, "staging")
	if e != nil {
		return state, e
	}
	for _, dir := range staging {
		key := strings.TrimPrefix(dir.Name, "staging/")
		if dir.Kind != nativefs.KindDirectory || !lowerHex(key, 64) {
			return state, ErrOwnership
		}
		if e := s.checkReservation(ctx, dir.Name); e != nil {
			return state, e
		}
		files, e := s.pruneDirectory(ctx, dir.Name)
		if e != nil {
			return state, e
		}
		// Preserve durable attribution through every partial/cancelled cleanup.
		// The journal can leave its source slot only after all other files did.
		sort.SliceStable(files, func(i, j int) bool {
			a, b := strings.HasSuffix(files[i].Name, "/intent.json"), strings.HasSuffix(files[j].Name, "/intent.json")
			if a != b {
				return !a
			}
			return files[i].Name < files[j].Name
		})
		for _, file := range files {
			name := strings.TrimPrefix(file.Name, dir.Name+"/")
			if file.Kind != nativefs.KindRegular || !pruneStageName(name) {
				return state, ErrOwnership
			}
			c, e := s.pruneMetadata(ctx, file.Name, true)
			if e != nil {
				return state, e
			}
			state.add(c, true)
		}
	}
	quarantine, e := s.pruneDirectory(ctx, "quarantine")
	if e != nil {
		return state, e
	}
	for _, dir := range quarantine {
		if dir.Kind != nativefs.KindDirectory || !lowerHex(strings.TrimPrefix(dir.Name, "quarantine/"), 64) {
			return state, ErrOwnership
		}
		files, e := s.pruneDirectory(ctx, dir.Name)
		if e != nil {
			return state, e
		}
		for _, file := range files {
			if file.Kind != nativefs.KindRegular || file.Size < 0 {
				return state, ErrOwnership
			}
			c, e := s.pruneMetadata(ctx, file.Name, false)
			if e != nil {
				return state, e
			}
			state.preview.QuarantinedBytes += c.bytes
			state.add(c, false)
		}
	}
	state.preview.ReproducibilityRisk = state.preview.Generations != 0
	state.fact(struct {
		Candidates, Bytes, Generations, Quarantined uint64
		Limited                                     bool
	}{state.preview.Candidates, state.preview.Bytes, state.preview.Generations, state.preview.QuarantinedBytes, state.preview.Limited})
	if state.failure != nil {
		return state, state.failure
	}
	copy(state.preview.Token[:], state.hash.Sum(nil))
	return state, nil
}
func (s *Store) pruneGenerationLease(ctx context.Context, path string) (*nativefs.OwnedLock, error) {
	gate, e := s.root.TryOwnedLock(ctx, "locks/selection.lock", true)
	if e != nil {
		return nil, ErrBusy
	}
	lease, e := s.root.TryOwnedLock(ctx, path, true)
	if closeErr := gate.Close(); closeErr != nil {
		if lease != nil {
			lease.Close()
		}
		return nil, ErrUnavailable
	}
	return lease, e
}

// Called only by activate after this exact writer sealed the complete graph,
// with the selection gate held. Reimport is explicit rehydration, not scan repair.
func (t *Transaction) reviveRetired(ctx context.Context, id ID) (failure error) {
	retired, e := t.store.generationRetired(ctx, id)
	if e != nil || !retired {
		return e
	}
	key := hex.EncodeToString(id[:])
	lease, e := t.store.root.TryOwnedLock(ctx, "generations/"+key+"/read.lock", true)
	if e != nil {
		return ErrBusy
	}
	defer func() { failure = errors.Join(failure, lease.Close()) }()
	if t.sequence >= 2_000_000+65_536+1024 {
		return ErrLimit
	}
	t.sequence++
	m, e := t.store.root.OpenMetadata(ctx, "generations/"+key+"/retired")
	if e != nil {
		return ErrUnavailable
	}
	defer func() { failure = errors.Join(failure, m.Close()) }()
	if m.Entry().Size != 0 {
		return ErrCorrupt
	}
	original, e := t.store.owner.Quarantine(ctx, m, fmt.Sprintf("%s/object-%016x", t.path, t.sequence))
	if e != nil {
		return e
	}
	defer func() { failure = errors.Join(failure, original.Close()) }()
	return original.Remove(ctx)
}
func lowerHex(v string, length int) bool {
	if len(v) != length {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func pruneStageName(v string) bool {
	if v == "intent.json" || v == "intent.tmp" || v == "closed.json" || v == "source-archive" || v == "source-changes" {
		return true
	}
	return strings.HasPrefix(v, "object-") && lowerHex(strings.TrimPrefix(v, "object-"), 16) || strings.HasPrefix(v, "selector-") && lowerHex(strings.TrimPrefix(v, "selector-"), 4)
}
func (s *Store) protectGeneration(ctx context.Context, p *pruneState, id ID) error {
	h, e := s.explicitHeader(ctx, id)
	if e != nil {
		return e
	}
	raw, e := s.readRef(ctx, h.Descriptor, 4096)
	if e != nil {
		return e
	}
	descriptor, e := parseGenerationDescriptor(raw)
	if e != nil {
		return e
	}
	add := func(ref ObjectRef) error {
		if old, ok := p.protected[ref.SHA256]; ok {
			if old.bytes != ref.Bytes {
				return ErrCorrupt
			}
			return nil
		}
		if len(p.protected) >= 2_100_000 {
			return ErrLimit
		}
		if !p.retainMetadata(48) {
			return ErrLimit
		}
		p.protected[ref.SHA256] = pruneReference{bytes: ref.Bytes}
		return nil
	}
	for _, ref := range []ObjectRef{h.Descriptor, descriptor.ObjectSet} {
		if e := add(ref); e != nil {
			return e
		}
	}
	set, e := s.openObjectSet(ctx, descriptor.ObjectSet)
	if e != nil {
		return e
	}
	defer set.Close()
	for {
		ref, ok, e := set.next()
		if e != nil {
			return e
		}
		if !ok {
			break
		}
		if e := add(ref); e != nil {
			return e
		}
	}
	return set.Close()
}
func (s *Store) pruneWriter(ctx context.Context) (*nativefs.OwnedLock, error) {
	writer, limit, e := s.acquireWriter(ctx)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*nativefs.OwnedLock, error) {
		closeErr := writer.Close()
		s.mu.Lock()
		s.active = false
		s.mu.Unlock()
		return nil, errors.Join(e, closeErr)
	}
	if e := s.ensureSelectionGate(ctx); e != nil {
		return fail(e)
	}
	if e := s.reconcileReservations(ctx, writer); e != nil {
		return fail(e)
	}
	if _, e := s.observeQuota(ctx, writer, limit); e != nil {
		return fail(e)
	}
	return writer, nil
}
func (s *Store) releasePruneWriter(writer *nativefs.OwnedLock) error {
	e := writer.Close()
	s.mu.Lock()
	s.active = false
	s.mu.Unlock()
	return e
}
func (s *Store) PreviewPrune(ctx context.Context) (result Preview, failure error) {
	if ctx == nil {
		return result, ErrUnavailable
	}
	work, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	writer, e := s.pruneWriter(work)
	if e != nil {
		return result, e
	}
	defer func() { failure = errors.Join(failure, s.releasePruneWriter(writer)) }()
	state, e := s.pruneState(work)
	if e != nil {
		return result, e
	}
	defer func() { failure = errors.Join(failure, state.Close()) }()
	path := "previews/" + hex.EncodeToString(state.preview.Token[:]) + ".json"
	// This zero-payload, durably flushed control retains only the commitment.
	// Apply must freshly reconstruct every canonical native fact and compare the
	// independently supplied token; marker text itself grants no authority.
	m, e := s.root.OpenMetadata(work, path)
	if e == nil {
		if m.Entry().Size != 0 {
			m.Close()
			return result, ErrCorrupt
		}
		_, e = s.owner.RetirementFingerprint(work, m)
		e = errors.Join(e, m.Close())
	} else {
		f, err := s.owner.CopyExclusive(work, path, bytes.NewReader(nil), 0)
		e = err
		if f != nil {
			e = errors.Join(e, f.Stable(), f.Close())
		}
	}
	if e != nil {
		return result, ErrUnavailable
	}
	return state.preview, nil
}
func (s *Store) ApplyPrune(ctx context.Context, token ID) (result PruneResult, failure error) {
	if token == (ID{}) {
		return result, ErrUntrusted
	}
	if s == nil || ctx == nil {
		return result, ErrUnavailable
	}
	result.Token = token
	work, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	writer, e := s.pruneWriter(work)
	if e != nil {
		return result, e
	}
	defer func() {
		failure = errors.Join(failure, s.releasePruneWriter(writer))
		if failure != nil && (result.Generations != 0 || result.RemovedFiles != 0 || result.QuarantinedFiles != 0) {
			result.Partial = true
		}
	}()
	path := "previews/" + hex.EncodeToString(token[:]) + ".json"
	m, e := s.root.OpenMetadata(work, path)
	if e != nil {
		return result, ErrUntrusted
	}
	if m.Entry().Size != 0 {
		m.Close()
		return result, ErrCorrupt
	}
	_, e = s.owner.RetirementFingerprint(work, m)
	e = errors.Join(e, m.Close())
	if e != nil {
		return result, ErrUntrusted
	}
	state, e := s.pruneState(work)
	if e != nil {
		return result, e
	}
	defer func() { failure = errors.Join(failure, state.Close()) }()
	if state.preview.Token != token {
		return result, ErrUntrusted
	}
	// Whole candidate/control preflight completes before a tombstone or unlink.
	for _, group := range [][]pruneCandidate{state.controls, state.candidates} {
		for _, old := range group {
			now, e := s.pruneMetadata(work, old.name, true)
			if e != nil || now != old {
				return result, ErrUntrusted
			}
		}
	}
	gate, e := s.root.TryOwnedLock(work, "locks/selection.lock", true)
	if e != nil {
		return result, ErrBusy
	}
	for _, gen := range state.generations {
		if gen.lease.Matches(work, s.root, "generations/"+hex.EncodeToString(gen.id[:])+"/read.lock", true) != nil {
			gate.Close()
			return result, ErrBinding
		}
		if !gen.retired {
			f, e := s.owner.CopyExclusive(work, "generations/"+hex.EncodeToString(gen.id[:])+"/retired", bytes.NewReader(nil), 0)
			if f != nil {
				e = errors.Join(e, f.Stable(), f.Close())
			}
			if e != nil {
				gate.Close()
				return result, ErrUnavailable
			}
			result.Generations++
		}
	}
	if e := gate.Close(); e != nil {
		return result, e
	}
	if len(state.candidates) == 0 {
		return result, nil
	}
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return result, ErrUnavailable
	}
	trash := "quarantine/" + hex.EncodeToString(nonce[:])
	if e := s.owner.Mkdir(work, trash); e != nil {
		return result, ErrUnavailable
	}
	for i, c := range state.candidates {
		if e := work.Err(); e != nil {
			return result, e
		}
		if strings.HasSuffix(c.name, "/intent.json") {
			parent := c.name[:strings.LastIndexByte(c.name, '/')]
			remaining, e := s.pruneDirectory(work, parent)
			if e != nil || len(remaining) != 1 || remaining[0].Name != c.name {
				return result, ErrUntrusted
			}
		}
		m, e := s.root.OpenMetadata(work, c.name)
		if e != nil {
			return result, ErrUnavailable
		}
		fp, e := s.owner.RetirementFingerprint(work, m)
		if e != nil || fp != c.fingerprint {
			m.Close()
			return result, ErrUntrusted
		}
		retired, e := s.owner.Quarantine(work, m, fmt.Sprintf("%s/%016x", trash, i))
		closeErr := m.Close()
		if e != nil || closeErr != nil {
			if retired != nil {
				retired.Close()
			}
			result.Partial = true
			return result, errors.Join(ErrBinding, e, closeErr)
		}
		result.QuarantinedFiles++
		e = retired.Remove(work)
		closeErr = retired.Close()
		if e != nil || closeErr != nil {
			return result, errors.Join(ErrUnavailable, e, closeErr)
		}
		result.RemovedFiles++
		result.RemovedBytes += c.bytes
	}
	return result, writer.Matches(work, s.root, "writer.lock", true)
}
