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
	"io"
	"packtrace/internal/nativefs"
	"sync"
	"time"
)

type Budget struct {
	Requests, HTTPBytes, ExpandedBytes, Entries, StagingBytes uint64
	Deadline                                                  time.Time
}
type operation uint8

const (
	operationSync operation = iota
	operationImport
	operationMaintenance
)

type ObjectRef struct {
	SHA256 [32]byte
	Bytes  uint64
}
type Transaction struct {
	mu       sync.Mutex
	store    *Store
	writer   *nativefs.OwnedLock
	work     context.Context
	cancel   context.CancelFunc
	id       ID
	path     string
	held     uint64
	written  uint64
	sequence uint64
	budget   Budget
	failed   error
	closed   bool
	sealed   map[ID]sealedGeneration
	prep     *preparationState
}
type reservationJournal struct {
	Version        int    `json:"version"`
	Instance       string `json:"instance"`
	Operation      uint8  `json:"operation"`
	Reservation    uint64 `json:"reservation"`
	PreviousUsed   uint64 `json:"previousUsed"`
	Reconciliation string `json:"reconciliation"`
}

func (s *Store) begin(ctx context.Context, kind operation, b *Budget) (*Transaction, error) {
	if s == nil || ctx == nil || b == nil || kind > operationMaintenance {
		return nil, ErrUnavailable
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	s.mu.Lock()
	if s.root == nil || s.owner == nil || s.mode != CreateOwned {
		s.mu.Unlock()
		return nil, ErrUnavailable
	}
	if s.active {
		s.mu.Unlock()
		return nil, ErrBusy
	}
	s.active = true
	limit := s.quotaLimit
	if limit == 0 {
		limit = 32 << 30
	}
	owner, root := s.owner, s.root
	s.mu.Unlock()
	failActive := func() { s.mu.Lock(); s.active = false; s.mu.Unlock() }
	// Create this permanent inode once. A failed exclusive create is not enough
	// to admit it: the actual native lock constructor rechecks type/link/binding.
	marker, e := root.OpenMetadata(ctx, "writer.lock")
	if e != nil {
		e = owner.WriteControl(ctx, "writer.lock", nil)
	} else {
		e = errors.Join(marker.Stable(), marker.Close())
	}
	if e != nil {
		failActive()
		return nil, ErrUnavailable
	}
	writer, e := root.TryOwnedLock(ctx, "writer.lock", true)
	if e != nil {
		failActive()
		if errors.Is(e, nativefs.ErrBusy) {
			return nil, ErrBusy
		}
		return nil, ErrUnavailable
	}
	fail := func(e error) (*Transaction, error) {
		closeErr := writer.Close()
		failActive()
		return nil, errors.Join(e, closeErr)
	}
	if e := s.ensureSelectionGate(ctx); e != nil {
		return fail(e)
	}
	if e := s.reconcileReservations(ctx, writer); e != nil {
		return fail(e)
	}
	quota, e := s.observeQuota(ctx, writer, limit)
	if e != nil {
		return fail(e)
	}
	budget := *b
	if budget.StagingBytes == 0 {
		budget.StagingBytes = 16 << 30
	}
	if budget.StagingBytes < 8192 || budget.StagingBytes > 16<<30 {
		return fail(ErrLimit)
	}
	if _, e := quota.reserve(budget.StagingBytes, limit); e != nil {
		return fail(e)
	}
	deadline := time.Now().Add(15 * time.Minute)
	if !budget.Deadline.IsZero() && budget.Deadline.Before(deadline) {
		deadline = budget.Deadline
	}
	budget.Deadline = deadline
	work, cancel := context.WithDeadline(ctx, deadline)
	t := &Transaction{store: s, writer: writer, work: work, cancel: cancel, budget: budget, held: budget.StagingBytes}
	if _, e := rand.Read(t.id[:]); e != nil {
		cancel()
		return fail(ErrUnavailable)
	}
	t.path = "staging/" + hex.EncodeToString(t.id[:])
	if e := owner.Mkdir(work, t.path); e != nil {
		cancel()
		return fail(ErrUnavailable)
	}
	journal := reservationJournal{1, hex.EncodeToString(s.instance[:]), uint8(kind), budget.StagingBytes, quota.used, "exclusive-lease-and-complete-native-lengths"}
	data, e := json.Marshal(journal)
	if e != nil {
		cancel()
		return fail(ErrUnavailable)
	}
	// This sync/checked-close receipt reserves capacity BEFORE any input reader.
	f, e := owner.CopyExclusive(work, t.path+"/intent.tmp", bytes.NewReader(data), 4096)
	if f != nil {
		n := uint64(f.Size())
		t.held -= n
		t.written += n
		if e == nil {
			e = f.Stable()
		}
		if e == nil {
			e = owner.Publish(work, f, t.path+"/intent.json", false)
		}
		e = errors.Join(e, f.Close())
	}
	if e != nil {
		cancel()
		return fail(ErrUnavailable)
	}
	return t, nil
}

func (t *Transaction) put(ctx context.Context, input io.Reader, max uint64) (ObjectRef, error) {
	if t == nil {
		return ObjectRef{}, ErrUnavailable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.putLocked(ctx, input, max)
}

func (t *Transaction) putLocked(ctx context.Context, input io.Reader, max uint64) (ObjectRef, error) {
	if t.closed || t.failed != nil || ctx == nil || input == nil {
		return ObjectRef{}, ErrUnavailable
	}
	fail := func(e error) (ObjectRef, error) { t.failed = e; return ObjectRef{}, e }
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	if e := t.work.Err(); e != nil {
		return fail(e)
	}
	if max > 512<<20 || t.held < 4096 || max > t.held-4096 || t.sequence >= 2_000_000+65_536+1024 {
		return fail(ErrLimit)
	}
	if e := t.writer.Matches(ctx, t.store.root, "writer.lock", true); e != nil {
		return fail(ErrUnavailable)
	}
	t.sequence++
	name := fmt.Sprintf("%s/object-%016x", t.path, t.sequence)
	h := sha256.New()
	work, cancel := context.WithCancel(t.work)
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	f, e := t.store.owner.CopyExclusive(work, name, io.TeeReader(input, h), max)
	if f != nil {
		n := uint64(f.Size())
		t.written += n
		if n > t.held {
			f.Close()
			return fail(ErrLimit)
		}
		t.held -= n
	}
	if e != nil {
		if f != nil {
			f.Close()
		}
		return fail(ErrUnavailable)
	}
	defer f.Close()
	if e := f.Stable(); e != nil {
		return fail(ErrCorrupt)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	ref := ObjectRef{sum, uint64(f.Size())}
	key := hex.EncodeToString(sum[:])
	parent := "objects/" + key[:2]
	dest := parent + "/" + key
	if e := t.store.owner.Mkdir(work, parent); e != nil {
		return fail(ErrUnavailable)
	}
	e = t.store.owner.Publish(work, f, dest, false)
	if errors.Is(e, nativefs.ErrExists) {
		old, e := t.store.root.OpenInput(work, dest, int64(ref.Bytes))
		if e != nil {
			return fail(ErrCorrupt)
		}
		verifier := sha256.New()
		count, copyErr := io.Copy(verifier, old)
		stableErr, closeErr := old.Stable(), old.Close()
		if copyErr != nil || stableErr != nil || closeErr != nil || uint64(count) != ref.Bytes || !bytes.Equal(verifier.Sum(nil), sum[:]) {
			return fail(ErrCorrupt)
		}
		// Retain this known-owned duplicate until an explicit checked cleanup. It
		// remains charged; successful dedup never refunds an uncertain unlink.
	} else if e != nil {
		return fail(ErrUnavailable)
	}
	if e := f.Close(); e != nil {
		return fail(ErrUnavailable)
	}
	return ref, nil
}

func (t *Transaction) Close() error {
	if t == nil {
		return ErrUnavailable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return ErrUnavailable
	}
	t.closed = true
	var receiptErr error
	if t.work.Err() == nil && t.held >= 4096 {
		data, _ := json.Marshal(struct {
			Version int    `json:"version"`
			Written uint64 `json:"written"`
			Failed  bool   `json:"failed"`
		}{1, t.written, t.failed != nil})
		f, e := t.store.owner.CopyExclusive(t.work, t.path+"/closed.json", bytes.NewReader(data), 4096)
		if f != nil {
			e = errors.Join(e, f.Stable(), f.Close())
		}
		receiptErr = e
	}
	t.cancel()
	leaseErr := t.writer.Close()
	t.store.mu.Lock()
	t.store.active = false
	t.store.mu.Unlock()
	return errors.Join(t.failed, receiptErr, leaseErr)
}
