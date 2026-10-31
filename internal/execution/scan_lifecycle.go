package execution

import (
	"context"
	"errors"
	"sync"
	"time"

	"packtrace/internal/integrityscan"
	"packtrace/internal/nativefs"
	"packtrace/internal/nativeresource"
)

// ScanRoleReceipt is caller-owned operational evidence, not a prediction in
// public bytes rendered before the writer runs. ExitObserved is NOT Reaped.
type ScanRoleReceipt struct {
	Role                 string
	PID                  int
	Samples              int
	PeakResidentBytes    uint64
	ExitObserved, Reaped bool
}
type ScanReceipt struct {
	Resources                  integrityscan.Resources
	Roles                      []ScanRoleReceipt
	MaxSampleGap               time.Duration
	Finished, CleanupConfirmed bool
}

// SCAN-only. Legacy RunBatch never constructs this observer and its writer
// retains exactly the old protocol, availability requirements and byte path.
type scanLifecycle struct {
	mu                sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	stop, joined      chan struct{}
	once              sync.Once
	resources         integrityscan.Resources
	roles             []ScanRoleReceipt
	child             *nativeresource.Child
	active            int
	last              time.Time
	maxGap            time.Duration
	finished, cleanup bool
	finishErr         error
}

func newScanLifecycle(ctx context.Context, deadline time.Time) *scanLifecycle {
	work, cancel := context.WithDeadline(ctx, deadline)
	m := &scanLifecycle{ctx: work, cancel: cancel, stop: make(chan struct{}), joined: make(chan struct{}), active: -1, cleanup: true}
	m.tick()
	go func() {
		defer close(m.joined)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-ticker.C:
				m.tick()
			}
		}
	}()
	return m
}
func (m *scanLifecycle) faultLocked() bool {
	return m.resources.QueryFailed || m.resources.Stale || m.resources.Stopped
}
func (m *scanLifecycle) tick() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tickLocked()
}
func (m *scanLifecycle) tickLocked() {
	now := time.Now()
	if !m.last.IsZero() {
		gap := now.Sub(m.last)
		m.maxGap = max(m.maxGap, gap)
		if gap > 350*time.Millisecond {
			m.resources.Stale = true
		}
	}
	m.last = now
	own, e := nativefs.OwnResidentBytes()
	if e != nil || own == 0 {
		m.resources.QueryFailed = true
	} else {
		m.resources.SupervisorSamples++
		m.resources.SupervisorPeakBytes = max(m.resources.SupervisorPeakBytes, own)
	}
	sum := own
	if m.child != nil {
		n, live, e := m.child.Sample()
		r := &m.roles[m.active]
		if e != nil || live && n == 0 {
			m.resources.QueryFailed = true
		} else if !live {
			r.ExitObserved = true
		} else {
			r.Samples++
			r.PeakResidentBytes = max(r.PeakResidentBytes, n)
			m.resources.WorkerSamples++
			m.resources.WorkerPeakBytes = max(m.resources.WorkerPeakBytes, n)
			if n > ^uint64(0)-own {
				m.resources.Stopped = true
			} else {
				sum += n
			}
		}
	}
	m.resources.PeakSampledSumBytes = max(m.resources.PeakSampledSumBytes, sum)
	if sum > 1<<30 {
		m.resources.Stopped = true
	}
	if m.faultLocked() {
		m.cancel()
	}
}
func (m *scanLifecycle) attach(pid int, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.child != nil || m.finished || !m.cleanup {
		return errReap
	}
	child, e := nativeresource.PinChild(pid) // BEFORE cmd.Wait: direct, unreaped child
	m.roles = append(m.roles, ScanRoleReceipt{Role: role, PID: pid})
	m.active = len(m.roles) - 1
	m.cleanup = false
	if e != nil {
		m.resources.QueryFailed = true
		m.cancel()
		return errScanResource
	}
	m.child = child
	m.tickLocked()
	if m.faultLocked() {
		return errScanResource
	}
	return nil
}

// Called only AFTER runChild has confirmed Wait and joined control/stderr.
func (m *scanLifecycle) reaped(confirmed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tickLocked()
	if m.active >= 0 {
		r := &m.roles[m.active]
		r.Reaped = confirmed
		if confirmed {
			r.ExitObserved = true
		}
		// No live observation is not a successful zero/missing sample.
		if r.Samples == 0 {
			m.resources.Stale = true
			m.cancel()
		}
	}
	m.cleanup = confirmed
	if m.child != nil {
		_ = m.child.Close()
		m.child = nil
	}
	m.active = -1
}
func (m *scanLifecycle) protocolResult(r integrityscan.Resources) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resources.QueryFailed = m.resources.QueryFailed || r.QueryFailed
	m.resources.Stale = m.resources.Stale || r.Stale
	m.resources.Stopped = m.resources.Stopped || r.Stopped
	if m.faultLocked() {
		m.cancel()
	}
}
func (m *scanLifecycle) snapshot() ScanReceipt {
	m.mu.Lock()
	defer m.mu.Unlock()
	return ScanReceipt{Resources: m.resources, Roles: append([]ScanRoleReceipt(nil), m.roles...), MaxSampleGap: m.maxGap, Finished: m.finished, CleanupConfirmed: m.cleanup}
}
func (m *scanLifecycle) check() error {
	r := m.snapshot()
	if !r.CleanupConfirmed && r.Finished {
		return errReap
	}
	if r.Resources.QueryFailed || r.Resources.Stale || r.Resources.Stopped {
		return errScanResource
	}
	if m.ctx.Err() != nil {
		return errors.New("scan: interrupted-or-deadline")
	}
	return nil
}
func (m *scanLifecycle) finish() (ScanReceipt, error) {
	m.once.Do(func() {
		close(m.stop)
		<-m.joined
		m.tick()
		m.mu.Lock()
		m.finished = true
		m.mu.Unlock()
		m.finishErr = m.check()
		m.cancel()
	})
	return m.snapshot(), m.finishErr
}

// Checkpoint covers parent rendering as well as the gaps between child roles.
// It neither grants completion nor includes future writer/teardown metrics.
func (r *ScanRun) Checkpoint() error {
	if r.output.state == nil {
		return errScanResource
	}
	s := r.output.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scan == nil {
		return errScanResource
	}
	s.scan.tick()
	r.Resources = s.scan.snapshot().Resources
	if e := s.contextError(s.caller); e != nil {
		return e
	}
	return s.scan.check()
}

// Finish must be called by the owner AFTER the last output attempt. The final
// receipt is retained in the caller; already-written bytes cannot be rewritten.
func (r *ScanRun) Finish() (ScanReceipt, error) {
	if r.output.state == nil || r.output.state.scan == nil {
		return ScanReceipt{}, nil
	}
	s := r.output.state
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, e := s.scan.finish()
	r.Operational = receipt
	r.Resources = receipt.Resources
	if s.broken {
		return receipt, errReap
	}
	return receipt, e
}
