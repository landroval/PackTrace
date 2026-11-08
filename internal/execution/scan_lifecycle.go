package execution

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"packtrace/internal/integrityscan"
	"packtrace/internal/nativefs"
	"packtrace/internal/nativeresource"
)

// ScanRoleReceipt is caller-owned operational evidence, not a prediction in
// public bytes rendered before the writer runs. ExitObserved is NOT Reaped.
type ScanRoleReceipt struct {
	Role                                                          string
	PID                                                           int
	Samples                                                       int
	PeakResidentBytes                                             uint64
	ExitObserved, Reaped                                          bool
	ExchangeJoined, ExchangeSucceeded, WaitReturned, StderrJoined bool
	ExitCode                                                      int // meaningful only when WaitReturned; -1 if no process state
	CallerContext, WorkContext, LifecycleContext                  string
}
type ScanReceipt struct {
	Resources                       integrityscan.Resources
	Roles                           []ScanRoleReceipt
	MaxSampleGap                    time.Duration
	ConcurrentSamples               int // actual ticks with both admitted Intel roles live
	Finished, CleanupConfirmed      bool
	FirstFault                      ScanFault
	CallerContext, LifecycleContext string
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
	progressChild     *nativeresource.Child
	progressActive    int
	allowProgress     bool // only explicit Intel preparation; never SCAN or legacy batches
	last              time.Time
	maxGap            time.Duration
	concurrentSamples int
	finished, cleanup bool
	finishErr         error
	started           time.Time
	caller            context.Context
	firstFault        ScanFault
	finalContext      string
}

func newScanLifecycle(ctx context.Context, deadline time.Time) *scanLifecycle {
	work, cancel := context.WithDeadline(ctx, deadline)
	m := &scanLifecycle{ctx: work, cancel: cancel, stop: make(chan struct{}), joined: make(chan struct{}), active: -1, progressActive: -1, cleanup: true, started: time.Now(), caller: ctx}
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
			m.faultLockedAt("sample-gap", nil)
			m.resources.Stale = true
		}
	}
	m.last = now
	own, e := nativefs.OwnResidentBytes()
	if e != nil || own == 0 {
		m.faultLockedAt("supervisor-resident", e)
		m.resources.QueryFailed = true
	} else {
		m.resources.SupervisorSamples++
		m.resources.SupervisorPeakBytes = max(m.resources.SupervisorPeakBytes, own)
	}
	sum := own
	liveChildren := 0
	for _, slot := range []struct {
		child *nativeresource.Child
		index int
	}{{m.child, m.active}, {m.progressChild, m.progressActive}} {
		if slot.child == nil {
			continue
		}
		n, live, e := slot.child.Sample()
		r := &m.roles[slot.index]
		if e != nil || live && n == 0 {
			m.faultLockedRole("child-resident", e, r.Role)
			m.resources.QueryFailed = true
		} else if !live {
			r.ExitObserved = true
		} else {
			liveChildren++
			r.Samples++
			r.PeakResidentBytes = max(r.PeakResidentBytes, n)
			m.resources.WorkerSamples++
			m.resources.WorkerPeakBytes = max(m.resources.WorkerPeakBytes, n)
			if n > ^uint64(0)-sum {
				m.faultLockedAt("resident-overflow", nil)
				m.resources.Stopped = true
			} else {
				sum += n
			}
		}
	}
	if liveChildren > 1 {
		m.concurrentSamples++
	}
	m.resources.PeakSampledSumBytes = max(m.resources.PeakSampledSumBytes, sum)
	if sum > 1<<30 {
		m.faultLockedAt("resident-threshold", nil)
		m.resources.Stopped = true
	}
	if m.faultLocked() {
		m.cancel()
	}
}
func (m *scanLifecycle) attach(process *os.Process, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if process == nil || process.Pid <= 0 || m.finished {
		return errReap
	}
	progress := role == "intel-progress"
	if progress {
		if !m.allowProgress || m.progressActive >= 0 || m.active < 0 || m.child == nil || m.roles[m.active].Role != "intel" {
			return errReap
		}
	} else if m.child != nil || m.progressActive >= 0 || !m.cleanup {
		return errReap
	}
	child, e := nativeresource.PinProcess(process) // BEFORE cmd.Wait: actual unreaped child
	m.roles = append(m.roles, ScanRoleReceipt{Role: role, PID: process.Pid})
	if progress {
		m.progressActive = len(m.roles) - 1
	} else {
		m.active = len(m.roles) - 1
	}
	m.cleanup = false
	if e != nil {
		m.faultLockedRole("child-pin", e, role)
		m.resources.QueryFailed = true
		m.cancel()
		return errScanResource
	}
	if progress {
		m.progressChild = child
	} else {
		m.child = child
	}
	m.tickLocked()
	if m.faultLocked() {
		return errScanResource
	}
	return nil
}

// Called only AFTER runChild has confirmed Wait and joined control/stderr.
func (m *scanLifecycle) roleIndexLocked(pid int) int {
	for i := len(m.roles) - 1; i >= 0; i-- {
		if m.roles[i].PID == pid {
			return i
		}
	}
	return -1
}
func (m *scanLifecycle) reaped(pid int, confirmed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tickLocked()
	index := m.roleIndexLocked(pid)
	if index >= 0 {
		r := &m.roles[index]
		r.Reaped = confirmed
		if confirmed {
			r.ExitObserved = true
		}
		// No live observation is not a successful zero/missing sample.
		if r.Samples == 0 {
			m.faultLockedAt("child-no-live-sample", nil)
			m.resources.Stale = true
			m.cancel()
		}
	}
	if index == m.active {
		if m.child != nil {
			_ = m.child.Close()
			m.child = nil
		}
		m.active = -1
	}
	if index == m.progressActive {
		if m.progressChild != nil {
			_ = m.progressChild.Close()
			m.progressChild = nil
		}
		m.progressActive = -1
	}
	m.cleanup = true
	for _, r := range m.roles {
		m.cleanup = m.cleanup && r.Reaped
	}
}
func (m *scanLifecycle) protocolResult(r integrityscan.Resources) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resources.QueryFailed = m.resources.QueryFailed || r.QueryFailed
	m.resources.Stale = m.resources.Stale || r.Stale
	m.resources.Stopped = m.resources.Stopped || r.Stopped
	if m.faultLocked() {
		m.faultLockedAt("protocol-resident", nil)
		m.cancel()
	}
}
func (m *scanLifecycle) snapshot() ScanReceipt {
	m.mu.Lock()
	defer m.mu.Unlock()
	lifecycleContext := scanContextStatus(m.ctx)
	if m.finished {
		lifecycleContext = m.finalContext
	}
	return ScanReceipt{Resources: m.resources, Roles: append([]ScanRoleReceipt(nil), m.roles...), MaxSampleGap: m.maxGap, ConcurrentSamples: m.concurrentSamples, Finished: m.finished, CleanupConfirmed: m.cleanup, FirstFault: m.firstFault, CallerContext: scanContextStatus(m.caller), LifecycleContext: lifecycleContext}
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
		if e := m.ctx.Err(); e != nil {
			m.faultLockedAt("finish-context", e)
		}
		if !m.cleanup {
			m.faultLockedAt("cleanup", errReap)
		}
		m.finished = true
		m.finalContext = scanContextStatus(m.ctx)
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
	if s.intelligence != nil {
		if e := s.intelligence.check(s.caller); e != nil {
			s.scan.noteFault("intelligence-binding", e)
			return e
		}
	}
	if r.userSetup != nil {
		if e := r.userSetup.check(s.caller); e != nil {
			s.scan.noteFault("user-setup-binding", e)
			return e
		}
	}
	if r.bunCache != nil {
		if e := r.bunCache.check(); e != nil {
			s.scan.noteFault("bun-cache-binding", e)
			return e
		}
	}
	if r.fileOutput != nil {
		if e := r.fileOutput.check(); e != nil {
			s.scan.noteFault("file-output-binding", e)
			return e
		}
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
	if s.broken.Load() {
		s.scan.noteFault("cleanup", errReap)
	}
	receipt, e := s.scan.finish()
	if f := r.fileOutput; f != nil && receipt.CleanupConfirmed && !s.broken.Load() {
		if closeErr := f.finish(); closeErr != nil {
			s.scan.noteFault("file-output-close", closeErr)
			e = errors.Join(e, closeErr)
			receipt = s.scan.snapshot()
		}
	}
	if q := r.bunCache; q != nil && receipt.CleanupConfirmed && !s.broken.Load() {
		if !q.closed {
			cacheErr := errors.Join(q.check(), q.close())
			if cacheErr != nil {
				s.scan.noteFault("bun-cache-close", cacheErr)
				e = errors.Join(e, cacheErr)
				receipt = s.scan.snapshot()
			}
		}
	}
	if q := s.intelligence; q != nil && receipt.CleanupConfirmed && !s.broken.Load() {
		if !q.closed {
			bindingErr := q.check(s.caller)
			closeErr := q.close()
			q.closeErr = errors.Join(bindingErr, closeErr)
		}
		if q.closeErr != nil {
			s.scan.noteFault("intelligence-close", q.closeErr)
			e = errors.Join(e, q.closeErr)
			receipt = s.scan.snapshot()
		}
	}
	if q := r.userSetup; q != nil && receipt.CleanupConfirmed && !s.broken.Load() && !q.closed {
		setupErr := errors.Join(q.check(s.caller), q.close())
		if setupErr != nil {
			s.scan.noteFault("user-setup-close", setupErr)
			e = errors.Join(e, setupErr)
			receipt = s.scan.snapshot()
		}
	}
	r.Operational = receipt
	r.Resources = receipt.Resources
	if s.broken.Load() {
		return receipt, errReap
	}
	return receipt, e
}
