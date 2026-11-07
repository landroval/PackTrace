package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"packtrace/internal/intelstore"
	"packtrace/internal/nativefs"
)

type scanFileOutputState struct {
	mu                           sync.Mutex
	cfg                          scanFileOutputConfig
	plan                         *nativefs.PublicationPlan
	target, reference            *nativefs.Root
	ownsTarget                   bool
	attempted, fulfilled, closed bool
}

// Read-only admission, before acquisition. An intelligence owner is borrowed,
// including its exact private store and generation pin; never opened implicitly.
func (r *ScanRun) prepareFileOutput(ctx context.Context, target, policyDirectory, destination string) error {
	s := r.output.state
	if s == nil {
		return errOutput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scan == nil || s.broken || r.fileOutput != nil {
		return errOutput
	}
	f := &scanFileOutputState{cfg: scanFileOutputConfig{Target: target, PolicyDirectory: policyDirectory, Destination: destination}}
	r.fileOutput = f // Retain even partial admission until Finish.
	var e error
	if q := s.intelligence; q != nil {
		if q.check(ctx) != nil || q.store == nil {
			return errOutput
		}
		f.target = q.target
		cfg := q.cfg
		f.cfg.Intelligence = &cfg
	} else {
		f.target, e = nativefs.OpenRoot(ctx, target)
		f.ownsTarget = true
		if e != nil {
			return errOutput
		}
	}
	if policyDirectory != "" {
		f.reference, e = f.target.OpenExternalRoot(ctx, policyDirectory)
		if e != nil {
			return errOutput
		}
	}
	f.plan, e = openScanFilePlan(ctx, f.target, s.intelligence, f.reference, destination)
	if e != nil {
		return errOutput
	}
	f.cfg.Binding, e = f.plan.Binding()
	if e != nil || !f.cfg.valid() {
		return errOutput
	}
	return nil
}

func openScanFilePlan(ctx context.Context, target *nativefs.Root, owner *scanIntelligenceOwner, reference *nativefs.Root, destination string) (*nativefs.PublicationPlan, error) {
	var refs []*nativefs.Root
	if reference != nil {
		refs = append(refs, reference)
	}
	if owner != nil {
		if owner.target != target || owner.store == nil || owner.check(ctx) != nil {
			return nil, errOutput
		}
		return owner.store.OpenReportPlan(ctx, target, refs, destination)
	}
	return nativefs.OpenPublicationPlan(ctx, target, refs, destination)
}

func (r *ScanRun) fileOutputConfig() *scanFileOutputConfig {
	if r.fileOutput == nil {
		return nil
	}
	f := r.fileOutput
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.cfg
	if c.Intelligence != nil {
		v := *c.Intelligence
		c.Intelligence = &v
	}
	return &c
}

// Acquisition binds the plan to its ACTUAL retained roots, not an extra root
// opened just to pass a token check. Caller holds plan/reference/owner to closure.
func bindScanFileAcquisition(ctx context.Context, target *nativefs.Root, owner *scanIntelligenceOwner, reference *nativefs.Root, cfg *scanFileOutputConfig) (*nativefs.PublicationPlan, error) {
	if !cfg.valid() || (reference != nil) != (cfg.PolicyDirectory != "") || (owner != nil) != (cfg.Intelligence != nil) {
		return nil, errOutput
	}
	if owner != nil {
		v := cfg.Intelligence
		if owner.cfg.Path != v.Path || owner.cfg.TrustedDigest != v.TrustedDigest || owner.cfg.Generation != v.Generation || owner.cfg.Binding != v.Binding || owner.cfg.TargetBinding != v.TargetBinding || owner.check(ctx) != nil {
			return nil, errOutput
		}
	}
	p, e := openScanFilePlan(ctx, target, owner, reference, cfg.Destination)
	if e != nil {
		return nil, errOutput
	}
	binding, e := p.Binding()
	if e != nil || binding != cfg.Binding {
		_ = p.Close()
		return nil, errOutput
	}
	return p, nil
}

func (f *scanFileOutputState) check() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.plan == nil {
		return errOutput
	}
	var e error
	if f.attempted {
		e = f.plan.CheckSources()
	} else {
		e = f.plan.Check()
	}
	if e != nil {
		return errOutput
	}
	return nil
}

// Only final report bytes use this routing. Historical diagnostics/stdout still
// use WriteOutput, which always passes nil file configuration to the transport.
func (r *ScanRun) WriteReportOutput(ctx context.Context, out io.Writer, data []byte) error {
	if r.fileOutput == nil {
		return r.WriteOutput(ctx, out, data)
	}
	if e := r.Checkpoint(); e != nil {
		return e
	}
	f := r.fileOutput
	f.mu.Lock()
	if f.closed || f.attempted || f.plan == nil || f.plan.Check() != nil {
		f.mu.Unlock()
		return errOutput
	}
	f.attempted = true // No retry/adoption, even on uncertain failed publication.
	cfg := f.cfg
	f.mu.Unlock()
	e := r.output.writeOutput(ctx, nil, data, &cfg)
	s := r.output.state
	s.mu.Lock()
	if e == nil {
		if s.broken || s.scan == nil || !s.scan.snapshot().CleanupConfirmed {
			e = errReap
		} else {
			f.mu.Lock()
			if f.plan.Fulfill() != nil {
				e = errOutput
			} else {
				f.fulfilled = true
			}
			f.mu.Unlock()
		}
	}
	s.mu.Unlock()
	r.NoteFailure("output", e)
	if observed := r.Checkpoint(); observed != nil {
		return observed
	}
	return e
}

// Called only with confirmed final cleanup, before the borrowed owner closes.
func (f *scanFileOutputState) finish() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	var e error
	if f.plan != nil {
		e = errors.Join(f.plan.CheckSources(), f.plan.Close())
	}
	if f.reference != nil {
		e = errors.Join(e, f.reference.Close())
	}
	if f.ownsTarget && f.target != nil {
		e = errors.Join(e, f.target.Close())
	}
	f.closed = true
	if e != nil {
		return errOutput
	}
	return nil
}

func openWriterIntelligence(ctx context.Context, target string, cfg scanIntelligenceConfig) (*scanIntelligenceOwner, error) {
	var forced *intelstore.ID
	if cfg.Generation != "" {
		if !intelResultID(cfg.Generation) {
			return nil, errOutput
		}
		raw, _ := hex.DecodeString(cfg.Generation)
		var id intelstore.ID
		copy(id[:], raw)
		forced = &id
	}
	o, e := openScanIntelligence(ctx, target, cfg.Path, cfg.TrustedDigest, forced)
	if e != nil {
		return o, errOutput
	}
	if o.cfg.Generation != cfg.Generation || o.cfg.Binding != cfg.Binding || o.cfg.TargetBinding != cfg.TargetBinding || o.store == nil || o.check(ctx) != nil {
		return o, errOutput
	}
	return o, nil
}

// Called only AFTER full approved transfer/hash/EOF verification. All native
// mutation, sync, no-clobber commit and closure occur inside the observed child.
func writeScanFile(cfg *scanFileOutputConfig, witness *os.File, data []byte) (failure error) {
	if !cfg.valid() {
		return errOutput
	}
	var sentinel [1]byte
	n, e := witness.Read(sentinel[:])
	if n != 0 || e != io.EOF {
		return errOutput
	}
	if nativefs.PrepareProcess() != nil {
		return errOutput
	}
	debug.SetMemoryLimit(512 << 20)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var target *nativefs.Root
	var owner *scanIntelligenceOwner
	if cfg.Intelligence != nil {
		// Open metadata + original generation pin only. The writer never reads
		// a snapshot/content or reevaluates policy/intelligence.
		owner, e = openWriterIntelligence(ctx, cfg.Target, *cfg.Intelligence)
		if owner != nil {
			defer func() {
				if owner.close() != nil {
					failure = errOutput
				}
			}()
		}
		if e != nil {
			return errOutput
		}
		target = owner.target
	} else {
		target, e = nativefs.OpenRoot(ctx, cfg.Target)
		if e != nil {
			return errOutput
		}
		defer func() {
			if target.Close() != nil {
				failure = errOutput
			}
		}()
	}
	var reference *nativefs.Root
	if cfg.PolicyDirectory != "" {
		reference, e = target.OpenExternalRoot(ctx, cfg.PolicyDirectory)
		if e != nil {
			return errOutput
		}
		defer func() {
			if reference.Close() != nil {
				failure = errOutput
			}
		}()
	}
	p, e := bindScanFileAcquisition(ctx, target, owner, reference, cfg)
	if e != nil {
		return errOutput
	}
	defer func() {
		if p.Close() != nil {
			failure = errOutput
		}
	}()
	pub, e := p.Begin()
	if e != nil {
		return errOutput
	}
	defer func() {
		if pub.Close() != nil {
			failure = errOutput
		}
	}()
	if n, e := pub.Write(data); e != nil || n != len(data) {
		return errOutput
	}
	if pub.Commit() != nil || pub.Close() != nil || p.CheckSources() != nil {
		return errOutput
	}
	if owner != nil && owner.check(ctx) != nil {
		return errOutput
	}
	return nil
}
