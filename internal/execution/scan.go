package execution

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/integrity"
	"packtrace/internal/integrityscan"
	"packtrace/internal/nativefs"
)

const ScanWorkerArgument = "--internal-integrity-scan-worker-v1"

var errScanProtocol = errors.New("scan: worker-protocol")
var errScanResource = errors.New("scan: resident-observation-failed")

type ScanRun struct {
	Plan                integrityscan.Plan
	Records             []integrityscan.Record
	Summary             integrityscan.Summary
	Resources           integrityscan.Resources // comparison checkpoint, updated by Checkpoint/Finish
	Operational         ScanReceipt             // populated only by Finish, never predicted in public bytes
	Usable, Interrupted bool
	output              BatchRun
}

func (r *ScanRun) WriteOutput(ctx context.Context, out io.Writer, data []byte) error {
	if r.output.state != nil && r.output.state.scan != nil {
		if e := r.Checkpoint(); e != nil {
			return e
		}
	}
	e := r.output.WriteOutput(ctx, out, data)
	if r.output.state != nil && r.output.state.scan != nil {
		if observed := r.Checkpoint(); observed != nil {
			return observed
		}
	}
	return e
}

type scanConfig struct {
	Nonce      string              `json:"nonce"`
	Stage      string              `json:"stage"`
	Target     string              `json:"target"`
	PolicyPath string              `json:"policyPath"`
	PolicyHash string              `json:"policyHash"`
	Plan       *integrityscan.Plan `json:"plan"`
}
type scanStart struct {
	Stage string `json:"stage"`
}
type scanClosure struct {
	Index       int `json:"index"`
	Differences int `json:"differences"`
	Gaps        int `json:"gaps"`
}
type scanDone struct {
	Records int                   `json:"records"`
	Summary integrityscan.Summary `json:"summary"`
}
type residentSample struct {
	ElapsedMS int64  `json:"elapsedMS"`
	Bytes     uint64 `json:"bytes"`
	Valid     bool   `json:"valid"`
}

// RunScan owns two fixed sequential phases: acquire explicit policy without
// touching the target, then run the parent-qualified concrete acquisition plan.
// The same state/budget subsequently owns the existing terminable writer role.
// The caller must Finish after its last output attempt, including error paths.
func RunScan(ctx context.Context, request cli.ScanArgumentRequest) (ScanRun, error) {
	s := newRunState(ctx)
	run := ScanRun{output: BatchRun{state: s}}
	if ctx.Err() != nil {
		run.Interrupted = explicitCancel(ctx)
		return run, errors.New("scan: interrupted")
	}
	s.scan = newScanLifecycle(ctx, s.deadline)
	if request.PolicyPath == "" || request.Privacy != "portable" || request.Output != "-" || request.StateDir != "" {
		return run, integrityscan.ErrOptions
	}
	target, e := filepath.Abs(request.Path)
	if e != nil {
		return run, integrityscan.ErrOptions
	}
	policyPath, e := filepath.Abs(request.PolicyPath)
	if e != nil {
		return run, integrityscan.ErrOptions
	}
	observation, e := run.scanPhase(ctx, scanConfig{Stage: "policy", Target: target, PolicyPath: policyPath})
	if e != nil {
		run.Interrupted = explicitCancel(ctx)
		return run, e
	}
	plan, e := integrityscan.Configure(request, observation.Policy)
	if e != nil {
		return run, e
	}
	run.Plan = plan
	run.Usable = true
	_, e = run.scanPhase(ctx, scanConfig{Stage: "acquire", Target: target, PolicyPath: policyPath, PolicyHash: observation.SourceHash, Plan: &plan})
	run.Interrupted = explicitCancel(ctx)
	return run, e
}
func (run *ScanRun) scanPhase(ctx context.Context, cfg scanConfig) (policy integrityscan.PolicyObservation, failure error) {
	cmd, e := childCommand(ScanWorkerArgument)
	if e != nil {
		return policy, errors.New("scan: worker-unavailable")
	}
	identity, e := buildIdentity()
	if e != nil {
		return policy, errScanProtocol
	}
	return run.superviseScanPhase(ctx, cfg, cmd, identity)
}

// Test boundary only; production always derives this command from os.Executable.
func (run *ScanRun) superviseScanPhase(ctx context.Context, cfg scanConfig, cmd *exec.Cmd, identity string) (policy integrityscan.PolicyObservation, failure error) {
	s := run.output.state
	// Standalone protocol tests also get actual process observation, but own
	// only this phase. RunScan owns its observer across rendering/output too.
	if s.scan == nil {
		s.scan = newScanLifecycle(ctx, s.deadline)
		defer func() {
			receipt, e := s.scan.finish()
			run.Resources = receipt.Resources
			if failure == nil {
				failure = e
			}
		}()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	witness, closeWitness, e := privatePipe()
	if e != nil {
		return policy, errScanProtocol
	}
	defer witness.Close()
	defer closeWitness.Close()
	cap, release, e := configureLaunch(cmd, "scan", witness)
	if e != nil {
		return policy, errScanProtocol
	}
	cfg.Nonce = cap
	// No original target input or arbitrary executable is inherited. The empty
	// private witness is checked by the child before its first native operation.
	closeWitness.Close()
	phase, cancel := context.WithCancel(ctx)
	defer cancel()
	monitor := newScanMonitor(cancel)
	type phaseData struct {
		policy  integrityscan.PolicyObservation
		records []integrityscan.Record
		summary integrityscan.Summary
	}
	parsed := make(chan phaseData, 1)
	failure = s.runChild(phase, cmd, release, func(_ context.Context, c *channel, input io.Closer) error {
		var data phaseData
		defer func() { parsed <- data }()
		acceptedPolicy := false
		var h hello
		if c.expect("hello", &h) != nil || h.Build != identity {
			return errScanProtocol
		}
		if c.send("hello", hello{identity}) != nil || c.send("config", cfg) != nil || input.Close() != nil {
			return errScanProtocol
		}
		stop := monitor.start()
		defer stop()
		started, completed := false, false
		fatal := ""
		expected := 0
		var pending *integrityscan.Record
		for {
			m, e := c.receive()
			if e == io.EOF {
				if !completed {
					return errScanProtocol
				}
				if fatal != "" {
					return errors.New(fatal)
				}
				return nil
			}
			if e != nil {
				return errScanProtocol
			}
			if completed {
				return errScanProtocol
			}
			switch m.Type {
			case "start":
				var v scanStart
				if started || decode(m.Data, &v) != nil || v.Stage != cfg.Stage {
					return errScanProtocol
				}
				started = true
			case "resident":
				var v residentSample
				if !started || decode(m.Data, &v) != nil {
					return errScanProtocol
				}
				if e := monitor.sample(v); e != nil {
					return e
				}
			case "policy":
				if !started || cfg.Stage != "policy" || acceptedPolicy || fatal != "" || decode(m.Data, &data.policy) != nil || integrityscan.ValidatePolicy(data.policy.Policy) != nil || !scanSourceHash(data.policy.SourceHash) {
					return errScanProtocol
				}
				acceptedPolicy = true
			case "instance":
				var v integrityscan.Record
				if !started || cfg.Stage != "acquire" || cfg.Plan == nil || pending != nil || fatal != "" || decode(m.Data, &v) != nil || v.Index != expected || integrityscan.ValidateRecord(*cfg.Plan, v, cfg.PolicyHash) != nil {
					return errScanProtocol
				}
				pending = &v
			case "closure":
				var v scanClosure
				if pending == nil || decode(m.Data, &v) != nil || v.Index != pending.Index || v.Differences != len(pending.Assessment.Differences) || v.Gaps != len(pending.Assessment.Gaps) {
					return errScanProtocol
				}
				data.records = append(data.records, *pending)
				expected++
				pending = nil
			case "diagnostic":
				var v diagnostic
				if !started || fatal != "" || decode(m.Data, &v) != nil || !scanDiagnostic(v.Code) {
					return errScanProtocol
				}
				fatal = v.Code
			case "done":
				var v scanDone
				if !started || pending != nil || decode(m.Data, &v) != nil || v.Records != expected || v.Summary.Records != expected || v.Summary.ObservedEntries < 0 || v.Summary.ObservedEntries > 100000 || v.Summary.AuthorityComplete || v.Summary.Qualified {
					return errScanProtocol
				}
				if cfg.Stage == "policy" {
					if expected != 0 || (fatal == "" && !acceptedPolicy) {
						return errScanProtocol
					}
				} else if fatal == "" && cfg.Plan != nil {
					want := len(cfg.Plan.Policy.References)
					if cfg.Plan.Checks&cli.ArgumentCheckIntegrity == 0 {
						want = 0
					}
					if expected != want {
						return errScanProtocol
					}
					data.summary = v.Summary
				}
				completed = true
				// Self telemetry ends at comparison completion. Retained external
				// sampling continues independently until confirmed process reap.
				stop()
			default:
				return errScanProtocol
			}
		}
	})
	// Publish results only after the exchange has actually joined. On cleanup
	// uncertainty, no goroutine can race with public rendering of its slices.
	select {
	case data := <-parsed:
		policy = data.policy
		run.Records = append(run.Records, data.records...)
		run.Summary = data.summary
	default:
	}
	resources := monitor.result()
	s.scan.protocolResult(resources)
	run.Resources = s.scan.snapshot().Resources
	if s.broken {
		return policy, errors.New("scan: cleanup-unconfirmed")
	}
	if resources.QueryFailed || resources.Stale || resources.Stopped || s.scan.check() == errScanResource {
		return policy, errScanResource
	}
	if failure != nil {
		if s.broken {
			return policy, errors.New("scan: cleanup-unconfirmed")
		}
		if explicitCancel(ctx) {
			return policy, errors.New("scan: interrupted")
		}
		if ctx.Err() != nil {
			return policy, errors.New("scan: deadline")
		}
		if scanDiagnostic(failure.Error()) {
			return policy, failure
		}
		return policy, errors.New("scan: worker-incomplete")
	}
	return policy, nil
}
func scanDiagnostic(s string) bool {
	switch s {
	case "scan: invalid-policy", "scan: acquisition-unavailable", "scan: native-bootstrap-unavailable", "scan: resident-observation-failed", "scan: input-unusable":
		return true
	}
	return false
}
func scanSourceHash(s string) bool {
	if len(s) != 51 || s[:7] != "sha256-" {
		return false
	}
	value := s[7:]
	data, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(data) == 32 && base64.StdEncoding.EncodeToString(data) == value
}

// Serializes the periodic own-RSS observations with concrete semantic records.
// No arbitrary Reader/Writer is bridged: these are only private control pipes.
type scanSender struct {
	mu     sync.Mutex
	c      *channel
	start  time.Time
	failed error
	cancel context.CancelFunc
}

func (s *scanSender) send(kind string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return s.failed
	}
	s.failed = s.c.send(kind, value)
	if s.failed != nil && s.cancel != nil {
		s.cancel()
	}
	return s.failed
}
func (s *scanSender) resident() error {
	n, e := nativefs.OwnResidentBytes()
	return s.send("resident", residentSample{ElapsedMS: time.Since(s.start).Milliseconds(), Bytes: n, Valid: e == nil && n > 0})
}
func (s *scanSender) sampleLoop() func() {
	stop := make(chan struct{})
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if s.resident() != nil {
					return
				}
			}
		}
	}()
	return func() { close(stop); <-joined }
}

func ScanWorkerMain(in io.Reader, out io.Writer, diagnosticOut io.Writer) int {
	cap, ids, e := launchCapability("scan")
	if e != nil {
		return 2
	}
	in, release, e := platformControlInput(in)
	if e != nil {
		return 2
	}
	defer release()
	identity, e := buildIdentity()
	if e != nil {
		return 2
	}
	c := newChannel(in, out, &traffic{})
	if c.send("hello", hello{identity}) != nil {
		return 2
	}
	var h hello
	if c.expect("hello", &h) != nil || h.Build != identity {
		return 2
	}
	var cfg scanConfig
	if c.expect("config", &cfg) != nil || cfg.Nonce != cap || !one(cfg.Stage, "policy", "acquire") || !filepath.IsAbs(cfg.Target) || !filepath.IsAbs(cfg.PolicyPath) {
		return 2
	}
	if cfg.Stage == "policy" && (cfg.Plan != nil || cfg.PolicyHash != "") {
		return 2
	}
	if cfg.Stage == "acquire" && (cfg.Plan == nil || integrityscan.ValidatePolicy(cfg.Plan.Policy) != nil || !scanSourceHash(cfg.PolicyHash)) {
		return 2
	}
	if _, e = c.receive(); e != io.EOF {
		return 2
	}
	witness := os.NewFile(ids[0], "scan-private-witness")
	if witness == nil {
		return 2
	}
	var sentinel [1]byte
	n, e := witness.Read(sentinel[:])
	closeErr := witness.Close()
	if n != 0 || e != io.EOF || closeErr != nil {
		return 2
	}
	debug.SetMemoryLimit(512 << 20)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sender := &scanSender{c: c, start: time.Now(), cancel: cancel}
	if sender.send("start", scanStart{cfg.Stage}) != nil {
		return 2
	}
	finishError := func(code string) int {
		if sender.send("diagnostic", diagnostic{code}) != nil || sender.send("done", scanDone{}) != nil {
			return 2
		}
		return 0
	}
	if nativefs.PrepareProcess() != nil {
		return finishError("scan: native-bootstrap-unavailable")
	}
	if n, e := nativefs.OwnResidentBytes(); e != nil || n == 0 {
		return finishError("scan: resident-observation-failed")
	}
	if sender.resident() != nil {
		return 2
	}
	stop := sender.sampleLoop()
	var summary integrityscan.Summary
	if cfg.Stage == "policy" {
		var observed integrityscan.PolicyObservation
		observed, e = integrityscan.AcquirePolicy(ctx, cfg.PolicyPath, cfg.Target)
		if e == nil {
			e = sender.send("policy", observed)
		}
	} else {
		summary, e = integrityscan.Acquire(ctx, cfg.Target, filepath.Dir(cfg.PolicyPath), cfg.PolicyHash, *cfg.Plan, func(r integrityscan.Record) error {
			// Exact shape uses non-null finite collections; no portable report or
			// child-selected public exit/coverage is sent through this role.
			if r.Assessment.Differences == nil {
				r.Assessment.Differences = []integrity.Difference{}
			}
			if r.Assessment.Gaps == nil {
				r.Assessment.Gaps = []integrity.Gap{}
			}
			if r.Assessment.Contexts == nil {
				r.Assessment.Contexts = []integrity.ScopedContext{}
			}
			if sender.send("instance", r) != nil {
				return errScanProtocol
			}
			return sender.send("closure", scanClosure{r.Index, len(r.Assessment.Differences), len(r.Assessment.Gaps)})
		})
	}
	stop()
	if sender.resident() != nil {
		return 2
	}
	if e != nil {
		code := "scan: acquisition-unavailable"
		if e == integrityscan.ErrPolicy {
			code = e.Error()
		}
		if sender.send("diagnostic", diagnostic{code}) != nil {
			return 2
		}
	}
	if sender.send("done", scanDone{summary.Records, summary}) != nil {
		return 2
	}
	return 0
}

// Protocol self-samples validate the comparison phase only, ending at done.
// scanLifecycle independently observes retained processes through runtime exit
// and confirmed reap, including the writer. Neither mechanism is a hard cap.
type scanMonitor struct {
	mu        sync.Mutex
	resources integrityscan.Resources
	cancel    context.CancelFunc
	last      time.Time
	elapsed   int64
	worker    uint64
}

func newScanMonitor(cancel context.CancelFunc) *scanMonitor {
	return &scanMonitor{cancel: cancel, last: time.Now(), elapsed: -1}
}
func (m *scanMonitor) own() {
	n, e := nativefs.OwnResidentBytes()
	m.mu.Lock()
	defer m.mu.Unlock()
	if e != nil || n == 0 {
		m.resources.QueryFailed = true
		m.cancel()
		return
	}
	m.resources.SupervisorSamples++
	if n > m.resources.SupervisorPeakBytes {
		m.resources.SupervisorPeakBytes = n
	}
	if m.worker > 0 {
		sum := n + m.worker
		if sum > m.resources.PeakSampledSumBytes {
			m.resources.PeakSampledSumBytes = sum
		}
		if sum > 1<<30 {
			m.resources.Stopped = true
			m.cancel()
		}
	}
	if time.Since(m.last) > 350*time.Millisecond {
		m.resources.Stale = true
		m.cancel()
	}
}
func (m *scanMonitor) start() func() {
	m.mu.Lock()
	m.last = time.Now()
	m.mu.Unlock()
	m.own()
	stop := make(chan struct{})
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				m.own()
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stop); <-joined }) }
}
func (m *scanMonitor) sample(s residentSample) error {
	// Pair even short-lived workers with an actual parent query, rather
	// than waiting for the first periodic parent tick.
	own, queryErr := nativefs.OwnResidentBytes()
	m.mu.Lock()
	defer m.mu.Unlock()
	if queryErr != nil || own == 0 || !s.Valid || s.Bytes == 0 {
		m.resources.QueryFailed = true
		return errScanResource
	}
	if s.ElapsedMS < 0 || s.ElapsedMS > int64((5*time.Minute)/time.Millisecond) || s.ElapsedMS < m.elapsed {
		return errScanProtocol
	}
	if time.Since(m.last) > 350*time.Millisecond {
		m.resources.Stale = true
		return errScanResource
	}
	m.last = time.Now()
	m.elapsed = s.ElapsedMS
	m.worker = s.Bytes
	m.resources.WorkerSamples++
	if s.Bytes > m.resources.WorkerPeakBytes {
		m.resources.WorkerPeakBytes = s.Bytes
	}
	m.resources.SupervisorSamples++
	m.resources.SupervisorPeakBytes = max(m.resources.SupervisorPeakBytes, own)
	if s.Bytes > ^uint64(0)-own {
		m.resources.Stopped = true
		return errScanResource
	}
	sum := own + s.Bytes
	m.resources.PeakSampledSumBytes = max(m.resources.PeakSampledSumBytes, sum)
	if sum > 1<<30 {
		m.resources.Stopped = true
		return errScanResource
	}
	return nil
}
func (m *scanMonitor) result() integrityscan.Resources {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.resources
	if r.WorkerSamples == 0 {
		r.Stale = true
	}
	return r
}
