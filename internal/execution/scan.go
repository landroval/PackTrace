package execution

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/integrity"
	"packtrace/internal/integrityscan"
	"packtrace/internal/intelstore"
	"packtrace/internal/nativefs"
	"packtrace/internal/projectinventory"
)

const ScanWorkerArgument = "--internal-integrity-scan-worker-v1"

var errScanProtocol = errors.New("scan: worker-protocol")
var errScanResource = errors.New("scan: resident-observation-failed")

type ScanRun struct {
	Plan                  integrityscan.Plan
	Records               []integrityscan.Record
	Summary               integrityscan.Summary
	Inventory             *projectinventory.PublicInventory
	Intelligence          *integrityscan.Intelligence
	Advisories            *integrityscan.AdvisoryReport
	PolicyMaterials       []integrityscan.PolicyMaterial // Private evidence, never a report projection.
	PolicyMaterialLimited bool
	Resources             integrityscan.Resources // comparison checkpoint, updated by Checkpoint/Finish
	Operational           ScanReceipt             // populated only by Finish, never predicted in public bytes
	Usable, Interrupted   bool
	output                BatchRun
	fileOutput            *scanFileOutputState
	bunCache              *scanBunCacheOwner
	userSetup             *scanSetupOwner
}

func (r *ScanRun) WriteOutput(ctx context.Context, out io.Writer, data []byte) error {
	if r.output.state != nil && r.output.state.scan != nil {
		if e := r.Checkpoint(); e != nil {
			return e
		}
	}
	e := r.output.WriteOutput(ctx, out, data)
	r.NoteFailure("output", e)
	if r.output.state != nil && r.output.state.scan != nil {
		if observed := r.Checkpoint(); observed != nil {
			return observed
		}
	}
	return e
}

type scanConfig struct {
	Nonce               string                  `json:"nonce"`
	Stage               string                  `json:"stage"`
	Target              string                  `json:"target"`
	PolicyPath          string                  `json:"policyPath"`
	PolicyHash          string                  `json:"policyHash"`
	TrustedPolicyDigest string                  `json:"trustedPolicyDigest,omitempty"`
	Plan                *integrityscan.Plan     `json:"plan"`
	Intelligence        *scanIntelligenceConfig `json:"intelligence,omitempty"`
	FileOutput          *scanFileOutputConfig   `json:"fileOutput,omitempty"`
	BunCacheBinding     string                  `json:"bunCacheBinding,omitempty"`
}
type scanStart struct {
	Stage string `json:"stage"`
}
type scanClosure struct {
	Index       int `json:"index"`
	Differences int `json:"differences"`
	Gaps        int `json:"gaps"`
}
type scanInventoryClosure struct {
	Batches   uint32                           `json:"batches"`
	Selection projectinventory.PublicSelection `json:"selection"`
	Counts    projectinventory.Counters        `json:"counts"`
	Complete  bool                             `json:"complete"`
}

type scanLocalObservations struct {
	Sequence     uint32                           `json:"sequence"`
	Observations []integrityscan.LocalObservation `json:"observations"`
}
type scanLocalClosure struct {
	Batches      uint32 `json:"batches"`
	Observations int    `json:"observations"`
	Limited      bool   `json:"limited"`
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
	if request.Privacy != "portable" && request.Privacy != "local" || request.Output == "" {
		return run, integrityscan.ErrOptions
	}
	target, e := filepath.Abs(request.Path)
	if e != nil {
		return run, integrityscan.ErrOptions
	}
	run.userSetup, request, e = loadScanSetup(ctx, target, request)
	if e != nil {
		return run, e
	}
	if run.userSetup != nil && request.Output != "-" {
		// The saved config is an additional original source. Do not publish a
		// file until that root is included in the writer's exclusion proof.
		return run, errors.New("scan: saved-setup requires stdout; use --format json without --output")
	}
	var policyPath string
	var observation integrityscan.PolicyObservation
	if request.PolicyPath != "" {
		policyPath, e = filepath.Abs(request.PolicyPath)
		if e != nil {
			return run, integrityscan.ErrOptions
		}
		observation, e = run.scanPhase(ctx, scanConfig{Stage: "policy", Target: target, PolicyPath: policyPath, TrustedPolicyDigest: request.TrustedPolicyDigest})
		if e != nil {
			run.Interrupted = explicitCancel(ctx)
			return run, e
		}
	}
	wantsIntelligence := request.StateDir != "" || request.TrustedSnapshotDigest != "" || request.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) != 0
	if wantsIntelligence {
		if request.StateDir == "" {
			request.StateDir, e = defaultIntelStateDirectory()
			if e != nil {
				return run, integrityscan.ErrOptions
			}
		}
		request.StateDir, e = filepath.Abs(request.StateDir)
		if e != nil {
			return run, integrityscan.ErrOptions
		}
	}
	var plan integrityscan.Plan
	if request.PolicyPath == "" {
		plan, e = integrityscan.ConfigureBuiltin(request)
		observation.Policy = plan.Policy
		observation.SourceHash = builtinPolicyHash(plan)
	} else {
		plan, e = integrityscan.Configure(request, observation.Policy)
	}
	if e != nil {
		return run, e
	}
	run.Plan = plan
	run.Usable = true
	var intelligence *scanIntelligenceConfig
	if wantsIntelligence {
		info := integrityscan.UnavailableIntelligence()
		run.Intelligence = &info
		owner, openErr := openScanIntelligence(ctx, target, request.StateDir, request.TrustedSnapshotDigest, nil)
		s.intelligence = owner
		if openErr != nil {
			run.Usable = false
			return run, errors.New("scan: intelligence-binding-unavailable")
		}
		intelligence = &owner.cfg
	}
	cacheBinding := ""
	if plan.Policy.BunCacheDirectory != "" {
		// The initial additional-source profile supports stdout only; never
		// publish a file without excluding this actual additional original root.
		if request.Output != "-" {
			return run, integrityscan.ErrOptions
		}
		var borrowed *nativefs.Root
		if s.intelligence != nil {
			borrowed = s.intelligence.target
		}
		run.bunCache, e = openScanBunCache(ctx, borrowed, target, plan.Policy.BunCacheDirectory, "")
		if e != nil {
			return run, integrityscan.ErrAcquisition
		}
		cacheBinding = run.bunCache.binding
	}
	if request.Output != "-" {
		destination, err := filepath.Abs(request.Output)
		if err != nil {
			return run, integrityscan.ErrOptions
		}
		policyDirectory := ""
		if policyPath != "" {
			policyDirectory = filepath.Dir(policyPath)
		}
		if err := run.prepareFileOutput(ctx, target, policyDirectory, destination); err != nil {
			return run, errors.New("scan: output-destination-unavailable")
		}
	}
	_, e = run.scanPhase(ctx, scanConfig{Stage: "acquire", Target: target, PolicyPath: policyPath, PolicyHash: observation.SourceHash, TrustedPolicyDigest: request.TrustedPolicyDigest, Plan: &plan, Intelligence: intelligence, FileOutput: run.fileOutputConfig(), BunCacheBinding: cacheBinding})
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
	defer func() {
		if cfg.Stage == "acquire" && failure != nil && run.Inventory != nil {
			p := run.Inventory
			p.Complete = false
			g := projectinventory.Gap{Code: "execution-incomplete"}
			if len(p.Gaps) < 257 {
				p.Gaps = append(p.Gaps, g)
			} else {
				p.Gaps[len(p.Gaps)-1] = g
			}
			p.Counts.Gaps = len(p.Gaps)
			run.Summary.InventoryComplete = false
		}
	}()
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
		policy       integrityscan.PolicyObservation
		records      []integrityscan.Record
		summary      integrityscan.Summary
		inventory    *projectinventory.PublicInventory
		intelligence *integrityscan.Intelligence
		advisories   *integrityscan.AdvisoryReport
		materials    *scanPolicyMaterialBuffer
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
		var inventory projectinventory.PublicInventory
		inventorySequence := uint32(0)
		inventoryClosed := false
		intelligenceClosed := cfg.Intelligence == nil
		advisoryClosed := cfg.Stage != "acquire" || cfg.Plan == nil || cfg.Plan.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) == 0
		advisoryDecisions := []integrityscan.AdvisoryDecision{}
		advisorySeen := map[[3]int]bool{}
		materialWanted := policyMaterialWanted(cfg.Plan)
		material := scanPolicyMaterialBuffer{}
		materialSeen := map[[5]int]bool{}
		localWanted := !advisoryClosed && integrityscan.PlanPrivacy(*cfg.Plan) == "local"
		localClosed := !localWanted
		localBatches := uint32(0)
		localDetails := integrityscan.LocalDetails{Observations: []integrityscan.LocalObservation{}, Advisories: []integrityscan.LocalAdvisory{}}
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
				if !started || cfg.Stage != "policy" || acceptedPolicy || fatal != "" || decode(m.Data, &data.policy) != nil || integrityscan.ValidatePolicy(data.policy.Policy) != nil || !scanSourceHash(data.policy.SourceHash) || data.policy.MatchedOperatorDigest != cfg.TrustedPolicyDigest {
					return errScanProtocol
				}
				acceptedPolicy = true
			case "intel-state":
				var v integrityscan.Intelligence
				if !started || cfg.Stage != "acquire" || cfg.Intelligence == nil || data.intelligence != nil || intelligenceClosed || inventorySequence != 0 || expected != 0 || fatal != "" || decode(m.Data, &v) != nil || integrityscan.ValidateIntelligence(v) != nil {
					return errScanProtocol
				}
				if v.State == "available" && (v.ID != cfg.Intelligence.Generation || v.Selection != cfg.Intelligence.Selection) {
					return errScanProtocol
				}
				data.intelligence = &v
			case "intel-closure":
				var v scanIntelligenceClosure
				if cfg.Intelligence == nil || data.intelligence == nil || intelligenceClosed || decode(m.Data, &v) != nil || v.States != 1 {
					return errScanProtocol
				}
				intelligenceClosed = true
			case "inventory-batch":
				var v projectinventory.InventoryBatch
				if !started || cfg.Stage != "acquire" || cfg.Plan == nil || !intelligenceClosed || inventoryClosed || pending != nil || expected != 0 || fatal != "" || decode(m.Data, &v) != nil || v.Sequence != inventorySequence || projectinventory.AppendBatch(&inventory, v) != nil {
					return errScanProtocol
				}
				inventorySequence++
			case "inventory-closure":
				var v scanInventoryClosure
				if !started || cfg.Stage != "acquire" || !intelligenceClosed || inventoryClosed || pending != nil || expected != 0 || fatal != "" || decode(m.Data, &v) != nil || v.Batches != inventorySequence {
					return errScanProtocol
				}
				inventory.Selection = v.Selection
				inventory.Counts = v.Counts
				inventory.Complete = v.Complete
				if projectinventory.ValidatePublic(inventory) != nil {
					return errScanProtocol
				}
				inventoryClosed = true
				data.inventory = &inventory
			case "local-observations":
				var v scanLocalObservations
				if !started || !inventoryClosed || !localWanted || localClosed || advisoryClosed || expected != 0 || pending != nil || fatal != "" || decode(m.Data, &v) != nil || v.Sequence != localBatches || len(v.Observations) == 0 || len(v.Observations) > 128 || len(localDetails.Observations)+len(v.Observations) > 4096 {
					return errScanProtocol
				}
				for _, observation := range v.Observations {
					if integrityscan.ValidateLocalObservation(observation, inventory) != nil || len(localDetails.Observations) > 0 && observation.Observation <= localDetails.Observations[len(localDetails.Observations)-1].Observation {
						return errScanProtocol
					}
					localDetails.Observations = append(localDetails.Observations, observation)
				}
				localBatches++
			case "local-closure":
				var v scanLocalClosure
				if !started || !inventoryClosed || !localWanted || localClosed || advisoryClosed || expected != 0 || pending != nil || fatal != "" || decode(m.Data, &v) != nil || v.Batches != localBatches || v.Observations != len(localDetails.Observations) {
					return errScanProtocol
				}
				total := 0
				for _, observation := range inventory.Observations {
					if (observation.Class == "locked" || observation.Class == "installed") && observation.Kind != "project" {
						total++
					}
				}
				if v.Observations != min(total, 4096) || v.Limited != (total > 4096) {
					return errScanProtocol
				}
				localDetails.Limited = v.Limited
				localClosed = true
			case "matching-advisory":
				var v integrityscan.LocalAdvisory
				if !started || !inventoryClosed || !localWanted || !localClosed || advisoryClosed || data.intelligence == nil || data.intelligence.State != "available" || fatal != "" || expected != 0 || pending != nil || decode(m.Data, &v) != nil || v.Advisory != len(localDetails.Advisories)+1 || integrityscan.ValidateLocalAdvisory(v) != nil {
					return errScanProtocol
				}
				localDetails.Advisories = append(localDetails.Advisories, v)
			case "matching-decision":
				var v integrityscan.AdvisoryDecision
				if !started || cfg.Stage != "acquire" || cfg.Plan == nil || data.intelligence == nil || !intelligenceClosed || !inventoryClosed || !localClosed || advisoryClosed || pending != nil || expected != 0 || fatal != "" || decode(m.Data, &v) != nil || len(advisoryDecisions) >= 4096 || v.Sequence != len(advisoryDecisions) || integrityscan.ValidateAdvisoryDecision(*cfg.Plan, inventory, *data.intelligence, v) != nil {
					return errScanProtocol
				}
				if localWanted && v.Advisory > len(localDetails.Advisories) {
					return errScanProtocol
				}
				key := [3]int{int(v.Observation), v.Advisory, v.Affected}
				if advisorySeen[key] {
					return errScanProtocol
				}
				advisorySeen[key] = true
				advisoryDecisions = append(advisoryDecisions, v)
			case "matching-closure":
				var v integrityscan.AdvisorySummary
				if !started || cfg.Stage != "acquire" || cfg.Plan == nil || data.intelligence == nil || !intelligenceClosed || !inventoryClosed || !localClosed || advisoryClosed || pending != nil || expected != 0 || fatal != "" || decode(m.Data, &v) != nil || integrityscan.ValidateAdvisorySummary(v, advisoryDecisions, inventory) != nil {
					return errScanProtocol
				}
				a := &integrityscan.AdvisoryReport{State: "observed", Decisions: advisoryDecisions, Summary: v}
				if localWanted {
					if integrityscan.ValidateLocalDetails(localDetails, advisoryDecisions, inventory) != nil {
						return errScanProtocol
					}
					a.Local = &localDetails
				}
				for _, d := range advisoryDecisions {
					if d.EnforcementEligible {
						a.Findings++
					}
					if d.Candidate {
						a.Candidates++
					}
				}
				data.advisories = a
				advisoryClosed = true
			case "policy-material":
				var v integrityscan.PolicyMaterial
				if !started || cfg.Stage != "acquire" || !materialWanted || !inventoryClosed || pending != nil || fatal != "" || decode(m.Data, &v) != nil || material.accept(v) != nil {
					return errScanProtocol
				}
				key := [5]int{0, int(v.Observation), v.Advisory, v.Affected, 0}
				if v.Scope.Category == "integrity" {
					key = [5]int{1, v.Record, v.Difference, 0, 0}
				}
				if materialSeen[key] {
					return errScanProtocol
				}
				materialSeen[key] = true
			case "policy-material-closure":
				var v scanPolicyMaterialClosure
				if !started || cfg.Stage != "acquire" || !materialWanted || !inventoryClosed || !advisoryClosed || pending != nil || fatal != "" || decode(m.Data, &v) != nil || material.finish(v) != nil {
					return errScanProtocol
				}
				if material.limited {
					// Budget exhaustion cannot certify partially transported witness
					// associations. Retain findings, but accept none of this phase.
					material.rows = nil
				}
				data.materials = &material
			case "instance":
				var v integrityscan.Record
				if !started || cfg.Stage != "acquire" || !intelligenceClosed || !inventoryClosed || !advisoryClosed || cfg.Plan == nil || pending != nil || material.closed || fatal != "" || decode(m.Data, &v) != nil || v.Index != expected || integrityscan.ValidateRecord(*cfg.Plan, v, cfg.PolicyHash) != nil {
					return errScanProtocol
				}
				if materialWanted {
					material.limited = material.limited || v.PolicyMaterialLimited
					if material.addWitnesses(v.PolicyWitnesses) != nil {
						return errScanProtocol
					}
				} else if v.PolicyObservation != 0 || len(v.PolicyWitnesses) != 0 || v.PolicyMaterialLimited {
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
				if !started || !intelligenceClosed || pending != nil || decode(m.Data, &v) != nil || v.Records != expected || v.Summary.Records != expected || v.Summary.ObservedEntries < 0 || v.Summary.ObservedEntries > 100000 || v.Summary.Qualified {
					return errScanProtocol
				}
				if cfg.Stage == "policy" {
					if expected != 0 || v.Summary.AuthorityComplete || (fatal == "" && !acceptedPolicy) {
						return errScanProtocol
					}
				} else if fatal == "" && cfg.Plan != nil {
					if !inventoryClosed || !advisoryClosed || materialWanted && !material.closed || v.Summary.InventoryComplete != inventory.Complete {
						return errScanProtocol
					}
					want := len(cfg.Plan.Policy.References)
					if cfg.Plan.Checks&cli.ArgumentCheckIntegrity == 0 {
						want = 0
					}
					if expected != want {
						return errScanProtocol
					}
					if v.Summary.AuthorityComplete != integrityscan.OperatorReferenceAuthorityComplete(*cfg.Plan, data.records) {
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
		if data.inventory != nil {
			run.Inventory = data.inventory
		}
		if data.intelligence != nil {
			run.Intelligence = data.intelligence
		}
		if data.advisories != nil {
			run.Advisories = data.advisories
		}
		if data.materials != nil && failure == nil {
			var decisions []integrityscan.AdvisoryDecision
			if data.advisories != nil {
				decisions = data.advisories.Decisions
			}
			// No material becomes usable until closure, EOF, exchange join and
			// semantic admission. Keep expensive shared-graph work out of the
			// receive loop so periodic worker samples can be consumed on time.
			if data.inventory == nil || len(data.materials.rows) != 0 && integrityscan.ValidatePolicyMaterials(*cfg.Plan, *data.inventory, data.records, decisions, data.materials.rows) != nil {
				failure = errScanProtocol
				run.PolicyMaterialLimited = true
			} else {
				run.PolicyMaterials = data.materials.rows
				run.PolicyMaterialLimited = data.materials.limited
			}
		} else if cfg.Stage == "acquire" && policyMaterialWanted(cfg.Plan) {
			run.PolicyMaterialLimited = true
		}
	default:
	}
	resources := monitor.result()
	s.scan.protocolResult(resources)
	run.Resources = s.scan.snapshot().Resources
	if s.broken.Load() {
		return policy, errors.New("scan: cleanup-unconfirmed")
	}
	if resources.QueryFailed || resources.Stale || resources.Stopped || s.scan.check() == errScanResource {
		return policy, errScanResource
	}
	if failure != nil {
		if s.broken.Load() {
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
	if c.expect("config", &cfg) != nil || cfg.Nonce != cap || !one(cfg.Stage, "policy", "acquire") || !filepath.IsAbs(cfg.Target) {
		return 2
	}
	if cfg.Stage == "policy" && (cfg.Plan != nil || cfg.PolicyHash != "" || cfg.Intelligence != nil || cfg.FileOutput != nil || cfg.BunCacheBinding != "" || !filepath.IsAbs(cfg.PolicyPath)) {
		return 2
	}
	if cfg.Stage == "acquire" && (cfg.Plan == nil || integrityscan.ValidatePlanPolicy(*cfg.Plan) != nil || !scanSourceHash(cfg.PolicyHash) || cfg.TrustedPolicyDigest != cfg.Plan.TrustedPolicyDigest) {
		return 2
	}
	if cfg.Stage == "acquire" {
		if (cfg.BunCacheBinding != "") != (cfg.Plan.Policy.BunCacheDirectory != "") || cfg.BunCacheBinding != "" && (!intelResultID(cfg.BunCacheBinding) || cfg.FileOutput != nil) {
			return 2
		}
		if cfg.FileOutput != nil {
			v := cfg.FileOutput
			if !v.valid() || v.Target != cfg.Target || v.PolicyDirectory != "" && v.PolicyDirectory != filepath.Dir(cfg.PolicyPath) || cfg.Plan.Builtin != (v.PolicyDirectory == "") || !reflect.DeepEqual(v.Intelligence, cfg.Intelligence) {
				return 2
			}
		}
		if cfg.Plan.Builtin {
			if cfg.PolicyPath != "" || cfg.TrustedPolicyDigest != "" || cfg.PolicyHash != builtinPolicyHash(*cfg.Plan) {
				return 2
			}
		} else if !filepath.IsAbs(cfg.PolicyPath) {
			return 2
		}
		privacy := integrityscan.PlanPrivacy(*cfg.Plan)
		if !one(privacy, "portable", "local") || cfg.Plan.Policy.RequirePortable && privacy == "local" {
			return 2
		}
		if (cfg.Plan.StateDir != "") != (cfg.Intelligence != nil) {
			return 2
		}
		if v := cfg.Intelligence; v != nil {
			if v.Path != cfg.Plan.StateDir || v.TrustedDigest != cfg.Plan.TrustedSnapshotDigest || !filepath.IsAbs(v.Path) || !intelResultID(v.TargetBinding) || v.NowUnixNS <= 0 {
				return 2
			}
			if v.Generation == "" {
				if v.Binding != "" || v.Selection != "none" {
					return 2
				}
			} else if !intelResultID(v.Generation) || !intelResultID(v.Binding) || !one(v.Selection, "current", "previous-fallback", "expected-digest") {
				return 2
			}
		}
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
		observed, e = integrityscan.AcquirePolicyPinned(ctx, cfg.PolicyPath, cfg.Target, cfg.TrustedPolicyDigest)
		if e == nil {
			e = sender.send("policy", observed)
		}
	} else {
		var intelligenceOwner *scanIntelligenceOwner
		intelligenceInfo := integrityscan.UnavailableIntelligence()
		e = nil // The launch witness's successful empty read left io.EOF.
		if cfg.Intelligence != nil {
			intelligenceOwner, intelligenceInfo, e = workerScanIntelligence(ctx, cfg.Target, *cfg.Intelligence)
			if sender.send("intel-state", intelligenceInfo) != nil || sender.send("intel-closure", scanIntelligenceClosure{1}) != nil {
				e = errScanProtocol
			}
		}
		material := scanPolicyMaterialBuffer{}
		var emitEvidence integrityscan.PolicyEvidenceEmitter
		if policyMaterialWanted(cfg.Plan) {
			emitEvidence = func(v integrityscan.PolicyMaterial) error { return material.emit(sender.send, v) }
		}
		emitRecord := func(r integrityscan.Record) error {
			material.limited = material.limited || r.PolicyMaterialLimited
			if emitEvidence != nil && material.addWitnesses(r.PolicyWitnesses) != nil {
				material.limited = true
				r.PolicyWitnesses = nil
			}
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
		}
		emitInventory := func(r projectinventory.Result) error {
			p := projectinventory.Portable(r)
			if policyMaterialWanted(cfg.Plan) || cfg.Plan.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) != 0 {
				p = projectinventory.PortableMatching(r)
			}
			batches := uint32(0)
			if e := projectinventory.WalkBatches(p, func(b projectinventory.InventoryBatch) error {
				if e := sender.send("inventory-batch", b); e != nil {
					return e
				}
				batches++
				return nil
			}); e != nil {
				return e
			}
			if e := sender.send("inventory-closure", scanInventoryClosure{Batches: batches, Selection: p.Selection, Counts: p.Counts, Complete: p.Complete}); e != nil {
				return e
			}
			if cfg.Plan.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) == 0 {
				return nil
			}
			var snapshot *intelstore.Snapshot
			if intelligenceOwner != nil {
				snapshot = intelligenceOwner.snapshot
			}
			now := time.Now()
			if cfg.Intelligence != nil {
				now = time.Unix(0, cfg.Intelligence.NowUnixNS)
			}
			var emitLocal func(integrityscan.LocalAdvisory) error
			if integrityscan.PlanPrivacy(*cfg.Plan) == "local" {
				local := integrityscan.CollectLocalObservations(r)
				batches := uint32(0)
				for from := 0; from < len(local.Observations); from += 128 {
					end := min(from+128, len(local.Observations))
					if e := sender.send("local-observations", scanLocalObservations{Sequence: batches, Observations: local.Observations[from:end]}); e != nil {
						return e
					}
					batches++
				}
				if e := sender.send("local-closure", scanLocalClosure{Batches: batches, Observations: len(local.Observations), Limited: local.Limited}); e != nil {
					return e
				}
				emitLocal = func(d integrityscan.LocalAdvisory) error { return sender.send("matching-advisory", d) }
			}
			matched, e := integrityscan.MatchInventoryWithPolicyEvidence(ctx, *cfg.Plan, r, snapshot, intelligenceInfo, now, func(d integrityscan.AdvisoryDecision) error {
				return sender.send("matching-decision", d)
			}, emitLocal, emitEvidence)
			if e != nil {
				return e
			}
			return sender.send("matching-closure", matched)
		}
		if e == nil {
			prepared := ""
			if !cfg.Plan.Builtin {
				prepared = filepath.Dir(cfg.PolicyPath)
			}
			if cfg.FileOutput != nil {
				summary, e = acquireBoundFileScan(ctx, cfg, intelligenceOwner, emitRecord, emitInventory, emitEvidence)
			} else if cfg.BunCacheBinding != "" {
				var borrowed *nativefs.Root
				if intelligenceOwner != nil {
					borrowed = intelligenceOwner.target
				}
				cache, cacheErr := openScanBunCache(ctx, borrowed, cfg.Target, cfg.Plan.Policy.BunCacheDirectory, cfg.BunCacheBinding)
				e = cacheErr
				if e == nil {
					summary, e = integrityscan.AcquireFromRootWithBunCache(ctx, cache.target, cache.cache, prepared, cfg.PolicyHash, *cfg.Plan, emitRecord, emitInventory, emitEvidence)
					e = errors.Join(e, cache.check())
				}
				if cache != nil {
					e = errors.Join(e, cache.close())
				}
			} else if intelligenceOwner != nil {
				summary, e = integrityscan.AcquireFromRootWithPolicyEvidence(ctx, intelligenceOwner.target, prepared, cfg.PolicyHash, *cfg.Plan, emitRecord, emitInventory, emitEvidence)
			} else {
				summary, e = integrityscan.AcquireWithPolicyEvidence(ctx, cfg.Target, prepared, cfg.PolicyHash, *cfg.Plan, emitRecord, emitInventory, emitEvidence)
			}
		}
		if intelligenceOwner != nil {
			e = errors.Join(e, intelligenceOwner.check(ctx), intelligenceOwner.close())
		}
		if e == nil && emitEvidence != nil {
			e = material.close(sender.send)
		}
	}
	stop()
	if sender.resident() != nil {
		return 2
	}
	if e != nil {
		code := "scan: acquisition-unavailable"
		if errors.Is(e, integrityscan.ErrPolicy) {
			code = integrityscan.ErrPolicy.Error()
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
	mu         sync.Mutex
	resources  integrityscan.Resources
	cancel     context.CancelFunc
	last       time.Time
	elapsed    int64
	maxElapsed int64 // zero retains the legacy5min bound
	worker     uint64
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
	limit := m.maxElapsed
	if limit == 0 {
		limit = int64((5 * time.Minute) / time.Millisecond)
	}
	if s.ElapsedMS < 0 || s.ElapsedMS > limit || s.ElapsedMS < m.elapsed {
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
