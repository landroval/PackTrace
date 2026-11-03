package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"packtrace/internal/cli"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	"packtrace/internal/nativefs"
	"path/filepath"
	"runtime/debug"
	"time"
)

type IntelRun struct {
	Result              IntelResult
	Usable, Interrupted bool
	lifecycle           ScanRun
}

func (r *IntelRun) WriteOutput(ctx context.Context, out io.Writer, data []byte) error {
	return r.lifecycle.WriteOutput(ctx, out, data)
}
func (r *IntelRun) Finish() (ScanReceipt, error) { return r.lifecycle.Finish() }

type intelConfig struct {
	Nonce   string                   `json:"nonce"`
	Request cli.IntelArgumentRequest `json:"request"`
}

func newIntelMonitor(cancel context.CancelFunc) *scanMonitor {
	monitor := newScanMonitor(cancel)
	monitor.maxElapsed = int64((15 * time.Minute) / time.Millisecond)
	return monitor
}

type intelClosure struct {
	Results int `json:"results"`
}

func validateIntelRequest(r cli.IntelArgumentRequest) error {
	var args []string
	switch r.Action {
	case cli.ArgumentActionIntelSync:
		args = []string{"intel", "sync"}
	case cli.ArgumentActionIntelImport:
		args = []string{"intel", "import"}
	case cli.ArgumentActionIntelExport:
		args = []string{"intel", "export"}
	case cli.ArgumentActionIntelStatus:
		args = []string{"intel", "status"}
	case cli.ArgumentActionIntelPin:
		args = []string{"intel", "pin"}
	case cli.ArgumentActionIntelUnpin:
		args = []string{"intel", "unpin"}
	case cli.ArgumentActionCachePrune:
		args = []string{"cache", "prune"}
	default:
		return errIntelProtocol
	}
	if r.Full {
		args = append(args, "--full")
	}
	if r.StateDir != "" {
		args = append(args, "--state-dir", r.StateDir)
	}
	if r.Format != "terminal" || r.Provided&cli.ArgumentOptionFormat != 0 {
		args = append(args, "--format", r.Format)
	}
	if r.Output != "" {
		args = append(args, "--output", r.Output)
	}
	if r.TrustedSnapshotDigest != "" {
		args = append(args, "--trusted-snapshot-digest", r.TrustedSnapshotDigest)
	}
	if r.ApplyPreview != "" {
		args = append(args, "--apply", r.ApplyPreview)
	}
	if r.Input != "" {
		if r.Action != cli.ArgumentActionIntelImport {
			return errIntelProtocol
		}
		args = append(args, "--", r.Input)
	}
	if r.Generation != "" {
		if r.Action != cli.ArgumentActionIntelPin && r.Action != cli.ArgumentActionIntelUnpin {
			return errIntelProtocol
		}
		args = append(args, "--", r.Generation)
	}
	parsed, e := cli.ParseArgs(args)
	if e != nil {
		return errIntelProtocol
	}
	expected := parsed.Intel
	r.Provided = expected.Provided
	if r != expected {
		return errIntelProtocol
	}
	return nil
}
func normalizeIntelRequest(r cli.IntelArgumentRequest) (cli.IntelArgumentRequest, error) {
	if r.Format == "" {
		r.Format = "terminal"
	}
	if e := validateIntelRequest(r); e != nil {
		return r, e
	}
	if r.StateDir == "" {
		cache, e := os.UserCacheDir()
		if e != nil {
			return r, errIntelProtocol
		}
		r.StateDir = filepath.Join(cache, "PackTrace")
	}
	for _, value := range []*string{&r.StateDir, &r.Input, &r.Output} {
		if *value != "" {
			abs, e := filepath.Abs(*value)
			if e != nil {
				return r, errIntelProtocol
			}
			*value = abs
		}
	}
	return r, nil
}
func RunIntel(ctx context.Context, request cli.IntelArgumentRequest) (run IntelRun, failure error) {
	if ctx == nil {
		return run, errIntelProtocol
	}
	s := newIntelRunState(ctx)
	run.lifecycle.output.state = s
	request, e := normalizeIntelRequest(request)
	if e != nil {
		return run, e
	}
	s.scan = newScanLifecycle(ctx, s.deadline)
	cmd, e := childCommand(IntelWorkerArgument)
	if e != nil {
		return run, e
	}
	identity, e := buildIdentity()
	if e != nil {
		return run, e
	}
	e = run.superviseIntel(ctx, request, cmd, identity)
	run.Interrupted = explicitCancel(ctx)
	return run, e
}
func (run *IntelRun) superviseIntel(ctx context.Context, request cli.IntelArgumentRequest, cmd *exec.Cmd, identity string) error {
	s := run.lifecycle.output.state
	s.mu.Lock()
	defer s.mu.Unlock()
	witness, closeWitness, e := privatePipe()
	if e != nil {
		return e
	}
	defer witness.Close()
	defer closeWitness.Close()
	nonce, release, e := configureLaunch(cmd, "intel", witness)
	if e != nil {
		return e
	}
	closeWitness.Close()
	phase, cancel := context.WithCancel(ctx)
	defer cancel()
	monitor := newIntelMonitor(cancel)
	var result IntelResult
	received := false
	failure := s.runChild(phase, cmd, release, func(_ context.Context, c *channel, input io.Closer) error {
		var h hello
		if c.expect("hello", &h) != nil || h.Build != identity {
			return errIntelProtocol
		}
		if c.send("hello", hello{identity}) != nil || c.send("config", intelConfig{nonce, request}) != nil || input.Close() != nil {
			return errIntelProtocol
		}
		stop := monitor.start()
		defer stop()
		started, done := false, false
		for {
			message, e := c.receive()
			if e == io.EOF {
				if !done {
					return errIntelProtocol
				}
				return nil
			}
			if e != nil {
				return e
			}
			if done {
				return errIntelProtocol
			}
			switch message.Type {
			case "start":
				var v scanStart
				if started || decode(message.Data, &v) != nil || v.Stage != "intel" {
					return errIntelProtocol
				}
				started = true
			case "resident":
				var v residentSample
				if !started || decode(message.Data, &v) != nil {
					return errIntelProtocol
				}
				if e := monitor.sample(v); e != nil {
					return e
				}
			case "result":
				if !started || received || decode(message.Data, &result) != nil || validateIntelResult(result, request) != nil {
					return errIntelProtocol
				}
				received = true
			case "done":
				var v intelClosure
				if !started || !received || decode(message.Data, &v) != nil || v.Results != 1 {
					return errIntelProtocol
				}
				done = true
				// Child self telemetry ends at semantic closure; the retained
				// external observer still covers runtime teardown and actual reap.
				stop()
			default:
				return errIntelProtocol
			}
		}
	})
	s.scan.protocolResult(monitor.result())
	if s.broken {
		return errReap
	}
	if e := s.scan.check(); e != nil {
		return e
	}
	if received && failure == nil {
		run.Result = result
		run.Usable = true
	}
	return failure
}
func IntelWorkerMain(in io.Reader, out io.Writer, diagnosticOut io.Writer) int {
	cap, ids, e := launchCapability("intel")
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
	var cfg intelConfig
	if c.expect("config", &cfg) != nil || cfg.Nonce != cap || validateIntelRequest(cfg.Request) != nil || !filepath.IsAbs(cfg.Request.StateDir) || (cfg.Request.Input != "" && !filepath.IsAbs(cfg.Request.Input)) || (cfg.Request.Output != "" && !filepath.IsAbs(cfg.Request.Output)) {
		return 2
	}
	if _, e := c.receive(); e != io.EOF {
		return 2
	}
	witness := os.NewFile(ids[0], "intel-private-witness")
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	sender := &scanSender{c: c, start: time.Now(), cancel: cancel}
	if sender.send("start", scanStart{"intel"}) != nil {
		return 2
	}
	result := IntelResult{Action: cfg.Request.Action, Outcome: "unavailable"}
	if nativefs.PrepareProcess() == nil {
		if sender.resident() != nil {
			return 2
		}
		stop := sender.sampleLoop()
		result = performIntel(ctx, cfg.Request)
		stop()
		if sender.resident() != nil {
			return 2
		}
	}
	if validateIntelResult(result, cfg.Request) != nil {
		return 2
	}
	if sender.send("result", result) != nil || sender.send("done", intelClosure{1}) != nil {
		return 2
	}
	return 0
}
func intelOutcome(e error) string {
	switch {
	case e == nil:
		return "complete"
	case errors.Is(e, context.Canceled):
		return "interrupted"
	case errors.Is(e, intelstore.ErrBusy):
		return "busy"
	case errors.Is(e, intelstore.ErrLimit):
		return "limit"
	case errors.Is(e, intelstore.ErrCorrupt):
		return "corrupt"
	case errors.Is(e, intelstore.ErrUntrusted):
		return "untrusted"
	default:
		return "unavailable"
	}
}
func performIntel(ctx context.Context, request cli.IntelArgumentRequest) (result IntelResult) {
	result.Action = request.Action
	result.Outcome = "unavailable"
	var store *intelstore.Store
	var e error
	switch request.Action {
	case cli.ArgumentActionIntelSync, cli.ArgumentActionIntelImport:
		store, e = intelstore.Open(ctx, request.StateDir, intelstore.CreateOwned)
	case cli.ArgumentActionIntelPin, cli.ArgumentActionIntelUnpin, cli.ArgumentActionCachePrune:
		store, e = intelstore.OpenExistingOwned(ctx, request.StateDir)
	default:
		store, e = intelstore.Open(ctx, request.StateDir, intelstore.ReadOnly)
	}
	if e != nil {
		result.Outcome = intelOutcome(e)
		return
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			result.Outcome = "unavailable"
		}
	}()
	var selected *intelstore.ID
	switch request.Action {
	case cli.ArgumentActionIntelSync:
		var value intelstore.OperationResult
		value, e = store.Sync(ctx, intelstore.SyncOptions{FullReconciliation: request.Full})
		if e == nil {
			selected = &value.Generation
		}
	case cli.ArgumentActionIntelImport:
		var root *nativefs.Root
		root, e = nativefs.OpenRoot(ctx, filepath.Dir(request.Input))
		if e == nil {
			var input *nativefs.File
			input, e = root.OpenDistributionInput(ctx, filepath.Base(request.Input))
			if e == nil {
				var value intelstore.OperationResult
				value, e = store.Import(ctx, input, intelstore.ImportOptions{TrustedSnapshotDigest: request.TrustedSnapshotDigest})
				e = errors.Join(e, input.Close())
				if e == nil {
					selected = &value.Generation
				}
			}
			e = errors.Join(e, root.Close())
		}
	case cli.ArgumentActionIntelPin, cli.ArgumentActionIntelUnpin:
		var id intelstore.ID
		raw, err := hex.DecodeString(request.Generation)
		if err != nil {
			return
		}
		copy(id[:], raw)
		e = store.SetPinned(ctx, id, request.Action == cli.ArgumentActionIntelPin)
		if e == nil {
			result.Generation = request.Generation
		}
		result.Outcome = intelOutcome(e)
		return
	case cli.ArgumentActionCachePrune:
		if request.ApplyPreview == "" {
			value, err := store.PreviewPrune(ctx)
			e = err
			if e == nil {
				result.Preview = &value
			}
		} else {
			var id intelstore.ID
			raw, _ := hex.DecodeString(request.ApplyPreview)
			copy(id[:], raw)
			value, err := store.ApplyPrune(ctx, id)
			e = err
			result.Prune = &value
		}
		result.Outcome = intelOutcome(e)
		return
	}
	if e != nil {
		result.Outcome = intelOutcome(e)
		return
	}
	snapshot, err := store.ReadPinned(ctx, selected)
	if err != nil {
		result.Outcome = intelOutcome(err)
		return
	}
	defer func() {
		if closeErr := snapshot.Close(); closeErr != nil {
			result.Outcome = "unavailable"
		}
	}()
	var expected *intelstore.ID
	if request.TrustedSnapshotDigest != "" {
		digest, err := intel.ParseSnapshotDigest(request.TrustedSnapshotDigest)
		if err != nil {
			return
		}
		id := intelstore.ID(digest)
		expected = &id
	}
	observed, err := snapshot.Observe(ctx, time.Now(), expected)
	if err != nil {
		result.Outcome = intelOutcome(err)
		return
	}
	result.Generation = observed.Generation
	result.Observation = &observed
	if request.Action == cli.ArgumentActionIntelExport {
		result.WrittenBytes, e = store.ExportFile(ctx, snapshot, request.Output)
	}
	result.Outcome = intelOutcome(e)
	return
}
