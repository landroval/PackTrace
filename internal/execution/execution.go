// Package execution supervises sequential same-executable parser/writer children.
// It isolates blocking original I/O, not target code, OS privileges or RSS.
package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"

	"packtrace/internal/demo"
	"packtrace/internal/inspect"
)

const WorkerArgument = "--internal-inspect-batch-worker-v1"
const WriterArgument = "--internal-inspect-batch-writer-v1"

type BatchRun struct {
	Result      inspect.BatchResult
	Usable      bool
	Interrupted bool
	state       *runState
}

func RunBatch(ctx context.Context, in io.Reader, profile string) (BatchRun, error) {
	if !validProfile(profile) {
		return BatchRun{}, errors.New("inspect-batch: invalid-profile")
	}
	s := newRunState(ctx)
	if e := s.contextError(ctx); e != nil {
		return BatchRun{Interrupted: explicitCancel(ctx), state: s}, e
	}
	cmd, e := childCommand(WorkerArgument)
	if e != nil {
		return BatchRun{state: s}, e
	}
	identity, e := buildIdentity()
	if e != nil {
		return BatchRun{state: s}, e
	}
	return superviseState(ctx, in, profile, cmd, identity, s)
}

// Test boundary only: production derives cmd from os.Executable, never input.
func supervise(ctx context.Context, in io.Reader, profile string, cmd *exec.Cmd, identity string) (BatchRun, error) {
	return superviseState(ctx, in, profile, cmd, identity, newRunState(ctx))
}
func superviseState(ctx context.Context, in io.Reader, profile string, cmd *exec.Cmd, identity string, s *runState) (run BatchRun, failure error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run.state = s
	source, e := prepareInput(in)
	if e != nil {
		return run, e
	}
	defer source.close()
	cap, release, e := configureLaunch(cmd, "parser", source.file)
	if e != nil {
		return run, errors.New("inspect-batch: read-failed")
	}
	parsed := make(chan BatchRun, 1)
	failure = s.runChild(ctx, cmd, release, func(childCtx context.Context, c *channel, input io.Closer) error {
		var h hello
		if e := c.expect("hello", &h); e != nil || h.Build != identity {
			return errProtocol
		}
		if e := c.send("hello", hello{identity}); e != nil {
			return e
		}
		if e := c.send("config", config{Nonce: cap, Profile: profile}); e != nil {
			return e
		}
		if e := input.Close(); e != nil {
			return errProtocol
		}
		join := source.bridge(childCtx)
		result, e := receiveResults(c, profile)
		bridgeErr := join()
		parsed <- result
		if bridgeErr != nil && (e == nil || inputCode(e.Error())) {
			return errors.New("inspect-batch: read-failed")
		}
		return e
	})
	select {
	case run = <-parsed:
	default:
	}
	run.state = s
	run.Interrupted = explicitCancel(ctx) || explicitCancel(s.caller)
	if failure != nil && run.Usable {
		run.Result.Coverage[0] = demo.Coverage{Check: "advisory-records", Outcome: "incomplete", Reason: "execution-incomplete"}
		run.Result.Coverage = append(run.Result.Coverage, demo.Coverage{Check: "execution", Outcome: "incomplete", Reason: "worker-incomplete"})
	}
	return run, failure
}

func receiveResults(c *channel, profile string) (run BatchRun, err error) {
	started, completed := false, false
	var scope start
	var open *advisory
	var expected []demo.Candidate
	var candidates []demo.Candidate
	var inventory []inspect.Observation
	closed, total, slots, pairs := 0, 0, 0, 0
	fatal := ""
	for {
		m, e := c.receive()
		if e == io.EOF {
			if !completed {
				return run, errProtocol
			}
			if fatal != "" {
				return run, errors.New(fatal)
			}
			return run, nil
		}
		if e != nil {
			return run, e
		}
		if completed {
			return run, errProtocol
		}
		switch m.Type {
		case "start":
			if started || fatal != "" || decode(m.Data, &scope) != nil || scope.Locked < 0 || scope.Locked > 64 || scope.Advisories < 1 || scope.Advisories > 16 {
				return run, errProtocol
			}
			started = true
			run.Result = batchResult(scope.Locked, profile)
		case "advisory":
			var a advisory
			if !started || open != nil || closed >= scope.Advisories || decode(m.Data, &a) != nil || a.Index != closed || !one(a.State, "usable", "invalid-advisory") {
				return run, errProtocol
			}
			if a.State == "usable" {
				if a.Report != nil && inventory != nil && !reflect.DeepEqual(inventory, a.Report.Inventory) {
					// Shared lockfile contradiction invalidates even previously closed scopes.
					return BatchRun{}, errProtocol
				}
				if validateReport(a.Report, a.Index, scope.Locked, profile) != nil {
					return run, errProtocol
				}
				inventory = a.Report.Inventory
				pairs += len(a.Report.Evaluations)
				if pairs > 4096 {
					return run, errProtocol
				}
				if scope.Locked > 0 {
					slots += len(a.Report.Evaluations) / scope.Locked
				}
				if slots > 64 {
					return run, errProtocol
				}
				expected = expectedCandidates(a.Report)
			} else {
				if a.Report != nil {
					return run, errProtocol
				}
				expected = nil
			}
			candidates = []demo.Candidate{}
			open = &a
		case "candidate":
			var v candidate
			if open == nil || open.Report == nil || decode(m.Data, &v) != nil || v.Index != open.Index || len(candidates) >= len(expected) || v.Value != expected[len(candidates)] {
				return run, errProtocol
			}
			candidates = append(candidates, v.Value)
		case "closure":
			var v closure
			if open == nil || decode(m.Data, &v) != nil || v.Index != open.Index || v.Candidates != len(candidates) || len(candidates) != len(expected) {
				return run, errProtocol
			}
			evaluations := 0
			if open.Report != nil {
				evaluations = len(open.Report.Evaluations)
				open.Report.Candidates = candidates
			}
			if v.Evaluations != evaluations {
				return run, errProtocol
			}
			run.Result.Advisories = append(run.Result.Advisories, inspect.BatchAdvisory{Reference: fmt.Sprintf("advisory-%d", closed), State: open.State, Report: open.Report})
			if open.Report == nil {
				run.Result.Coverage[0] = demo.Coverage{Check: "advisory-records", Outcome: "incomplete", Reason: "one-or-more-records-unusable"}
			}
			total += len(candidates)
			run.Result.CandidateCount = total
			closed++
			open = nil
			run.Usable = true
		case "diagnostic":
			var v diagnostic
			if decode(m.Data, &v) != nil {
				return run, errProtocol
			}
			if started && v.Code == errLimit.Error() {
				return run, errLimit
			}
			if started || fatal != "" || !inputCode(v.Code) {
				return run, errProtocol
			}
			fatal = v.Code
		case "done":
			var v done
			if decode(m.Data, &v) != nil || open != nil || v.Advisories != closed || v.Candidates != total || (fatal == "" && (!started || closed != scope.Advisories)) || (fatal != "" && started) {
				return run, errProtocol
			}
			completed = true
		default:
			return run, errProtocol
		}
	}
}

func sendSemantic(c *channel, kind string, value any) bool {
	if e := c.send(kind, value); e != nil {
		if errors.Is(e, errLimit) {
			_ = c.send("diagnostic", diagnostic{errLimit.Error()})
		}
		return false
	}
	return true
}

func readInheritedInput(cfg config) ([]byte, error) {
	cap, ids, e := launchCapability("parser")
	if e != nil || cfg.Nonce != cap || !validProfile(cfg.Profile) {
		return nil, errProtocol
	}
	f := os.NewFile(ids[0], "inspect-batch-original-input")
	if f == nil {
		return nil, errProtocol
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, maxInput+1))
	if e != nil {
		return nil, errors.New("inspect-batch: read-failed")
	}
	if len(data) > maxInput {
		return nil, errors.New("inspect-batch: limit-exceeded")
	}
	return data, nil
}

// Only a configured parser child reads original input, and only after exact
// launch, version/build/job/profile/nonce validation and control-channel EOF.
func WorkerMain(in io.Reader, out io.Writer, diagnosticOut io.Writer) int {
	if _, _, e := launchCapability("parser"); e != nil {
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
	var cfg config
	if c.expect("config", &cfg) != nil {
		return 2
	}
	if _, e = c.receive(); e != io.EOF {
		return 2
	}
	data, e := readInheritedInput(cfg)
	var result inspect.BatchResult
	if e == nil {
		result, e = inspect.ReadBatchProfile(bytes.NewReader(data), cfg.Profile)
	}
	if e != nil {
		if !inputCode(e.Error()) {
			return 2
		}
		if c.send("diagnostic", diagnostic{e.Error()}) != nil || c.send("done", done{}) != nil {
			return 2
		}
		return 0
	}
	if c.send("start", start{result.LockedEntries, len(result.Advisories)}) != nil {
		return 2
	}
	for i, a := range result.Advisories {
		var report *inspect.Result
		values := []demo.Candidate{}
		evaluations := 0
		if a.Report != nil {
			copy := *a.Report
			values = copy.Candidates
			copy.Candidates = []demo.Candidate{}
			report = &copy
			evaluations = len(copy.Evaluations)
		}
		if !sendSemantic(c, "advisory", advisory{i, a.State, report}) {
			return 2
		}
		for _, v := range values {
			if c.send("candidate", candidate{i, v}) != nil {
				return 2
			}
		}
		if c.send("closure", closure{i, len(values), evaluations}) != nil {
			return 2
		}
	}
	if c.send("done", done{len(result.Advisories), result.CandidateCount}) != nil {
		return 2
	}
	return 0
}
