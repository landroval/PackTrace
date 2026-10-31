package execution

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	launchRole   = "PACKTRACE_INTERNAL_ROLE"
	launchNonce  = "PACKTRACE_INTERNAL_NONCE"
	launchHandle = "PACKTRACE_INTERNAL_HANDLE"
	launchData   = "PACKTRACE_INTERNAL_DATA"
)

var errReap = errors.New("inspect-batch: reap-unconfirmed")
var errJoin = errors.New("inspect-batch: cleanup-unconfirmed")
var errOutput = errors.New("cli: output-failed")

type runState struct {
	mu       sync.Mutex // one live role, including concurrent WriteOutput calls
	budget   traffic
	deadline time.Time
	caller   context.Context
	broken   bool
}

func newRunState(ctx context.Context) *runState {
	deadline := time.Now().Add(5 * time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return &runState{deadline: deadline, caller: ctx}
}
func (s *runState) work(ctx context.Context) (context.Context, context.CancelFunc) {
	work, cancel := context.WithDeadline(s.caller, s.deadline)
	stop := context.AfterFunc(ctx, cancel)
	return work, func() { stop(); cancel() }
}
func explicitCancel(ctx context.Context) bool { return errors.Is(ctx.Err(), context.Canceled) }
func (s *runState) contextError(ctx context.Context) error {
	if explicitCancel(ctx) || explicitCancel(s.caller) {
		return errors.New("inspect-batch: interrupted")
	}
	if ctx.Err() != nil || s.caller.Err() != nil || !time.Now().Before(s.deadline) {
		return errors.New("inspect-batch: worker-deadline")
	}
	return nil
}
func childCommand(arg string) (*exec.Cmd, error) {
	executable, e := os.Executable()
	if e != nil {
		return nil, errors.New("inspect-batch: worker-unavailable")
	}
	cmd := exec.Command(executable, arg)
	return cmd, nil
}
func reducedEnvironment() []string {
	env := []string{}
	if root := os.Getenv("SystemRoot"); runtime.GOOS == "windows" && root != "" {
		env = append(env, "SystemRoot="+root)
	}
	return env
}
func configureLaunch(cmd *exec.Cmd, role string, files ...*os.File) (string, func(), error) {
	ids, release, e := inheritFiles(cmd, files...)
	if e != nil {
		return "", nil, e
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		release()
		return "", nil, errProtocol
	}
	cap := hex.EncodeToString(nonce[:])
	cmd.Env = append(reducedEnvironment(), launchRole+"="+role, launchNonce+"="+cap, launchHandle+"="+ids[0])
	if len(ids) == 2 {
		cmd.Env = append(cmd.Env, launchData+"="+ids[1])
	}
	return cap, release, nil
}

// Metadata is supplied only by the trusted launch, never a path/handle from
// JSONL. This capability is consistency/private-entry gating, not a sandbox.
func launchCapability(role string) (string, []uintptr, error) {
	arg := WorkerArgument
	if role == "writer" {
		arg = WriterArgument
	}
	if len(os.Args) != 2 || os.Args[1] != arg || os.Getenv(launchRole) != role {
		return "", nil, errProtocol
	}
	cap := os.Getenv(launchNonce)
	decoded, e := hex.DecodeString(cap)
	if e != nil || len(decoded) != 32 {
		return "", nil, errProtocol
	}
	names := []string{launchHandle}
	if role == "writer" {
		names = append(names, launchData)
	} else if os.Getenv(launchData) != "" {
		return "", nil, errProtocol
	}
	var ids []uintptr
	for _, name := range names {
		id, e := strconv.ParseUint(os.Getenv(name), 10, strconv.IntSize)
		if e != nil {
			return "", nil, errProtocol
		}
		ids = append(ids, uintptr(id))
	}
	if !validLaunchHandles(ids) {
		return "", nil, errProtocol
	}
	return cap, ids, nil
}

// Every parent endpoint is a newly owned private pipe with verified deadlines.
// No Fd call or inherited-file pollability assumption is used on these ends.
func privatePipe() (*os.File, *os.File, error) {
	r, w, e := platformPipe()
	if e != nil {
		return nil, nil, errProtocol
	}
	if r.SetReadDeadline(time.Time{}) != nil || w.SetWriteDeadline(time.Time{}) != nil {
		r.Close()
		w.Close()
		return nil, nil, errProtocol
	}
	return r, w, nil
}

type inputSource struct {
	file              *os.File
	feed              io.Reader
	goPipe            *io.PipeReader
	readEnd, writeEnd *os.File
}

func prepareInput(in io.Reader) (*inputSource, error) {
	s := &inputSource{}
	switch v := in.(type) {
	case *os.File:
		if v == nil {
			return nil, errors.New("inspect-batch: read-failed")
		}
		s.file = v
		return s, nil
	case *bytes.Reader, *bytes.Buffer, *strings.Reader:
		if reflect.ValueOf(in).IsNil() {
			return nil, errors.New("inspect-batch: read-failed")
		}
		s.feed = in
	case *io.PipeReader:
		if v == nil {
			return nil, errors.New("inspect-batch: read-failed")
		}
		s.feed = v
		s.goPipe = v
	default:
		return nil, errors.New("inspect-batch: read-failed")
	}
	var e error
	s.readEnd, s.writeEnd, e = privatePipe()
	if e != nil {
		return nil, e
	}
	s.file = s.readEnd
	return s, nil
}
func (s *inputSource) close() {
	if s.readEnd != nil {
		_ = s.readEnd.Close()
		_ = s.writeEnd.Close()
	}
}

// Only finite memory types or a Go PipeReader (whose Close joins Read) enter
// this bridge. Original CLI files never do. A single detection byte is enough.
func (s *inputSource) bridge(ctx context.Context) func() error {
	if s.feed == nil {
		return func() error { return nil }
	}
	watched := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(watched)
		_ = s.writeEnd.Close()
		if s.goPipe != nil {
			_ = s.goPipe.Close()
		}
	})
	joined := make(chan error, 1)
	go func() {
		_, e := io.Copy(s.writeEnd, io.LimitReader(s.feed, maxInput+1))
		_ = s.writeEnd.Close()
		joined <- e
	}()
	return func() error {
		stopped := stop()
		_ = s.writeEnd.Close()
		if s.goPipe != nil {
			_ = s.goPipe.Close()
		}
		e := <-joined
		if !stopped {
			<-watched
		}
		return e
	}
}

// runChild owns all control I/O and waits. Its exchange must touch only checked
// private pipes/finite memory, never an original public stream. Unknown reap
// prevents any later writer launch. EOF + exchange success alone is insufficient.
func (s *runState) runChild(ctx context.Context, cmd *exec.Cmd, release func(), exchange func(context.Context, *channel, io.Closer) error) (failure error) {
	if s.broken {
		release()
		return errReap
	}
	if e := s.contextError(ctx); e != nil {
		release()
		return e
	}
	work, cancel := s.work(ctx)
	defer cancel()
	childIn, parentIn, e := privatePipe()
	if e != nil {
		release()
		return e
	}
	parentOut, childOut, e := privatePipe()
	if e != nil {
		release()
		childIn.Close()
		parentIn.Close()
		return e
	}
	parentErr, childErr, e := privatePipe()
	if e != nil {
		release()
		childIn.Close()
		parentIn.Close()
		parentOut.Close()
		childOut.Close()
		return e
	}
	defer parentIn.Close()
	defer parentOut.Close()
	defer parentErr.Close()
	cmd.Stdin = childIn
	cmd.Stdout = childOut
	cmd.Stderr = childErr
	if e = s.contextError(ctx); e != nil {
		release()
		childIn.Close()
		childOut.Close()
		childErr.Close()
		return e
	}
	e = cmd.Start()
	release()
	childIn.Close()
	childOut.Close()
	childErr.Close()
	if e != nil {
		return errors.New("inspect-batch: worker-unavailable")
	}
	// Check again after Start: os/exec may expose only the CHILD endpoints via Fd.
	if parentIn.SetWriteDeadline(time.Time{}) != nil || parentOut.SetReadDeadline(time.Time{}) != nil || parentErr.SetReadDeadline(time.Time{}) != nil {
		failure = errProtocol
		cancel()
	}
	childCtx, stopChild := context.WithCancel(work)
	defer stopChild()
	waited := make(chan error, 1)
	go func() { e := cmd.Wait(); stopChild(); waited <- e }()
	stderr := make(chan error, 1)
	go func() {
		var buf [4096]byte
		for {
			n, e := parentErr.Read(buf[:])
			if n > 0 {
				if s.budget.addStderr(n) != nil {
					stderr <- errLimit
					cancel()
					return
				}
			}
			if e == io.EOF {
				stderr <- nil
				return
			}
			if e != nil {
				stderr <- errProtocol
				return
			}
		}
	}()
	finished := make(chan error, 1)
	go func() { finished <- exchange(childCtx, newChannel(parentOut, parentIn, &s.budget), parentIn) }()
	haveExchange := false
	if failure == nil {
		select {
		case failure = <-finished:
			haveExchange = true
		case <-work.Done():
			failure = s.contextError(ctx)
			if failure == nil {
				failure = errProtocol
			}
		}
	}
	if failure != nil {
		cancel()
		_ = cmd.Process.Kill()
		_ = parentIn.Close()
		_ = parentOut.Close()
	}
	var waitErr error
	waitReturned := false
	select {
	case waitErr = <-waited:
		waitReturned = true
	case <-work.Done():
		_ = cmd.Process.Kill()
		select {
		case waitErr = <-waited:
			waitReturned = true
		case <-time.After(2 * time.Second):
			s.broken = true
			failure = errReap
		}
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case waitErr = <-waited:
			waitReturned = true
		case <-time.After(2 * time.Second):
			s.broken = true
			failure = errReap
		}
	}
	if !waitReturned || cmd.ProcessState == nil {
		s.broken = true
		failure = errReap
	}
	if !haveExchange {
		_ = parentIn.Close()
		_ = parentOut.Close()
		select {
		case e = <-finished:
			if failure == nil {
				failure = e
			}
		case <-time.After(2 * time.Second):
			s.broken = true
			failure = errJoin
		}
	}
	var stderrErr error
	select {
	case stderrErr = <-stderr:
	case <-time.After(2 * time.Second):
		_ = parentErr.Close()
		select {
		case <-stderr:
			stderrErr = errProtocol
		case <-time.After(2 * time.Second):
			s.broken = true
			failure = errJoin
		}
	}
	if failure == nil && waitErr != nil {
		failure = errors.New("inspect-batch: worker-exit")
	}
	if stderrErr != nil && !s.broken {
		failure = stderrErr
	}
	if e = s.contextError(ctx); e != nil && !s.broken {
		failure = e
	}
	return failure
}
