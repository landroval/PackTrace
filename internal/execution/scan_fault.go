package execution

import (
	"context"
	"errors"
	"os/exec"
	"time"

	"packtrace/internal/nativeresource"
)

// ScanFault is bounded caller-owned diagnostic metadata, never report content.
// Codes/stages are fixed labels; raw errors, paths, identities and IPC data are
// deliberately absent. The first observed fault is not replaced by cleanup.
type ScanFault struct {
	Stage, Code, Role string
	Elapsed           time.Duration
	QueryStage        string
	Errno             int
	Revents           int16
}

func scanErrorCode(err error) string {
	switch {
	case err == nil:
		return "observation-failed"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, nativeresource.ErrUnavailable):
		return "resident-query-unavailable"
	case errors.Is(err, errScanResource):
		return "resident-observation-failed"
	case errors.Is(err, errReap):
		return "reap-unconfirmed"
	case errors.Is(err, errJoin):
		return "join-unconfirmed"
	case errors.Is(err, errOutput):
		return "output-failed"
	case errors.Is(err, errProtocol), errors.Is(err, errScanProtocol):
		return "protocol-failed"
	case errors.Is(err, errLimit):
		return "limit"
	default:
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "child-exit"
		}
		return "operation-failed"
	}
}
func scanContextStatus(ctx context.Context) string {
	switch ctx.Err() {
	case nil:
		return "active"
	case context.Canceled:
		return "canceled"
	case context.DeadlineExceeded:
		return "deadline"
	default:
		return "unavailable"
	}
}
func (m *scanLifecycle) faultLockedAt(stage string, err error) {
	if m.firstFault.Stage != "" {
		return
	}
	f := ScanFault{Stage: stage, Code: scanErrorCode(err), Elapsed: time.Since(m.started)}
	if m.active >= 0 {
		f.Role = m.roles[m.active].Role
	}
	var query *nativeresource.QueryFailure
	if errors.As(err, &query) {
		f.QueryStage = query.Stage
		f.Errno = query.Errno
		f.Revents = query.Revents
	}
	m.firstFault = f
}
func (m *scanLifecycle) noteFault(stage string, err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.finished {
		m.faultLockedAt(stage, err)
	}
}

// NoteFailure preserves a caller boundary failure before a diagnostic output
// attempt can itself fail. It neither writes nor changes admission/exit policy.
func (r *ScanRun) NoteFailure(stage string, err error) {
	if r.output.state == nil || r.output.state.scan == nil || err == nil {
		return
	}
	switch stage {
	case "run", "checkpoint", "render", "output", "diagnostic":
	default:
		stage = "caller"
	}
	r.output.state.scan.noteFault(stage, err)
}
