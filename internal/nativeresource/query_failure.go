package nativeresource

import (
	"errors"
	"syscall"
)

// QueryFailure retains only fixed query stages and numeric kernel facts. Error
// remains the existing private code: no path or raw syscall error is exposed.
type QueryFailure struct {
	Stage   string
	Errno   int
	Revents int16
}

func (*QueryFailure) Error() string { return ErrUnavailable.Error() }
func (*QueryFailure) Unwrap() error { return ErrUnavailable }
func queryFailure(stage string, err error, revents int16) error {
	var errno syscall.Errno
	_ = errors.As(err, &errno)
	return &QueryFailure{Stage: stage, Errno: int(errno), Revents: revents}
}
