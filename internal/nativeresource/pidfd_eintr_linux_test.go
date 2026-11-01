//go:build linux && (amd64 || arm64)

package nativeresource

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestInterruptedImmediatePidfdQueryRequiresSuccessfulObservation(t *testing.T) {
	for _, revents := range []int16{0, 1, 16} {
		calls := 0
		exited, e := pidfdExitWithin(0, func(wait time.Duration) (int16, syscall.Errno) {
			if wait != 0 {
				t.Fatal("immediate query became blocking")
			}
			calls++
			if calls == 1 {
				return 0, syscall.EINTR
			}
			return revents, 0
		})
		if e != nil || calls != 2 || exited != (revents != 0) {
			t.Fatalf("interruption not resolved by actual next observation: calls=%d exited=%v error=%v", calls, exited, e)
		}
	}
}
func TestInterruptedPidfdRetryIsFiniteAndNeverInventsExit(t *testing.T) {
	for _, bound := range []time.Duration{0, 25 * time.Millisecond} {
		calls := 0
		exited, e := pidfdExitWithin(bound, func(wait time.Duration) (int16, syscall.Errno) {
			calls++
			if wait < 0 || wait > bound {
				t.Fatal("timeout extended")
			}
			return 0, syscall.EINTR
		})
		var q *QueryFailure
		if exited || e == nil || !errors.As(e, &q) || q.Errno != int(syscall.EINTR) || calls > 9 {
			t.Fatal("persistent interruption gained exit or unbounded retry", calls, exited, e)
		}
	}
	for _, result := range []struct {
		revents int16
		errno   syscall.Errno
	}{{0, syscall.EBADF}, {0, syscall.EPERM}, {8, 0}} {
		calls := 0
		exited, e := pidfdExitWithin(0, func(time.Duration) (int16, syscall.Errno) { calls++; return result.revents, result.errno })
		if exited || e == nil || calls != 1 {
			t.Fatal("real query failure weakened", calls, exited, e)
		}
	}
}
