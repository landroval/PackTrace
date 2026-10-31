//go:build !windows || !amd64

package nativeresource

import "os"

// Keep Linux's reviewed direct-unreaped-child acquisition unchanged. Windows
// instead duplicates os.Process.WithHandle without any numeric-PID lookup.
func PinProcess(process *os.Process) (*Child, error) {
	if process == nil {
		return nil, ErrUnavailable
	}
	return PinChild(process.Pid)
}
