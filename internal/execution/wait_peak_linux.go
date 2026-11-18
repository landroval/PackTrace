package execution

import (
	"math"
	"os"
	"syscall"
)

// Linux ru_maxrss is reported in KiB. This is not an aggregate tree peak.
func waitPeakResidentBytes(state *os.ProcessState) uint64 {
	if state == nil {
		return 0
	}
	r, _ := state.SysUsage().(*syscall.Rusage)
	if r == nil {
		return 0
	}
	return linuxPeakBytes(int64(r.Maxrss))
}

func linuxPeakBytes(kib int64) uint64 {
	if kib <= 0 {
		return 0
	}
	if uint64(kib) > math.MaxUint64/1024 {
		return math.MaxUint64 // positive over-budget observation, never a wrapped zero
	}
	return uint64(kib) * 1024
}

func supervisorPeakResidentBytes() (uint64, bool, error) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, true, err
	}
	return linuxPeakBytes(int64(usage.Maxrss)), true, nil
}
