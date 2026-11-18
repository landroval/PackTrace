package execution

import (
	"math"
	"os"
	"syscall"
)

// Linux ru_maxrss is reported in KiB. This is not an aggregate tree peak.
func waitPeakResidentBytes(state *os.ProcessState) uint64 {
	r, _ := state.SysUsage().(*syscall.Rusage)
	if r == nil || r.Maxrss <= 0 || uint64(r.Maxrss) > math.MaxUint64/1024 {
		return 0
	}
	return uint64(r.Maxrss) * 1024
}
