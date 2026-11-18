//go:build !linux

package execution

import "os"

func waitPeakResidentBytes(*os.ProcessState) uint64 { return 0 }
