//go:build !linux

package execution

import "os"

func waitPeakResidentBytes(*os.ProcessState) uint64 { return 0 }

func supervisorPeakResidentBytes() (uint64, bool, error) { return 0, false, nil }
