// Package cli contains pure CLI decisions, not an operational scan runner.
package cli

// ScanExitConditions are qualified caller conditions, not evidence collected here.
// Default flags do not establish complete coverage, no findings or safety.
type ScanExitConditions struct {
	Interrupted                bool
	ReportPreventingError      bool
	RequiredCoverageIncomplete bool
	EnforcedUnacceptedFindings bool
}

// SelectScanExit selects a code without terminating the process or erasing facts.
// User interruption precedes ordinary error > required gap > enforcement > success.
func SelectScanExit(conditions ScanExitConditions) int {
	if conditions.Interrupted {
		return 130
	}
	if conditions.ReportPreventingError {
		return 2
	}
	if conditions.RequiredCoverageIncomplete {
		return 3
	}
	if conditions.EnforcedUnacceptedFindings {
		return 1
	}
	return 0
}
