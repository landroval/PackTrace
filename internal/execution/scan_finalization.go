package execution

import "errors"

// This checkpoint belongs only to ScanRun.Finish, after output and binding
// closes. Intel and legacy batch finalization retain their existing semantics.
func (m *scanLifecycle) noteFinalFault(stage string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.faultLockedRole(stage, err, "")
}

func accountScanPeaks(own, sampledOwn uint64, roles []ScanRoleReceipt) ScanFinalization {
	r := ScanFinalization{Status: "observed", SupervisorPeakResidentBytes: own, SumPeakResidentBytes: max(own, sampledOwn)}
	if own == 0 {
		r.Status = "missing"
	}
	for _, role := range roles {
		if !role.Reaped || !role.WaitReturned || !role.ExchangeJoined || !role.StderrJoined || role.WaitPeakResidentBytes == 0 {
			r.Status = "missing"
		}
		// Retain positive observations even if another role/metric is missing.
		peak := max(role.WaitPeakResidentBytes, role.PeakResidentBytes)
		if peak > ^uint64(0)-r.SumPeakResidentBytes {
			r.SumPeakResidentBytes = ^uint64(0)
		} else {
			r.SumPeakResidentBytes += peak
		}
	}
	return r
}

func scanPeakStatus(supported bool, own uint64, err error, status string) string {
	if !supported {
		return "unsupported"
	}
	if err != nil {
		return "failed"
	}
	if own == 0 {
		return "missing"
	}
	return status
}

func (m *scanLifecycle) finalize(prior error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.finalized {
		return m.finalErr
	}
	m.finalized = true
	own, supported, err := supervisorPeakResidentBytes()
	m.finalization.Status = scanPeakStatus(supported, own, err, "observed")
	if supported {
		m.finalization = accountScanPeaks(own, m.resources.SupervisorPeakBytes, m.roles)
		m.finalization.Status = scanPeakStatus(supported, own, err, m.finalization.Status)
		if err != nil {
			m.resources.QueryFailed = true
			m.faultLockedRole("final-supervisor-peak", err, "")
		} else if m.finalization.Status == "missing" {
			m.resources.Stale = true
			m.faultLockedRole("final-peak-missing", nil, "")
		}
		if m.finalization.SumPeakResidentBytes > 1<<30 {
			m.resources.Stopped = true
			m.faultLockedRole("final-peak-threshold", nil, "")
		}
		if m.faultLocked() {
			prior = errors.Join(prior, errScanResource)
		}
	}
	m.finalErr = prior
	return prior
}
