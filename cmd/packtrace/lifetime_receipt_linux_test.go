package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"packtrace/internal/execution"
)

// Only the outer owner can observe the CLI's wait result, after Finish and exit.
// Linux wait accounting may include a waited descendant's high water mark:
// the sum is conservative, not simultaneous RSS or an exact own-only peak.
func TestScanLifetimeWaitSumOwnedLinux(t *testing.T) {
	root, policy := scanFixture(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--checks", "integrity", "--format", "json", root)
	receipt := retainScanReceipt(t, cmd)
	if err := cmd.Run(); cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 {
		t.Fatalf("expected incomplete owned scan: %v", err)
	}
	var r execution.ScanReceipt
	if err := json.Unmarshal([]byte(receipt()), &r); err != nil || !r.Finished || !r.CleanupConfirmed {
		t.Fatalf("incomplete final receipt: %v %+v", err, r)
	}
	usage := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if usage.Maxrss <= 0 {
		t.Fatal("missing supervisor wait usage")
	}
	total := uint64(usage.Maxrss) * 1024
	counts := map[string]int{}
	for _, role := range r.Roles {
		if !role.WaitReturned || !role.Reaped || !role.ExchangeJoined || !role.ExchangeSucceeded || !role.StderrJoined || role.ExitCode != 0 || role.WaitPeakResidentBytes == 0 {
			t.Fatal("unaccounted role", role)
		}
		counts[role.Role]++
		total += role.WaitPeakResidentBytes
	}
	if len(r.Roles) != 3 || counts["scan"] != 2 || counts["scan-writer"] != 1 {
		t.Fatal("unexpected owned role set", counts)
	}
	t.Logf("supervisor wait=%d bytes; conservative total=%d bytes across supervisor and %d children", uint64(usage.Maxrss)*1024, total, len(r.Roles))
}
