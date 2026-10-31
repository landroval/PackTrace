package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// The child writes exactly once after Finish into an owned regular file. Read
// only after cmd.Wait: it is not a public-output fallback or a live buffer.
func retainScanReceipt(t *testing.T, cmd *exec.Cmd) func() string {
	t.Helper()
	path := t.TempDir() + "/receipt.json"
	cmd.Env = append(os.Environ(), "PACKTRACE_TEST_SCAN_RECEIPT="+path)
	return func() string {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "receipt unavailable"
		}
		if len(raw) > 16384 {
			return "receipt oversized"
		}
		return string(raw)
	}
}

// A failed inherited public sink must not erase the caller-owned operational
// receipt. This is a controlled failure, not a reproduction of the hosted bug.
func TestScanReceiptSurvivesFailedPublicOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned Linux scan process")
	}
	root, policy := scanFixture(t)
	receiptPath := t.TempDir() + "/receipt.json"
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	read.Close()
	defer write.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--checks", "integrity", "--format", "json", root)
	cmd.Env = append(os.Environ(), "PACKTRACE_TEST_SCAN_RECEIPT="+receiptPath)
	cmd.Stdout, cmd.Stderr = write, write
	err = cmd.Run()
	if err == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("controlled failed output: %v %v", cmd.ProcessState, err)
	}
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("failed public output lost final diagnostic receipt: %v", err)
	}
	if len(raw) > 16384 || strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "sha256-") {
		t.Fatal("unbounded or sensitive diagnostic receipt")
	}
	var receipt struct {
		Finished, CleanupConfirmed bool
		FirstFault                 struct{ Stage, Code, Role string }
		Roles                      []struct {
			Role                                               string
			Reaped, WaitReturned, ExchangeJoined, StderrJoined bool
			ExitCode                                           int
		}
	}
	if err = json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	// Either EOF in the control reader or Wait may be observed first; both
	// are real consequences of this controlled writer exit, never a later
	// diagnostic writer's error.
	first := receipt.FirstFault
	observedWriterFailure := first.Stage == "exchange" && first.Code == "output-failed" || first.Stage == "wait-exit" && first.Code == "child-exit"
	if !receipt.Finished || !receipt.CleanupConfirmed || !observedWriterFailure || first.Role != "scan-writer" {
		t.Fatalf("lost first fault or final cleanup: %s", raw)
	}
	if len(receipt.Roles) < 3 {
		t.Fatalf("writer role absent: %s", raw)
	}
	writer := receipt.Roles[2]
	if writer.Role != "scan-writer" || !writer.Reaped || !writer.WaitReturned || !writer.ExchangeJoined || !writer.StderrJoined || writer.ExitCode != 2 {
		t.Fatalf("lost actual writer completion: %s", raw)
	}
	t.Logf("controlled failure receipt: %s", raw)
}
