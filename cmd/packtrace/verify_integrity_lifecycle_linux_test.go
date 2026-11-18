//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/execution"
)

// Fill a real inherited pipe before admission so even the short integrity
// report blocks in the supervised writer, never in the command goroutine.
func integrityFullPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	fd := int(w.Fd())
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	for {
		_, err = syscall.Write(fd, make([]byte, 4096))
		if err == syscall.EAGAIN {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	return r, w
}

func TestVerifyIntegrityBlockedDeadline(t *testing.T) {
	target, policy, pin := npmPackIntegrityFixture(t)
	_, w := integrityFullPipe(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := cli.ScanArgumentRequest{Path: target, PolicyPath: policy, TrustedPolicyDigest: pin, Manager: "npm", Checks: cli.ArgumentCheckIntegrity, FailOn: cli.ArgumentCheckIntegrity, Privacy: "portable", Format: "terminal", Output: "-"}
	var diag bytes.Buffer
	var receipt execution.ScanReceipt
	code := runIntegrityContext(ctx, req, w, &diag, func(r execution.ScanReceipt) { receipt = r })
	if code != 2 || ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("deadline: %d %v %s", code, ctx.Err(), &diag)
	}
	writer := false
	for _, role := range receipt.Roles {
		if role.Role == "scan-writer" {
			writer = true
		}
		if !role.Reaped || !role.WaitReturned || !role.ExchangeJoined || !role.StderrJoined {
			t.Fatalf("unjoined role: %+v", role)
		}
	}
	if !writer || !receipt.Finished || !receipt.CleanupConfirmed {
		t.Fatalf("did not exercise writer cleanup: %+v", receipt)
	}
	t.Logf("exit=%d receipt=%+v", code, receipt)
}

// Stop only our owned command, not its children or the desktop. A real sampling
// gap exceeds the existing 350ms resource-observation guard. This is not a
// claim to have exhausted the 1GiB resident threshold.
func TestVerifyIntegrityResourceObservationGap(t *testing.T) {
	target, policy, pin := npmPackIntegrityFixture(t)
	_, w := integrityFullPipe(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "verify-integrity", "--policy", policy, "--trusted-policy-digest", pin, target)
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	cmd.Env = append(os.Environ(), "PACKTRACE_TEST_SCAN_RECEIPT="+receiptPath)
	cmd.Stdout = w
	var diag bytes.Buffer
	cmd.Stderr = &diag
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	reaped := false
	defer func() {
		if !reaped {
			cmd.Process.Signal(syscall.SIGCONT)
			cmd.Process.Kill()
			<-done
		}
	}()
	// The final writer is live after the acquisition roles exit. Require the
	// actual writer argv in procfs, rather than a timing-only admission guess.
	deadline := time.Now().Add(10 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		tasks, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", cmd.Process.Pid))
		var children []byte
		for _, task := range tasks {
			data, _ := os.ReadFile(task)
			children = append(children, data...)
			children = append(children, ' ')
		}
		for _, pid := range strings.Fields(string(children)) {
			if _, err := strconv.Atoi(pid); err != nil {
				t.Fatal(err)
			}
			argv, _ := os.ReadFile("/proc/" + pid + "/cmdline")
			if bytes.Contains(argv, []byte(execution.WriterArgument)) {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !found {
		t.Fatal("no live supervised writer")
	}
	if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		reaped = true
		if cmd.ProcessState.ExitCode() != 2 {
			t.Fatalf("resource gap exit=%d stderr=%s", cmd.ProcessState.ExitCode(), &diag)
		}
		data, err := os.ReadFile(receiptPath)
		if err != nil {
			t.Fatal(err)
		}
		var receipt execution.ScanReceipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			t.Fatal(err)
		}
		if !receipt.Resources.Stale || !receipt.Finished || !receipt.CleanupConfirmed || receipt.FirstFault.Stage != "sample-gap" {
			t.Fatalf("resource receipt: %+v", receipt)
		}
		for _, role := range receipt.Roles {
			if !role.Reaped {
				t.Fatalf("unreaped role: %+v", role)
			}
		}
		t.Logf("exit=2 receipt=%+v", receipt)
	case <-time.After(5 * time.Second):
		t.Fatal("resource guard did not terminate blocked writer")
	}
}
