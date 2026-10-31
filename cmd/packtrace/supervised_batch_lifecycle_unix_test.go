//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Fill a synthetic inherited pipe before launching the command. The command
// gets an ordinary blocking fd, not a Go deadline-capable wrapper.
func batchFullPipe(t *testing.T) (*os.File, *os.File) {
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
	data := bytes.Repeat([]byte("x"), 4096)
	for {
		_, err := syscall.Write(fd, data)
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

// Installing NotifyContext before argument validation would swallow the legacy
// default SIGINT while help/error output is blocked. No actual work is selected.
func TestSupervisedNoWorkDefaultInterrupt(t *testing.T) {
	for _, help := range []bool{true, false} {
		t.Run(map[bool]string{true: "help", false: "invalid"}[help], func(t *testing.T) {
			_, sink := batchFullPipe(t)
			args := []string{"inspect-batch", "--format=PRIVATE"}
			if help {
				args = []string{"inspect-batch", "--help"}
			}
			cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestSupervisedCLIProcess$", "--"}, args...)...)
			if help {
				cmd.Stdout = sink
			} else {
				cmd.Stderr = sink
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			time.Sleep(200 * time.Millisecond)
			if err := cmd.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
				status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGINT {
					t.Fatalf("no-work changed default SIGINT: %v", cmd.ProcessState)
				}
			case <-time.After(2 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Fatal("no-work swallowed SIGINT")
			}
		})
	}
}

// Replacing only report stdout still leaves fatal diagnostics vulnerable to a
// blocked inherited stderr after NotifyContext has swallowed default SIGINT.
func TestSupervisedBatchInterruptBlockedDiagnostic(t *testing.T) {
	_, sink := batchFullPipe(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "inspect-batch", "--format=json")
	cmd.Stdin = strings.NewReader("PRIVATE-invalid-json")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, sink
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	time.Sleep(250 * time.Millisecond)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if cmd.ProcessState.ExitCode() != 130 || out.Len() != 0 {
			t.Fatalf("blocked diagnostic: exit=%d stdout=%q", cmd.ProcessState.ExitCode(), out.String())
		}
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("SIGINT did not interrupt blocked diagnostic")
	}
}
