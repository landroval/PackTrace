//go:build linux

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScanInterruptBlockedSequentialWriter(t *testing.T) {
	root, policy := scanFixture(t)
	for i := 0; i < 400; i++ {
		if e := os.WriteFile(filepath.Join(root, "node_modules/PRIVATE-pkg", fmt.Sprintf("extra-%03d", i)), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	reader, writer, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--checks", "integrity", "--format", "json", root)
	receipt := retainScanReceipt(t, cmd)
	cmd.Stdout = writer
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	if e = cmd.Start(); e != nil {
		writer.Close()
		t.Fatal(e)
	}
	writer.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	reaped := false
	defer func() {
		if !reaped {
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	_ = reader.SetReadDeadline(time.Now().Add(5 * time.Second))
	var first [1]byte
	if _, e = io.ReadFull(reader, first[:]); e != nil {
		// Join os/exec's stderr copy before retaining failure diagnostics.
		// Reading its bytes.Buffer while cmd.Wait is active would race.
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		reaped = true
		t.Fatalf("no actual report prefix: read=%v exit=%d joined-stderr=%q receipt=%s", e, cmd.ProcessState.ExitCode(), diagnostic.String(), receipt())
	}
	// Receiving report bytes proves acquisition has ended. The large report
	// cannot fit in the undrained pipe; only the sequential writer may be live.
	if e = cmd.Process.Signal(os.Interrupt); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
		reaped = true
		if cmd.ProcessState.ExitCode() != 130 || strings.Contains(diagnostic.String(), "PRIVATE") {
			t.Fatalf("blocked scan output exit=%d diag=%s receipt=%s", cmd.ProcessState.ExitCode(), diagnostic.String(), receipt())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked scan writer not joined/reaped")
	}
}
