package intelstore

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPruneReaderProcessHelper(t *testing.T) {
	path := os.Getenv("PACKTRACE_TEST_PRUNE_READER")
	if path == "" {
		t.Skip("owned reader child")
	}
	id, e := parseID(os.Getenv("PACKTRACE_TEST_PRUNE_GENERATION"))
	if e != nil {
		t.Fatal(e)
	}
	s, e := Open(context.Background(), path, ReadOnly)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	pin, e := s.Pin(context.Background(), &id)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	fmt.Fprintln(os.Stdout, "READY")
	var control [1]byte
	if n, e := os.Stdin.Read(control[:]); e != nil || n != 1 || control[0] != 'R' {
		t.Fatal("missing release")
	}
}
func TestPruneRealReaderMustExitAndReapBeforeHistoryBecomesCandidate(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	first := fixtureGeneration(t, s, "FIRST-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "SECOND-1", "2026-11-01T00:00:00Z")
	fixtureGeneration(t, s, "THIRD-1", "2026-11-01T00:00:00Z")
	work, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(work, os.Args[0], "-test.run=^TestPruneReaderProcessHelper$")
	cmd.Env = append(os.Environ(), "PACKTRACE_TEST_PRUNE_READER="+path, fmt.Sprintf("PACKTRACE_TEST_PRUNE_GENERATION=%x", first))
	input, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	ready, e := bufio.NewReader(io.LimitReader(output, 4096)).ReadString('\n')
	if e != nil || ready != "READY\n" {
		t.Fatal("child did not acquire actual generation", ready, e)
	}
	preview, e := s.PreviewPrune(ctx)
	if e != nil || preview.Generations != 0 {
		t.Fatal("live child protection absent", e)
	}
	if _, e := input.Write([]byte{'R'}); e != nil {
		t.Fatal(e)
	}
	input.Close()
	if e := cmd.Wait(); e != nil || cmd.ProcessState == nil || !cmd.ProcessState.Success() {
		t.Fatal("reader child not exited/reaped", e)
	}
	preview, e = s.PreviewPrune(ctx)
	if e != nil || preview.Generations != 1 {
		t.Fatal("confirmed child release not observed", e)
	}
	if _, e := s.ApplyPrune(ctx, preview.Token); e != nil {
		t.Fatal(e)
	}
}
