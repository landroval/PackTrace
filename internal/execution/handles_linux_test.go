//go:build linux

package execution

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func ownChildren() ([]int, error) {
	paths, e := filepath.Glob("/proc/self/task/*/children")
	if e != nil {
		return nil, e
	}
	seen := map[int]bool{}
	for _, path := range paths {
		data, e := os.ReadFile(path)
		if e != nil {
			continue
		}
		for _, id := range strings.Fields(string(data)) {
			pid, e := strconv.Atoi(id)
			if e == nil {
				seen[pid] = true
			}
		}
	}
	var pids []int
	for pid := range seen {
		pids = append(pids, pid)
	}
	return pids, nil
}
func waitRole(t *testing.T, role string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pids, _ := ownChildren()
		if len(pids) > 1 {
			t.Fatalf("more than one child alive: %v", pids)
		}
		if len(pids) == 1 {
			data, e := os.ReadFile("/proc/" + strconv.Itoa(pids[0]) + "/cmdline")
			if e == nil && strings.Contains(string(data), role+"\x00") {
				return pids[0]
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no live expected role", role)
	return 0
}
func flags(t *testing.T, f *os.File) uintptr {
	t.Helper()
	raw, e := f.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	var bits uintptr
	var errno syscall.Errno
	e = raw.Control(func(fd uintptr) { bits, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0) })
	if e != nil || errno != 0 {
		t.Fatal(e, errno)
	}
	return bits
}
func blockingPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	// syscall.Pipe + NewFile models a genuinely blocking inherited CLI handle,
	// unlike os.Pipe's Go-owned pollable endpoints.
	var fd [2]int
	if e := syscall.Pipe(fd[:]); e != nil {
		t.Fatal(e)
	}
	syscall.CloseOnExec(fd[0])
	syscall.CloseOnExec(fd[1])
	r, w := os.NewFile(uintptr(fd[0]), "owned-original-read"), os.NewFile(uintptr(fd[1]), "owned-original-write")
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w
}
func TestSequentialRolesInheritedHandlesAndBoundedKillReap(t *testing.T) {
	input, feed := blockingPipe(t)
	inputFlags := flags(t, input)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type answer struct {
		run BatchRun
		e   error
	}
	done := make(chan answer, 1)
	go func() { run, e := RunBatch(ctx, input, "explicit-only"); done <- answer{run, e} }()
	parser := waitRole(t, WorkerArgument)
	// The parent must not make inherited stdin nonblocking even temporarily.
	if got := flags(t, input); got != inputFlags {
		t.Fatal("caller input flags changed", inputFlags, got)
	}
	if _, e := io.WriteString(feed, fixture); e != nil {
		t.Fatal(e)
	}
	feed.Close()
	a := <-done
	if a.e != nil || !a.run.Usable {
		t.Fatal(a)
	}
	if e := syscall.Kill(parser, 0); !errors.Is(e, syscall.ESRCH) {
		t.Fatal("parser unreaped before writer", e)
	}
	output, sink := blockingPipe(t)
	_ = output // never drain public output
	outputFlags := flags(t, sink)
	written := make(chan error, 1)
	go func() { written <- a.run.WriteOutput(ctx, sink, []byte(strings.Repeat("APPROVED", 1<<17))) }()
	writer := waitRole(t, WriterArgument)
	if writer == parser {
		t.Fatal("unexpected role pid reuse")
	}
	if got := flags(t, sink); got != outputFlags {
		t.Fatal("caller output flags changed", outputFlags, got)
	}
	before := time.Now()
	cancel()
	select {
	case e := <-written:
		if e == nil || !a.run.Interrupted {
			t.Fatal("explicit cancel lost", e, a.run.Interrupted)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked public writer stranded parent")
	}
	if time.Since(before) > time.Second {
		t.Fatal("slow kill/reap", time.Since(before))
	}
	if e := syscall.Kill(writer, 0); !errors.Is(e, syscall.ESRCH) {
		t.Fatal("writer not reaped", e)
	}
	if pids, _ := ownChildren(); len(pids) != 0 {
		t.Fatal("live child after return", pids)
	}
	if _, e := input.Stat(); e != nil {
		t.Fatal("caller input closed", e)
	}
	if _, e := sink.Stat(); e != nil {
		t.Fatal("caller output closed", e)
	}
	if flags(t, input) != inputFlags || flags(t, sink) != outputFlags {
		t.Fatal("shared descriptor flags not retained")
	}
}
func TestGoOwnedCallerFlagsPreservedDuringInheritance(t *testing.T) {
	input, feed, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	defer feed.Close()
	original := flags(t, input)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := RunBatch(ctx, input, "explicit-only"); done <- e }()
	_ = waitRole(t, WorkerArgument)
	changed := flags(t, input) != original
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("unjoined inherited Go pipe")
	}
	if changed || flags(t, input) != original {
		t.Fatal("inheritance invoked Fd on original Go-owned caller and changed shared flags")
	}
}

func TestControlBudgetLaunchesNoChild(t *testing.T) {
	run, e := RunBatch(context.Background(), strings.NewReader(fixture), "explicit-only")
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.CreateTemp(t.TempDir(), "public")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	run.state.budget.n = maxTraffic - 2
	var before, after syscall.Rusage
	if e = syscall.Getrusage(syscall.RUSAGE_CHILDREN, &before); e != nil {
		t.Fatal(e)
	}
	e = run.WriteOutput(context.Background(), f, []byte("x"))
	if !errors.Is(e, errLimit) {
		t.Fatal(e)
	}
	if e = syscall.Getrusage(syscall.RUSAGE_CHILDREN, &after); e != nil {
		t.Fatal(e)
	}
	if before.Utime != after.Utime || before.Stime != after.Stime {
		t.Fatal("child launched despite exhausted shared control budget")
	}
}

func TestOriginalBlockedInputCancellationKillsParser(t *testing.T) {
	input, _ := blockingPipe(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		run, e := RunBatch(ctx, input, "explicit-only")
		if !run.Interrupted {
			e = errors.New("missing explicit interrupt")
		}
		done <- e
	}()
	pid := waitRole(t, WorkerArgument)
	before := time.Now()
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("clean canceled parser")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("original input read stranded parent")
	}
	if time.Since(before) > time.Second {
		t.Fatal("slow blocked-input return")
	}
	if e := syscall.Kill(pid, 0); !errors.Is(e, syscall.ESRCH) {
		t.Fatal("parser still alive", e)
	}
	if _, e := input.Stat(); e != nil {
		t.Fatal("original stdin closed", e)
	}
}
