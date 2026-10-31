//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"packtrace/internal/execution"
	"packtrace/internal/inspect"
)

func batchPressureInput(t *testing.T) []byte {
	t.Helper()
	packages := map[string]any{}
	for i := 0; i < 32; i++ {
		packages[fmt.Sprintf("node_modules/owned%d", i)] = map[string]any{"name": "owned", "version": "1.2.3"}
	}
	ad := map[string]any{"id": "PRIVATE-owned", "modified": "2026-01-01T00:00:00Z", "affected": []any{map[string]any{"package": map[string]any{"ecosystem": "npm", "name": "owned"}, "versions": []string{"1.2.3"}}}}
	ads := make([]any, 16)
	for i := range ads {
		ads[i] = ad
	}
	wire, err := json.Marshal(map[string]any{"lockfile": map[string]any{"lockfileVersion": 3, "packages": packages}, "advisories": ads})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// A blocking inherited stdout must live only in the writer child. SIGINT must
// kill/reap that child, not swallow interruption or return a stale exit 3.
func TestSupervisedBatchInterruptBlockedOutput(t *testing.T) {
	for _, format := range []string{"json", "terminal"} {
		for _, drain := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/drain=%t", format, drain), func(t *testing.T) {
				reader, output, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "inspect-batch", "--format="+format)
				cmd.Stdin = bytes.NewReader(batchPressureInput(t))
				cmd.Stdout = output
				var diagnostic bytes.Buffer
				cmd.Stderr = &diagnostic
				if err = cmd.Start(); err != nil {
					output.Close()
					t.Fatal(err)
				}
				output.Close()
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
				first := make([]byte, 1)
				if _, err = io.ReadFull(reader, first); err != nil {
					t.Fatalf("no output: %v", err)
				}
				// One byte released cannot drain either report. Worker has
				// completed before rendering; only the public write is blocked.
				time.Sleep(100 * time.Millisecond)
				if err = cmd.Process.Signal(os.Interrupt); err != nil {
					t.Fatal(err)
				}
				if drain {
					time.Sleep(50 * time.Millisecond)
					if _, err = io.Copy(io.Discard, reader); err != nil {
						t.Fatal(err)
					}
				}
				select {
				case <-done:
					reaped = true
					if cmd.ProcessState.ExitCode() != 130 || strings.Contains(diagnostic.String(), "PRIVATE") {
						t.Fatalf("exit=%d stderr=%q", cmd.ProcessState.ExitCode(), diagnostic.String())
					}
				case <-time.After(2 * time.Second):
					t.Fatal("SIGINT did not interrupt blocked public output")
				}
			})
		}
	}
}

func batchFileFlags(t *testing.T, f *os.File) uintptr {
	t.Helper()
	raw, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags uintptr
	var errno syscall.Errno
	if err = raw.Control(func(fd uintptr) { flags, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0) }); err != nil || errno != 0 {
		t.Fatalf("flags: %v %v", err, errno)
	}
	return flags
}

// Passing the original sink to a child must neither close it nor change its
// shared flags. Both blocking and already-nonblocking caller flags survive.
func TestSupervisedOutputPreservesCallerFileAndFlags(t *testing.T) {
	for _, blocking := range []bool{true, false} {
		t.Run(fmt.Sprint(blocking), func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			if blocking {
				_ = w.Fd() // Explicitly model an inherited blocking NewFile.
			}
			before := batchFileFlags(t, w)
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			run := execution.BatchRun{}
			if err = run.WriteOutput(ctx, w, bytes.Repeat([]byte("x"), 1<<20)); err == nil || err.Error() != "inspect-batch: worker-deadline" {
				t.Fatalf("blocked output deadline: %v", err)
			}
			if after := batchFileFlags(t, w); after != before {
				t.Fatalf("shared flags changed: %#x -> %#x", before, after)
			}
			_ = r.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			_, _ = io.Copy(io.Discard, r)
			_ = r.SetReadDeadline(time.Time{})
			if _, err = w.Write([]byte("after")); err != nil {
				t.Fatalf("caller's pipe unusable: %v", err)
			}
			data := make([]byte, 5)
			if _, err = io.ReadFull(r, data); err != nil || string(data) != "after" {
				t.Fatalf("caller's pipe: %q %v", data, err)
			}
		})
	}
}

func TestSupervisedOutputDeadlineExit(t *testing.T) {
	wire := batchPressureInput(t)
	result, err := inspect.ReadBatch(bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var diagnostic bytes.Buffer
	if exit := renderSupervisedBatchContext(ctx, ctx, execution.BatchRun{Usable: true, Result: result}, nil, "json", w, &diagnostic); exit != 2 {
		t.Fatalf("deadline mistaken for SIGINT: exit=%d stderr=%q", exit, diagnostic.String())
	}
}

func TestSupervisedOutputRegularAndNull(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	run := execution.BatchRun{}
	if err = run.WriteOutput(context.Background(), f, []byte("legacy\n")); err != nil {
		t.Fatal(err)
	}
	_, _ = f.Seek(0, 0)
	data, err := io.ReadAll(f)
	if err != nil || string(data) != "legacy\n" {
		t.Fatalf("regular output: %q %v", data, err)
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if err = run.WriteOutput(context.Background(), null, []byte("legacy\n")); err != nil {
		t.Fatal(err)
	}
}
