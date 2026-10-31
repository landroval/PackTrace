package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/execution"
	"packtrace/internal/inspect"
)

// The test executable dispatches both trusted same-executable child roles.
// No production fixture switch or environment variable is needed.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && (os.Args[1] == execution.WorkerArgument || os.Args[1] == execution.WriterArgument || os.Args[1] == execution.ScanWorkerArgument) {
		main()
	}
	os.Exit(m.Run())
}

// Test-only process entry: exercise main's actual signal and dispatch boundary.
func TestSupervisedCLIProcess(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			// Test-only owned regular file: never a public stream or production
			// environment hook. Worker environments do not inherit this setting.
			if path := os.Getenv("PACKTRACE_TEST_SCAN_RECEIPT"); path != "" {
				f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if e != nil {
					t.Fatal(e)
				}
				code := runMainObserved(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, func(r execution.ScanReceipt) {
					data, e := json.Marshal(r)
					if e == nil && len(data) <= 16384 {
						_, _ = f.Write(data)
					}
				})
				_ = f.Close()
				os.Exit(code)
			}
			main()
		}
	}
}

func TestSupervisedBatchInterruptBlockedInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt cannot be sent to a Windows child by os.Process.Signal")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "inspect-batch", "--format=json")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	var out, diagnostic bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// Input remains open and empty. The process must stop supervised work, not
	// rely on stdin EOF, and return the public interruption code itself.
	time.Sleep(300 * time.Millisecond)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if cmd.ProcessState.ExitCode() != 130 || out.Len() != 0 || strings.Contains(diagnostic.String(), "PRIVATE") || strings.Contains(diagnostic.String(), "cleanup-unconfirmed") {
			t.Fatalf("blocked-input interruption: exit=%d stdout=%q stderr=%q", cmd.ProcessState.ExitCode(), out.String(), diagnostic.String())
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("blocked-input interruption failed to terminate within 5s")
	}
}

// Reject private argument variants before entering the worker or touching input.
func TestSupervisedPrivateArguments(t *testing.T) {
	for _, args := range [][]string{
		{execution.WorkerArgument, "PRIVATE-extra"},
		{execution.WorkerArgument, "--help"},
		{execution.WriterArgument, "PRIVATE-extra"},
		{execution.WriterArgument, "--help"},
		{execution.WriterArgument + "=PRIVATE"},
		{"--internal-inspect-batch-writer-v2"},
		{execution.WorkerArgument + "=PRIVATE"},
		{"--internal-inspect-batch-worker-v2"},
		{"PRIVATE-command", execution.WorkerArgument},
		{"inspect-batch", execution.WorkerArgument},
	} {
		var out, diag bytes.Buffer
		if exit := runMain(args, forbiddenReader{}, &out, &diag); exit != 2 || out.Len() != 0 || diag.Len() == 0 || strings.Contains(diag.String(), "PRIVATE") {
			t.Fatalf("private arguments %q: exit=%d stdout=%q stderr=%q", args, exit, out.String(), diag.String())
		}
	}
}

func TestSupervisedPrivateMissingLaunchCapability(t *testing.T) {
	for _, role := range []string{execution.WorkerArgument, execution.WriterArgument} {
		var out, diag bytes.Buffer
		if exit := runMain([]string{role}, forbiddenReader{}, &out, &diag); exit != 2 || out.Len() != 0 || diag.Len() != 0 {
			t.Fatalf("unlaunched role %s: exit=%d stdout=%q stderr=%q", role, exit, out.String(), diag.String())
		}
	}
}

func TestSupervisedCanceledBeforeInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, diag bytes.Buffer
	if exit := runBatchContext(ctx, nil, forbiddenReader{}, &out, &diag); exit != 130 || out.Len() != 0 || strings.Contains(diag.String(), "PRIVATE") {
		t.Fatalf("pre-canceled: exit=%d stdout=%q stderr=%q", exit, out.String(), diag.String())
	}
}

// A regression returning worker-supplied ExitCode (including 0) instead of the
// CLI's qualified exit would fail this boundary check.
func TestSupervisedParentRenderingAndExit(t *testing.T) {
	result, err := inspect.ReadBatch(strings.NewReader(batchInput))
	if err != nil {
		t.Fatal(err)
	}
	for _, workerExit := range []int{0, 1, 2, 130} {
		for _, interrupted := range []bool{false, true} {
			for _, abnormal := range []bool{false, true} {
				run := execution.BatchRun{Result: result, Usable: true, Interrupted: interrupted}
				run.Result.ExitCode = workerExit
				var runErr error
				if abnormal {
					runErr = errors.New("inspect-batch: execution-failed")
				}
				var out, diag bytes.Buffer
				want := 3
				if interrupted {
					want = 130
				}
				exit := renderSupervisedBatch(run, runErr, "json", &out, &diag, false)
				if exit != want || diag.Len() != 0 || !strings.Contains(out.String(), fmt.Sprintf(`"exit_code": %d`, want)) {
					t.Fatalf("parent exit=%d want=%d report=%s diagnostic=%s", exit, want, out.String(), diag.String())
				}
			}
		}
	}
	for _, interrupted := range []bool{false, true} {
		want := 2
		if interrupted {
			want = 130
		}
		for _, usable := range []bool{false, true} {
			for _, short := range []bool{false, true} {
				var diag bytes.Buffer
				run := execution.BatchRun{Result: result, Usable: usable, Interrupted: interrupted}
				if exit := renderSupervisedBatch(run, errors.New("inspect-batch: execution-failed"), "json", failedWriter{short}, &diag, false); exit != want || strings.Contains(diag.String(), "PRIVATE") || diag.Len() == 0 {
					t.Fatalf("error precedence exit=%d want=%d diagnostic=%s", exit, want, diag.String())
				}
			}
		}
		var out, diag bytes.Buffer
		if exit := renderSupervisedBatch(execution.BatchRun{Result: result, Usable: true, Interrupted: interrupted}, nil, "PRIVATE-format", &out, &diag, false); exit != want || out.Len() != 0 || diag.String() != "inspect-batch: report-failed\n" {
			t.Fatalf("render failure exit=%d want=%d diagnostic=%s", exit, want, diag.String())
		}
	}
}

func TestSupervisedPrivateWorkerMalformedWire(t *testing.T) {
	for _, role := range []string{execution.WorkerArgument, execution.WriterArgument} {
		for _, wire := range []string{"", "PRIVATE-not-json\n", "{}\n", `{"version":1,"version":1}` + "\n"} {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cmd := exec.CommandContext(ctx, os.Args[0], role)
			cmd.Stdin = strings.NewReader(wire)
			var out, diag bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &diag
			err := cmd.Run()
			cancel()
			if err == nil {
				t.Fatalf("malformed private wire accepted: %q", wire)
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatalf("malformed private wire failed to terminate: %q", wire)
			}
			if strings.Contains(out.String()+diag.String(), "PRIVATE") || strings.Contains(out.String(), "packtrace.inspect.batch.v1") {
				t.Fatalf("private malformed wire exposed public report or raw input: stdout=%q stderr=%q", out.String(), diag.String())
			}
		}
	}
}
