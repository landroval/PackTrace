package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"packtrace/internal/cli"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	"packtrace/internal/nativefs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Only the test binary dispatches this adversarial producer; no product hook,
// environment escape or caller-selected executable is exposed by RunIntel.
func intelFaultDriver(mode string) int {
	cap, ids, e := launchCapability("intel")
	if e != nil {
		return 98
	}
	w := os.NewFile(ids[0], "owned witness")
	if w == nil {
		return 98
	}
	var b [1]byte
	n, e := w.Read(b[:])
	w.Close()
	if n != 0 || e != io.EOF {
		return 98
	}
	c := newChannel(os.Stdin, os.Stdout, &traffic{})
	identity, e := buildIdentity()
	if e != nil {
		return 98
	}
	if mode == "no-hello" {
		time.Sleep(20 * time.Second)
		return 0
	}
	if mode == "wrong-build" {
		identity = "wrong"
	}
	if c.send("hello", hello{identity}) != nil {
		return 97
	}
	var h hello
	var cfg intelConfig
	if c.expect("hello", &h) != nil || c.expect("config", &cfg) != nil || cfg.Nonce != cap {
		return 96
	}
	if _, e := c.receive(); e != io.EOF {
		return 95
	}
	if mode == "empty-exit" {
		return 0
	}
	result := IntelResult{Action: cfg.Request.Action, Outcome: "unavailable"}
	if mode == "result-before-start" {
		c.send("result", result)
		return 0
	}
	c.send("start", scanStart{"intel"})
	if mode == "double-start" {
		c.send("start", scanStart{"intel"})
		return 0
	}
	rss, e := nativefs.OwnResidentBytes()
	if e != nil {
		return 94
	}
	sample := residentSample{ElapsedMS: 0, Bytes: rss, Valid: mode != "invalid-resident"}
	if mode != "missing-resident" {
		c.send("resident", sample)
	}
	if mode == "oversize" || mode == "traffic" {
		padding := strings.Repeat(" ", 1<<16)
		if mode == "oversize" {
			padding = strings.Repeat(" ", maxMessage)
		}
		count := 1
		if mode == "traffic" {
			count = maxTraffic/len(padding) + 1
		}
		raw, _ := json.Marshal(sample)
		for i := 0; i < count; i++ {
			c.sent++
			if _, e := fmt.Fprintf(os.Stdout, "{\"version\":1,\"seq\":%d,\"job\":1,\"type\":\"resident\",\"data\":%s}%s\n", c.sent, raw, padding); e != nil {
				return 93
			}
		}
	}
	if mode == "progress-wait" {
		for i := 1; i <= 9; i++ {
			time.Sleep(100 * time.Millisecond)
			sample.ElapsedMS = int64(i * 100)
			c.send("resident", sample)
		}
	}
	if mode == "wrong-sequence" {
		io.WriteString(os.Stdout, `{"version":1,"seq":999,"job":1,"type":"done","data":{"results":1}}`+"\n")
		return 0
	}
	if mode == "wrong-action" {
		result.Action = cli.ArgumentActionIntelImport
	}
	if mode == "huge-count" {
		id := strings.Repeat("1", 64)
		result.Generation = id
		result.Observation = &intelstore.Observation{Generation: id, SourceAuthority: intelstore.SourceLocal, Check: intel.FreshnessCurrent, FullReconciliation: intel.FreshnessCurrent, Records: 2_000_001, Gaps: []intelstore.Gap{}}
	}
	if mode == "unknown-outcome" {
		result.Outcome = "publisher-approved"
	}
	if mode == "invented-success" {
		result.Outcome = "complete"
	}
	if mode == "extra-private-field" {
		raw, _ := json.Marshal(result)
		var v map[string]any
		json.Unmarshal(raw, &v)
		v["path"] = "PRIVATE-secret"
		c.send("result", v)
	} else {
		c.send("result", result)
	}
	if mode == "double-result" {
		c.send("result", result)
	}
	if mode == "unclosed" {
		return 0
	}
	count := 1
	if mode == "wrong-closure" {
		count = 2
	}
	c.send("done", intelClosure{count})
	switch mode {
	case "double-done":
		c.send("done", intelClosure{1})
	case "after-done":
		c.send("result", result)
	case "done-crash":
		return 7
	case "done-stall":
		time.Sleep(20 * time.Second)
	case "truncated":
		io.WriteString(os.Stdout, `{"version":1`)
	}
	return 0
}
func TestIntelActualWorkerRejectsWrongNonceBeforeStoreIO(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native launch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	s := newIntelRunState(ctx)
	s.scan = newScanLifecycle(ctx, s.deadline)
	run := IntelRun{lifecycle: ScanRun{output: BatchRun{state: s}}}
	defer run.Finish()
	cmd, e := childCommand(IntelWorkerArgument)
	if e != nil {
		t.Fatal(e)
	}
	witness, feed, e := privatePipe()
	if e != nil {
		t.Fatal(e)
	}
	defer witness.Close()
	defer feed.Close()
	_, release, e := configureLaunch(cmd, "intel", witness)
	if e != nil {
		t.Fatal(e)
	}
	feed.Close()
	identity, e := buildIdentity()
	if e != nil {
		release()
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "must-not-initialize")
	e = s.runChild(ctx, cmd, release, func(_ context.Context, c *channel, input io.Closer) error {
		var h hello
		if c.expect("hello", &h) != nil || h.Build != identity {
			return errIntelProtocol
		}
		if c.send("hello", hello{identity}) != nil || c.send("config", intelConfig{"wrong", cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelImport, StateDir: path, Input: filepath.Join(t.TempDir(), "missing.bundle"), Format: "json"}}) != nil || input.Close() != nil {
			return errIntelProtocol
		}
		if _, e := c.receive(); e != io.EOF {
			return errIntelProtocol
		}
		return nil
	})
	if e == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 2 {
		t.Fatal("wrong nonce accepted or original child not reaped", e, cmd.ProcessState)
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("untrusted launch initialized state", e)
	}
}
func TestIntelActualStalledWriterIsKilledAndReaped(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native writer")
	}
	run, e := RunIntel(context.Background(), cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelStatus, StateDir: filepath.Join(t.TempDir(), "absent"), Format: "json"})
	if e != nil {
		run.Finish()
		t.Fatal(e)
	}
	reader, writer, e := os.Pipe()
	if e != nil {
		run.Finish()
		t.Fatal(e)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	e = run.WriteOutput(ctx, writer, []byte(strings.Repeat("approved public bytes", 65536)))
	receipt, finish := run.Finish()
	if e == nil || len(receipt.Roles) != 2 || receipt.Roles[1].Role != "intel-writer" || !receipt.Roles[1].Reaped || !receipt.CleanupConfirmed {
		t.Fatal("stalled writer became successful output or lost cleanup", e, finish, receipt)
	}
}
func TestIntelFaultChildrenCannotAuthorizeUsableResult(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native process observer")
	}
	for _, mode := range []string{"valid", "huge-count", "wrong-action", "no-hello", "wrong-build", "empty-exit", "result-before-start", "double-start", "missing-resident", "invalid-resident", "wrong-sequence", "unknown-outcome", "invented-success", "extra-private-field", "double-result", "unclosed", "wrong-closure", "double-done", "after-done", "done-crash", "done-stall", "truncated", "oversize", "traffic"} {
		t.Run(mode, func(t *testing.T) {
			// Independent owned processes/roots/budgets; no shared environment edits.
			t.Parallel()
			timeout := 3 * time.Second
			if mode == "no-hello" || mode == "done-stall" {
				timeout = time.Second
			}
			if mode == "traffic" {
				timeout = 12 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			s := newIntelRunState(ctx)
			s.scan = newScanLifecycle(ctx, s.deadline)
			run := IntelRun{lifecycle: ScanRun{output: BatchRun{state: s}}}
			identity, e := buildIdentity()
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(os.Args[0], "--intel-fault-driver", mode)
			request := cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelStatus, StateDir: filepath.Join(t.TempDir(), "absent"), Format: "json"}
			e = run.superviseIntel(ctx, request, cmd, identity, nil)
			receipt, finish := run.Finish()
			if mode == "valid" {
				if e != nil || finish != nil || !run.Usable || cmd.ProcessState == nil || !receipt.CleanupConfirmed {
					t.Fatal("positive driver control", e, finish, receipt)
				}
				return
			}
			public, _ := json.Marshal(struct {
				Result  IntelResult
				Receipt ScanReceipt
			}{run.Result, receipt})
			if strings.Contains(string(public), "PRIVATE") {
				t.Fatal("worker payload leaked into closed parent facts")
			}
			if e == nil || run.Usable || cmd.ProcessState == nil || !receipt.CleanupConfirmed {
				t.Fatalf("bad child granted result or lost original reap: mode=%s usable=%t error=%v state=%v receipt=%+v", mode, run.Usable, e, cmd.ProcessState, receipt)
			}
			if (mode == "traffic" || mode == "oversize") && !errors.Is(e, errLimit) {
				t.Fatalf("byte limit passed for wrong reason: %v", e)
			}
		})
	}
}
