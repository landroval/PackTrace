package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestActualWriterVerbatimAndCallerRetained(t *testing.T) {
	run, e := RunBatch(context.Background(), strings.NewReader(fixture), "explicit-only")
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.CreateTemp(t.TempDir(), "approved")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	data := []byte("escaped \\n \"<>&\" \u2603\n\x00no transformation")
	for i := 0; i < 2; i++ {
		if e = run.WriteOutput(context.Background(), f, data); e != nil {
			t.Fatal(e)
		}
	}
	_, _ = f.Seek(0, 0)
	got, e := io.ReadAll(f)
	if e != nil || !bytes.Equal(got, append(append([]byte{}, data...), data...)) {
		t.Fatalf("verbatim output: %q %v", got, e)
	}
}
func TestWriterClosedConsumerFixedError(t *testing.T) {
	run, e := RunBatch(context.Background(), strings.NewReader(fixture), "explicit-only")
	if e != nil {
		t.Fatal(e)
	}
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	r.Close()
	defer w.Close()
	if e = run.WriteOutput(context.Background(), w, []byte("approved")); e == nil || e.Error() != "cli: output-failed" || run.Interrupted {
		t.Fatal(e, run.Interrupted)
	}
	if _, e = w.Stat(); e != nil {
		t.Fatal("caller handle closed", e)
	}
}
func TestSharedTrafficIncludesRenderedBytes(t *testing.T) {
	run, e := RunBatch(context.Background(), strings.NewReader(fixture), "explicit-only")
	if e != nil {
		t.Fatal(e)
	}
	used := run.state.budget.n
	if used <= 0 {
		t.Fatal("parser traffic not charged")
	}
	run.state.budget.n = maxTraffic - 3
	var out bytes.Buffer
	if e = run.WriteOutput(context.Background(), &out, []byte("123")); e != nil || out.String() != "123" {
		t.Fatal(e)
	}
	if e = run.WriteOutput(context.Background(), &out, []byte("4")); !errors.Is(e, errLimit) || out.String() != "123" {
		t.Fatal("reset or uncharged rendered budget", e)
	}
}
func TestWriterControlPreflightBeforePublicIO(t *testing.T) {
	run, e := RunBatch(context.Background(), strings.NewReader(fixture), "explicit-only")
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.CreateTemp(t.TempDir(), "output")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	run.state.budget.n = maxTraffic - 2
	if e = run.WriteOutput(context.Background(), f, []byte("x")); !errors.Is(e, errLimit) {
		t.Fatal(e)
	}
	info, _ := f.Stat()
	if info.Size() != 0 {
		t.Fatal("writer launched without control budget")
	}
}
func TestSharedStderrNotResetForWriterRole(t *testing.T) {
	run, e, _ := runDriver(t, "stderr-exact", strings.NewReader(fixture), 3*time.Second)
	if e != nil || run.state.budget.stderr != maxStderr {
		t.Fatal(e)
	}
	if e = run.state.budget.addStderr(1); !errors.Is(e, errLimit) {
		t.Fatal("stderr reset per role", e)
	}
	if e = run.state.budget.addStderr(0); e != nil {
		t.Fatal("zero length", e)
	}
}
func TestDeadlineIsNotUserInterruptAndNotReset(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	run, e := RunBatch(ctx, r, "explicit-only")
	if run.Interrupted || e == nil || e.Error() != "inspect-batch: worker-deadline" {
		t.Fatal("deadline classified as explicit interrupt", run, e)
	}
	run, e = RunBatch(context.Background(), strings.NewReader(fixture), "explicit-only")
	if e != nil {
		t.Fatal(e)
	}
	run.state.deadline = time.Now().Add(-time.Second)
	var out bytes.Buffer
	if e = run.WriteOutput(context.Background(), &out, []byte("never")); e == nil || run.Interrupted || out.Len() != 0 {
		t.Fatal("writer reset operation deadline", run, e)
	}
}
func TestUnknownIORejectedWithoutCallingIt(t *testing.T) {
	run, e := RunBatch(context.Background(), panicReader{}, "explicit-only")
	if e == nil || e.Error() != "inspect-batch: read-failed" {
		t.Fatal(e)
	}
	if e = run.WriteOutput(context.Background(), panicWriter{}, []byte("never")); e == nil || e.Error() != "cli: output-failed" {
		t.Fatal(e)
	}
}

type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("unbounded writer invoked") }

func TestWriterRefusesMissingLaunchBeforeIO(t *testing.T) {
	if WorkerMain(panicReader{}, panicWriter{}, panicWriter{}) == 0 || WriterMain(panicReader{}, panicWriter{}, panicWriter{}) == 0 {
		t.Fatal("foreign launch accepted")
	}
}
func TestBrokenLifecycleForbidsWriter(t *testing.T) {
	run := BatchRun{state: newRunState(context.Background())}
	run.state.broken = true
	var out bytes.Buffer
	if e := run.WriteOutput(context.Background(), &out, []byte("never")); !errors.Is(e, errReap) || out.Len() != 0 {
		t.Fatal("unknown reap became clean", e)
	}
}
func TestWriterRejectsTransferBeforePublicIO(t *testing.T) {
	for _, mode := range []string{"control", "size", "hash", "nonce", "extra-data", "extra-control", "short-data"} {
		t.Run(mode, func(t *testing.T) {
			public, e := os.CreateTemp(t.TempDir(), "public")
			if e != nil {
				t.Fatal(e)
			}
			defer public.Close()
			raw, feed, e := privatePipe()
			if e != nil {
				t.Fatal(e)
			}
			defer raw.Close()
			defer feed.Close()
			cmd, e := childCommand(WriterArgument)
			if e != nil {
				t.Fatal(e)
			}
			cap, release, e := configureLaunch(cmd, "writer", public, raw)
			if e != nil {
				t.Fatal(e)
			}
			identity, e := buildIdentity()
			if e != nil {
				t.Fatal(e)
			}
			data := []byte("APPROVED")
			sum := sha256.Sum256(data)
			cfg := writerConfig{cap, len(data), hex.EncodeToString(sum[:])}
			switch mode {
			case "size":
				cfg.Size = maxTraffic + 1
			case "hash":
				cfg.SHA256 = strings.Repeat("0", 64)
			case "nonce":
				cfg.Nonce = strings.Repeat("0", 64)
			case "extra-data":
				data = append(data, 'x')
			case "short-data":
				data = data[:3]
			}
			s := newRunState(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			e = s.runChild(ctx, cmd, release, func(_ context.Context, c *channel, input io.Closer) error {
				var h hello
				if e := c.expect("hello", &h); e != nil {
					return e
				}
				if mode == "control" {
					return errProtocol
				}
				if e := c.send("hello", hello{identity}); e != nil {
					return e
				}
				if e := c.send("config", cfg); e != nil {
					return e
				}
				if mode == "extra-control" {
					_ = c.send("done", done{})
				}
				_ = input.Close()
				_, _ = feed.Write(data)
				_ = feed.Close()
				var d writerDone
				return c.expect("written", &d)
			})
			info, _ := public.Stat()
			if e == nil || info.Size() != 0 || cmd.ProcessState == nil {
				t.Fatal("unvalidated transfer reached public handle", mode, e, info)
			}
		})
	}
}
