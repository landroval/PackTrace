package execution

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// Removing inherited input isolation makes the supervisor consume this file
// even though the child deliberately never opens its launch input handle.
func TestInheritedInputNotReadBySupervisor(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "owned-input")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.WriteString(fixture); e != nil {
		t.Fatal(e)
	}
	_, _ = f.Seek(0, 0)
	_, e, _ = runDriver(t, "exit-zero", f, 3*time.Second)
	if e == nil {
		t.Fatal("missing result accepted")
	}
	pos, e := f.Seek(0, io.SeekCurrent)
	if e != nil || pos != 0 {
		t.Fatalf("parent consumed original before child read: offset=%d error=%v", pos, e)
	}
}

func TestClosedOriginalInputPreservesReadFailure(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "closed")
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	run, e := RunBatch(context.Background(), f, "explicit-only")
	if run.Usable || e == nil || e.Error() != "inspect-batch: read-failed" {
		t.Fatal("closed caller input code changed", run, e)
	}
}

func TestGoPipeReadFailurePreservesFixedCode(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	_ = w.CloseWithError(errors.New("PRIVATE"))
	run, e := RunBatch(context.Background(), r, "explicit-only")
	if run.Usable || e == nil || e.Error() != "inspect-batch: read-failed" {
		t.Fatal("bounded bridge changed read-failed code", run, e)
	}
}

func TestInheritedInputBoundAndDetectionByte(t *testing.T) {
	for _, extra := range []int{0, 1, 2} {
		f, e := os.CreateTemp(t.TempDir(), "original")
		if e != nil {
			t.Fatal(e)
		}
		data := fixture + strings.Repeat(" ", maxInput-len(fixture)+extra)
		_, _ = f.WriteString(data)
		_, _ = f.Seek(0, 0)
		run, e := RunBatch(context.Background(), f, "explicit-only")
		if extra == 0 {
			if e != nil || !run.Usable {
				t.Fatal("exact input limit", e)
			}
		} else if e == nil || e.Error() != "inspect-batch: limit-exceeded" {
			t.Fatal("missing detection byte limit", e)
		}
		pos, _ := f.Seek(0, io.SeekCurrent)
		f.Close()
		want := int64(maxInput)
		if extra > 0 {
			want++
		}
		if pos != want {
			t.Fatal("original input read beyond bounded allowance", pos, want)
		}
	}
}

func TestParserRejectsLaunchConfigBeforeOriginalRead(t *testing.T) {
	for _, mode := range []string{"nonce", "profile", "extra-field", "build", "extra-control"} {
		t.Run(mode, func(t *testing.T) {
			original, e := os.CreateTemp(t.TempDir(), "original")
			if e != nil {
				t.Fatal(e)
			}
			defer original.Close()
			_, _ = original.WriteString(fixture)
			_, _ = original.Seek(0, 0)
			cmd, e := childCommand(WorkerArgument)
			if e != nil {
				t.Fatal(e)
			}
			cap, release, e := configureLaunch(cmd, "parser", original)
			if e != nil {
				t.Fatal(e)
			}
			identity, e := buildIdentity()
			if e != nil {
				t.Fatal(e)
			}
			s := newRunState(context.Background())
			e = s.runChild(context.Background(), cmd, release, func(_ context.Context, c *channel, input io.Closer) error {
				var h hello
				if e := c.expect("hello", &h); e != nil {
					return e
				}
				build := identity
				if mode == "build" {
					build = "wrong"
				}
				if e := c.send("hello", hello{build}); e != nil {
					return e
				}
				cfg := config{cap, "explicit-only"}
				if mode == "nonce" {
					cfg.Nonce = "wrong"
				}
				if mode == "profile" {
					cfg.Profile = "wrong"
				}
				var payload any = cfg
				if mode == "extra-field" {
					payload = map[string]any{"nonce": cap, "profile": "explicit-only", "path": "PRIVATE"}
				}
				if e := c.send("config", payload); e != nil {
					return e
				}
				if mode == "extra-control" {
					_ = c.send("done", done{})
				}
				_ = input.Close()
				_, e := receiveResults(c, "explicit-only")
				return e
			})
			pos, _ := original.Seek(0, io.SeekCurrent)
			if e == nil || pos != 0 || cmd.ProcessState == nil {
				t.Fatal("original consumed before validated configuration", mode, e, pos)
			}
		})
	}
}

// Runtime interface assertion permits a behavioral RED on the old API rather
// than manufacturing a compiler failure.
func TestApprovedWriterAPI(t *testing.T) {
	run, e := RunBatch(context.Background(), bytes.NewBufferString(fixture), "explicit-only")
	if e != nil {
		t.Fatal(e)
	}
	w, ok := any(&run).(interface {
		WriteOutput(context.Context, io.Writer, []byte) error
	})
	if !ok {
		t.Fatal("approved sequential writer API missing")
	}
	var out bytes.Buffer
	if e = w.WriteOutput(context.Background(), &out, []byte("approved\n")); e != nil || out.String() != "approved\n" {
		t.Fatal(out.String(), e)
	}
}
