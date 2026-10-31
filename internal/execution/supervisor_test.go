package execution

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"packtrace/internal/demo"
	"packtrace/internal/inspect"
)

// All driver branches live only in the test executable. Production has no
// fixture flag, environment switch or caller-selected executable.
func testDriver(mode string) int {
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
		_ = c.send("hello", hello{"wrong"})
		time.Sleep(20 * time.Second)
		return 0
	}
	if mode == "duplicate-hello" {
		_, _ = io.WriteString(os.Stdout, `{"version":1,"version":1,"seq":1,"job":1,"type":"hello","data":{"build":"x"}}`+"\n")
		time.Sleep(20 * time.Second)
		return 0
	}
	if c.send("hello", hello{identity}) != nil {
		return 97
	}
	if mode == "blocked-config" {
		time.Sleep(20 * time.Second)
		return 0
	}
	var h hello
	var cfg config
	if c.expect("hello", &h) != nil {
		return 96
	}
	if mode == "exit-before-config" {
		return 7
	}
	if c.expect("config", &cfg) != nil {
		return 96
	}
	if _, e = c.receive(); e != io.EOF {
		return 95
	}
	if mode == "exit-zero" {
		return 0
	}
	if mode == "stderr-over" {
		_, _ = io.WriteString(os.Stderr, strings.Repeat("PRIVATE", maxStderr/7+1))
		time.Sleep(20 * time.Second)
		return 0
	}
	if mode == "stderr-exact" {
		_, _ = io.WriteString(os.Stderr, strings.Repeat("x", maxStderr))
	}
	if mode == "oversize" {
		_, _ = io.WriteString(os.Stdout, strings.Repeat("x", maxMessage+1))
		return 0
	}
	data, e := readInheritedInput(cfg)
	if e != nil {
		return 94
	}
	result, e := inspect.ReadBatchProfile(strings.NewReader(string(data)), cfg.Profile)
	if e != nil {
		return 93
	}
	if mode == "nested-policy" {
		result.Advisories[0].Report.Privacy = "PRIVATE"
	}
	if mode == "coverage-forgery" {
		result.Advisories[0].Report.Coverage[3].Outcome = "completed"
	}
	_ = c.send("start", start{result.LockedEntries, len(result.Advisories)})
	for i, a := range result.Advisories {
		var report *inspect.Result
		values := []demo.Candidate{}
		evaluations := 0
		if a.Report != nil {
			r := *a.Report
			values = r.Candidates
			r.Candidates = []demo.Candidate{}
			report = &r
			evaluations = len(r.Evaluations)
		}
		if mode == "wrong-reference" && i == 1 {
			i = 0
		}
		_ = c.send("advisory", advisory{i, a.State, report})
		if mode == "unclosed" && i == 1 {
			return 0
		}
		for _, v := range values {
			if mode == "cross-reference" {
				v.PackageIndex = 63
			}
			_ = c.send("candidate", candidate{i, v})
		}
		n := len(values)
		if mode == "bad-closure" {
			n++
		}
		_ = c.send("closure", closure{i, n, evaluations})
		if mode == "partial-crash" {
			return 7
		}
	}
	_ = c.send("done", done{len(result.Advisories), result.CandidateCount})
	switch mode {
	case "false-done-crash":
		return 7
	case "extra":
		_ = c.send("done", done{len(result.Advisories), result.CandidateCount})
	case "truncated":
		_, _ = io.WriteString(os.Stdout, `{"version":1`)
	case "done-hang":
		time.Sleep(20 * time.Second)
	case "reap-before-return":
		_ = os.Stdout.Close()
		time.Sleep(100 * time.Millisecond)
	}
	return 0
}
func runDriver(t *testing.T, mode string, in io.Reader, timeout time.Duration) (BatchRun, error, *exec.Cmd) {
	t.Helper()
	identity, e := buildIdentity()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.Command(os.Args[0], "--execution-test-driver", mode)
	cmd.Env = []string{}
	got, e := supervise(ctx, in, "explicit-only", cmd, identity)
	if cmd.ProcessState == nil {
		t.Fatal("returned before child reap")
	}
	if cmd.Process != nil {
		if killErr := cmd.Process.Kill(); killErr == nil {
			t.Fatal("child still alive after return")
		}
	}
	return got, e, cmd
}
func TestRealChildAbnormalCompletionCannotBecomeClean(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		usable bool
	}{
		{"partial-crash", true}, {"false-done-crash", true}, {"extra", true}, {"truncated", true}, {"unclosed", true}, {"wrong-reference", true},
		{"exit-zero", false}, {"cross-reference", false}, {"bad-closure", false}, {"nested-policy", false}, {"coverage-forgery", false}, {"oversize", false}, {"stderr-over", false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			got, e, _ := runDriver(t, tc.mode, strings.NewReader(fixture), 3*time.Second)
			if e == nil || got.Usable != tc.usable || got.Interrupted || strings.Contains(e.Error(), "PRIVATE") {
				t.Fatalf("abnormal accepted: %+v %v", got, e)
			}
			if got.Usable {
				if len(got.Result.Advisories) < 1 || got.Result.Coverage[0].Outcome != "incomplete" || got.Result.Coverage[len(got.Result.Coverage)-1].Check != "execution" || got.Result.ExitCode != 3 {
					t.Fatalf("partial falsely complete %+v", got)
				}
				if tc.mode == "unclosed" || tc.mode == "wrong-reference" || tc.mode == "partial-crash" {
					if len(got.Result.Advisories) != 1 {
						t.Fatal("unclosed work retained")
					}
				}
			}
		})
	}
}
func TestRealChildHandshakeBeforeInput(t *testing.T) {
	for _, mode := range []string{"wrong-build", "duplicate-hello", "no-hello"} {
		r, w := io.Pipe()
		defer r.Close()
		defer w.Close()
		got, e, _ := runDriver(t, mode, r, 150*time.Millisecond)
		if e == nil || got.Usable || got.Interrupted {
			t.Fatal(mode, got, e)
		}
	}
}
func TestDeadChildCancelsBlockedOriginalInput(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	before := time.Now()
	got, e, _ := runDriver(t, "exit-before-config", r, 3*time.Second)
	if e == nil || got.Usable || got.Interrupted || time.Since(before) > time.Second {
		t.Fatal("dead child left original input blocked", got, e, time.Since(before))
	}
}

func TestRealChildBackpressureCancelAndDoneRequiresEOF(t *testing.T) {
	for _, mode := range []string{"blocked-config", "done-hang"} {
		before := time.Now()
		got, e, _ := runDriver(t, mode, strings.NewReader(fixture), 150*time.Millisecond)
		if time.Since(before) > 3*time.Second || e == nil || got.Interrupted {
			t.Fatalf("unbounded cancel %s %+v %v", mode, got, e)
		}
		if mode == "done-hang" && (!got.Usable || got.Result.Coverage[0].Outcome != "incomplete") {
			t.Fatal("done without EOF qualified", got)
		}
	}
}
func TestRealChildReturnWaitsForReap(t *testing.T) {
	before := time.Now()
	got, e, _ := runDriver(t, "reap-before-return", strings.NewReader(fixture), 3*time.Second)
	if e != nil || !got.Usable || time.Since(before) < 100*time.Millisecond {
		t.Fatal("returned before child exit", got, e)
	}
}

func TestRealChildExactStderrCapDoesNotLeak(t *testing.T) {
	got, e, _ := runDriver(t, "stderr-exact", strings.NewReader(fixture), 3*time.Second)
	if e != nil || !got.Usable || got.Interrupted {
		t.Fatal(got, e)
	}
}
