package execution

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/inspect"
)

const fixture = `{"lockfile":{"lockfileVersion":3,"packages":{"":{},"node_modules/owned":{"name":"owned","version":"1.2.3"}}},"advisories":[{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"owned"},"versions":["1.2.3"]}]},42]}`

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--owned-worker-environment-facts" {
		os.Exit(writeOwnedEnvironmentFacts())
	}
	if len(os.Args) == 3 && os.Args[1] == "--scan-fault-driver" {
		mode := os.Args[2]
		os.Args = []string{os.Args[0], ScanWorkerArgument}
		os.Exit(scanFaultDriver(mode))
	}
	if len(os.Args) == 3 && os.Args[1] == "--writer-test-driver" {
		mode := os.Args[2]
		os.Args = os.Args[:2]
		os.Args[1] = WriterArgument
		if mode == "stderr-one" {
			_, _ = io.WriteString(os.Stderr, "X")
		}
		os.Exit(WriterMain(os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) == 3 && os.Args[1] == "--review-driver" {
		mode := os.Args[2]
		os.Args = os.Args[:2]
		os.Args[1] = WorkerArgument
		os.Exit(reviewDriver(mode))
	}
	if len(os.Args) == 3 && os.Args[1] == "--execution-test-driver" {
		mode := os.Args[2]
		os.Args = os.Args[:2]
		os.Args[1] = WorkerArgument
		os.Exit(testDriver(mode))
	}
	if len(os.Args) == 2 && os.Args[1] == WriterArgument {
		os.Exit(WriterMain(os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) == 2 && os.Args[1] == WorkerArgument {
		// Test-only assertion at the actual child boundary, not a production hook.
		for _, v := range os.Environ() {
			if !ownedWorkerEnvironmentAllowed(v, runtime.GOOS, runtime.GOARCH) {
				os.Exit(96)
			}
		}
		os.Exit(WorkerMain(os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// A direct-read fallback, stub, or decoder-only implementation fails this check.
func TestRealChildMatchesExistingBatch(t *testing.T) {
	for _, profile := range []string{"explicit-only", "npm-lock-v2-v3"} {
		want, err := inspect.ReadBatchProfile(strings.NewReader(fixture), profile)
		if err != nil {
			t.Fatal(err)
		}
		got, err := RunBatch(context.Background(), strings.NewReader(fixture), profile)
		if err != nil || !got.Usable || got.Interrupted || !reflect.DeepEqual(got.Result, want) {
			t.Fatalf("real supervised result differs: %+v %v", got, err)
		}
	}
}
func TestSharedStderrActualSequentialChildren(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := newRunState(ctx)
	identity, e := buildIdentity()
	if e != nil {
		t.Fatal(e)
	}
	parser := exec.Command(os.Args[0], "--execution-test-driver", "stderr-exact")
	run, e := superviseState(ctx, strings.NewReader(fixture), "explicit-only", parser, identity, s)
	if e != nil || !run.Usable || parser.ProcessState == nil {
		t.Fatal("parser control", e)
	}
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
	writer := exec.Command(os.Args[0], "--writer-test-driver", "stderr-one")
	_, release, e := configureLaunch(writer, "writer", public, raw)
	if e != nil {
		t.Fatal(e)
	}
	e = s.runChild(ctx, writer, release, func(_ context.Context, c *channel, _ io.Closer) error {
		var h hello
		_ = c.expect("hello", &h)
		return errProtocol
	})
	if !errors.Is(e, errLimit) || writer.ProcessState == nil {
		t.Fatal("stderr allowance reset across roles", e)
	}
}

func TestWorkerReducedEnvironment(t *testing.T) {
	t.Setenv("PACKTRACE_OWNED_TEST_SECRET", "PRIVATE")
	t.Setenv("HTTP_PROXY", "PRIVATE")
	got, e := RunBatch(context.Background(), strings.NewReader(fixture), "explicit-only")
	if e != nil || !got.Usable {
		t.Fatal("worker inherited parent environment", e)
	}
}

func TestFatalCodesAndPrivacy(t *testing.T) {
	for _, tc := range []struct{ in, profile, code string }{
		{fixture, "PRIVATE", "inspect-batch: invalid-profile"},
		{"PRIVATE", "explicit-only", "inspect-batch: invalid-input"},
		{strings.Repeat("x", 1048577), "explicit-only", "inspect-batch: limit-exceeded"},
	} {
		got, err := RunBatch(context.Background(), strings.NewReader(tc.in), tc.profile)
		if err == nil || err.Error() != tc.code || got.Usable {
			t.Fatalf("fatal: %+v %v want %s", got, err, tc.code)
		}
	}
}
func TestCancelBlockedInputReaps(t *testing.T) {
	in, out := io.Pipe()
	defer out.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var got BatchRun
	var err error
	go func() { got, err = RunBatch(ctx, in, "explicit-only"); close(done) }()
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("blocked cancellation")
	}
	if !got.Interrupted || err == nil || got.Usable {
		t.Fatalf("cancel: %+v %v", got, err)
	}
}
func TestPrecancelNeverReads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := RunBatch(ctx, panicReader{}, "explicit-only")
	if err == nil || !got.Interrupted {
		t.Fatalf("pre-cancel: %+v %v", got, err)
	}
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("input released early") }
func TestReadFailure(t *testing.T) {
	got, err := RunBatch(context.Background(), errorReader{}, "explicit-only")
	if got.Usable || err == nil || err.Error() != "inspect-batch: read-failed" {
		t.Fatalf("read failure %+v %v", got, err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE") }

func TestOversizeSemanticRecordProducesControlledLimitGap(t *testing.T) {
	bad := `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"owned"},"versions":[` + strings.TrimSuffix(strings.Repeat(`"INVALID",`, 20000), ",") + `]}]}`
	input := strings.TrimSuffix(fixture, `42]}`) + bad + `]}`
	got, e := RunBatch(context.Background(), strings.NewReader(input), "explicit-only")
	if e == nil || e.Error() != errLimit.Error() || !got.Usable || len(got.Result.Advisories) != 1 || got.Result.CandidateCount != 1 || got.Result.Coverage[0].Outcome != "incomplete" {
		t.Fatalf("semantic limit not controlled: %+v %v", got, e)
	}
}

func TestWorkerRejectsInvalidHandshakeWithoutInput(t *testing.T) {
	var out, diag bytes.Buffer
	code := WorkerMain(strings.NewReader("{\"PRIVATE\":true}\n"), &out, &diag)
	if code == 0 || strings.Contains(out.String()+diag.String(), "PRIVATE") {
		t.Fatalf("unsafe worker response %d %q %q", code, out.String(), diag.String())
	}
}
