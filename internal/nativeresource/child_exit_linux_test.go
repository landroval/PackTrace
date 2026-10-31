//go:build linux && (amd64 || arm64)

package nativeresource

import (
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Linux may detach the exiting leader's mm before the retained pidfd reports
// whole-process exit. A real ESRCH in that interval is not a live RSS sample.
func TestSampleDuringOwnedChildExitDoesNotInventLiveQueryFailure(t *testing.T) {
	for attempt := 0; attempt < 8; attempt++ {
		func() {
			input, feed, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer feed.Close()
			read, output, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			defer output.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedResidentChildEntry$")
			cmd.Env = append(os.Environ(), "PACKTRACE_TEST_RSS_CHILD=1", "GORACE=atexit_sleep_ms=0")
			cmd.Stdin, cmd.Stdout = input, output
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			child, err := PinChild(cmd.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			_ = read.SetReadDeadline(time.Now().Add(3 * time.Second))
			var ready [1]byte
			if _, err = io.ReadFull(read, ready[:]); err != nil || ready[0] != 'R' {
				t.Fatal(err, ready)
			}
			if _, err = feed.Write([]byte{'A'}); err != nil {
				t.Fatal(err)
			}
			if _, err = io.ReadFull(read, ready[:]); err != nil || ready[0] != 'A' {
				t.Fatal(err, ready)
			}
			if n, live, err := child.Sample(); err != nil || !live || n == 0 {
				t.Fatal("live positive", n, live, err)
			}
			_ = feed.Close()
			ended := false
			deadline := time.Now().Add(2 * time.Second)
			for queries := 0; queries < 1000 && time.Now().Before(deadline); queries++ {
				n, live, err := child.Sample()
				if err != nil {
					t.Fatalf("normal exit misclassified as live query failure: attempt=%d rss=%d live=%v detail=%#v", attempt, n, live, err)
				}
				if !live {
					ended = true
					break
				}
			}
			if !ended {
				t.Fatal("bounded retained exit not observed")
			}
			if err = cmd.Wait(); err != nil {
				t.Fatal(err)
			}
			waited = true
		}()
	}
}
