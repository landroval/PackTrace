package execution

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

// These tests execute the actual platform constructor and common deadline guard.
// On Windows they are native contracts; cross-compilation does not run them.
func TestPrivatePipeTransferAndEOF(t *testing.T) {
	r, w, err := privatePipe()
	if err != nil {
		t.Fatal("required cancelable private pipe unavailable", err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	if err := r.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := w.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("private-byte-channel\x00\xff"), 8192)
	written := make(chan error, 1)
	go func() {
		_, err := w.Write(want)
		if closeErr := w.Close(); err == nil {
			err = closeErr
		}
		written <- err
	}()
	got, readErr := io.ReadAll(r)
	writeErr := <-written
	if readErr != nil || writeErr != nil || !bytes.Equal(got, want) {
		t.Fatalf("private transfer/EOF: read=%v write=%v bytes=%d", readErr, writeErr, len(got))
	}
}

func TestPrivatePipeReadDeadlineAndReuse(t *testing.T) {
	r, w, err := privatePipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	if err := r.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := r.Read(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read not canceled by deadline", err)
	}
	if err := r.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := w.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(r, b[:]); err != nil || b[0] != 42 {
		t.Fatal("read failed after canceled operation joined", b, err)
	}
}

func TestPrivatePipeBlockedWriteDeadline(t *testing.T) {
	r, w, err := privatePipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	if err := w.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// Larger than either platform's private-pipe buffer; no reader drains it.
	if _, err := w.Write(make([]byte, 2<<20)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("backpressured write not canceled by deadline", err)
	}
}

func TestPrivatePipeCloseJoinsBlockedIO(t *testing.T) {
	for _, mode := range []string{"read", "write"} {
		t.Run(mode, func(t *testing.T) {
			r, w, err := privatePipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { r.Close(); w.Close() })
			if err := r.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := w.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			started, done := make(chan struct{}), make(chan error, 1)
			end := r
			if mode == "write" {
				end = w
			}
			go func() {
				close(started)
				var err error
				if mode == "read" {
					_, err = r.Read(make([]byte, 1))
				} else {
					_, err = w.Write(make([]byte, 2<<20))
				}
				done <- err
			}()
			<-started
			// Give I/O a chance to pend; the close-before-submit race is also safe.
			time.Sleep(20 * time.Millisecond)
			if err := end.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, os.ErrClosed) {
				t.Fatal("close did not cancel/join private I/O", err)
			}
		})
	}
}

func TestPrivatePipesAreIsolated(t *testing.T) {
	r1, w1, err := privatePipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r1.Close(); w1.Close() })
	r2, w2, err := privatePipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r2.Close(); w2.Close() })
	for _, r := range []*os.File{r1, r2} {
		if err := r.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	for i, w := range []*os.File{w1, w2} {
		if err := w.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte{byte(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	for i, r := range []*os.File{r1, r2} {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil || b[0] != byte(i+1) {
			t.Fatal("private pipes crossed", b, err)
		}
	}
}
