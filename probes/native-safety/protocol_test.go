package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestCapabilityWorker(t *testing.T) {
	if os.Getenv("PROBE_CAP_WORKER") == "" {
		return
	}
	key, err := inheritedToken()
	if err != nil {
		os.Stdout.Write([]byte("rejected"))
	} else if key == (token{7}) {
		os.Stdout.Write([]byte("accepted"))
	} else {
		os.Stdout.Write([]byte("wrong-token"))
	}
	os.Exit(0)
}
func TestInheritedCapability(t *testing.T) {
	for _, mode := range []string{"valid", "short", "extra", "zero", "regular", "directory", "absent", "openpipe", "partialopen"} {
		key := make([]byte, 32)
		key[0] = 7
		if mode == "short" || mode == "partialopen" {
			key = key[:31]
		}
		if mode == "extra" {
			key = append(key, 1)
		}
		if mode == "zero" {
			key[0] = 0
		}
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		w.Write(key)
		if mode != "openpipe" && mode != "partialopen" {
			w.Close()
		}
		dir, err := os.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCapabilityWorker$")
		cmd.Env = append(os.Environ(), "PROBE_CAP_WORKER=1")
		cmd.ExtraFiles = []*os.File{dir, dir, r}
		regularFile, err := os.CreateTemp(t.TempDir(), "cap-rejection")
		if err != nil {
			t.Fatal(err)
		}
		if mode == "regular" {
			cmd.ExtraFiles[2] = regularFile
		}
		if mode == "directory" {
			cmd.ExtraFiles[2] = dir
		}
		if mode == "absent" {
			cmd.ExtraFiles = nil
		}
		got, err := cmd.Output()
		cancel()
		w.Close()
		regularFile.Close()
		r.Close()
		dir.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := "rejected"
		if mode == "valid" {
			want = "accepted"
		}
		if string(got) != want {
			t.Errorf("%s: %q", mode, got)
		}
	}
}
func TestFrames(t *testing.T) {
	key := token{1, 2, 3}
	f := frame{Op: opResult, ID: 5, Observation: regularObservation()}
	var b bytes.Buffer
	if err := writeFrame(&b, key, f); err != nil {
		t.Fatal(err)
	}
	if b.Len() != 512 {
		t.Fatalf("frame size=%d", b.Len())
	}
	raw := append([]byte(nil), b.Bytes()...)
	got, err := readFrame(bytes.NewReader(raw), key, opResult, 5)
	if err != nil || got != f {
		t.Fatalf("roundtrip %v", err)
	}
	for _, kind := range []string{"token", "op", "case", "padding", "short"} {
		bad := append([]byte(nil), raw...)
		switch kind {
		case "token":
			bad[0] ^= 1
		case "op":
			bad[32] = opReady
		case "case":
			bad[33] = 4
		case "padding":
			bad[511] = 1
		case "short":
			bad = bad[:511]
		}
		if _, err := readFrame(bytes.NewReader(bad), key, opResult, 5); err == nil {
			t.Errorf("accepted %s", kind)
		}
	}
	if writeFrame(io.Discard, key, frame{Op: 99, ID: 1}) == nil {
		t.Fatal("unknown operation admitted")
	}
	if writeFrame(io.Discard, key, frame{Op: 1, ID: 0}) == nil {
		t.Fatal("unknown case admitted")
	}
}

// Inert test subprocesses exercise real pipes, output limits, signals and Wait.
// They never execute the Darwin adapter or investigate a source.
func TestControlledWorker(t *testing.T) {
	mode := os.Getenv("PROBE_TEST_WORKER")
	if mode == "" {
		return
	}
	switch mode {
	case "echo":
		b := make([]byte, 4)
		io.ReadFull(os.Stdin, b)
		os.Stdout.Write(b)
	case "exit":
		os.Exit(7)
	case "flood":
		os.Stderr.Write(bytes.Repeat([]byte("e"), 70000))
		os.Stdout.Write([]byte("okay"))
	case "hang":
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}
func workerCommand(mode string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestControlledWorker$")
	cmd.Env = append(os.Environ(), "PROBE_TEST_WORKER="+mode)
	return cmd
}
func TestSession(t *testing.T) {
	echo := func(r io.Reader, w io.Writer) error {
		if _, err := w.Write([]byte("okay")); err != nil {
			return err
		}
		b := make([]byte, 4)
		_, err := io.ReadFull(r, b)
		if err == nil && string(b) != "okay" {
			return errors.New("bad echo")
		}
		return err
	}
	r := childSession(workerCommand("echo"), echo, time.Second)
	if r.Err != nil || !r.Reaped || r.TimedOut {
		t.Fatalf("echo: %+v", r)
	}
	r = childSession(workerCommand("flood"), echo, time.Second)
	if r.Err == nil || !r.Reaped || r.StderrBytes != 65536 {
		t.Fatalf("stderr overflow not failed/bounded: %+v", r)
	}
	for _, mode := range []string{"hang", "exit"} {
		start := time.Now()
		r := childSession(workerCommand(mode), echo, 400*time.Millisecond)
		if r.Err == nil || !r.Reaped || time.Since(start) > 2*time.Second {
			t.Fatalf("%s: %+v", mode, r)
		}
		if mode == "hang" && !r.TimedOut {
			t.Fatal("timeout unreported")
		}
	}
	r = childSession(workerCommand("exit"), func(io.Reader, io.Writer) error { return nil }, time.Second)
	if r.Err == nil || !r.Reaped {
		t.Fatalf("nonzero exit after completed IO lost %+v", r)
	}
	r = childSession(workerCommand("hang"), func(io.Reader, io.Writer) error { return errors.New("bad frame") }, time.Second)
	if r.Err == nil || !r.Reaped {
		t.Fatalf("protocol error lost %+v", r)
	}
	r = childSession(exec.Command("/nonexistent/owned-probe-worker"), echo, time.Second)
	if r.Err == nil || !r.Reaped {
		t.Fatalf("start failure lost %+v", r)
	}
}
