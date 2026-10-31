package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func inheritedToken() (token, error) {
	var key token
	var st syscall.Stat_t
	if err := syscall.Fstat(5, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return key, errors.New("missing-capability-pipe")
	}
	// exec obtains File.Fd(), which restores blocking mode. NewFile on an
	// inherited blocking pipe cannot SetReadDeadline. Re-enable nonblocking
	// BEFORE wrapping so the runtime can enforce this fixed capability read.
	if err := syscall.SetNonblock(5, true); err != nil {
		return key, err
	}
	f := os.NewFile(5, "capability")
	if f == nil {
		return key, errors.New("missing-capability-pipe")
	}
	defer f.Close()
	if err := f.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return key, err
	}
	if _, err := io.ReadFull(f, key[:]); err != nil {
		return token{}, err
	}
	if key == (token{}) {
		return key, errors.New("zero-capability")
	}
	var extra [1]byte
	if n, err := f.Read(extra[:]); n != 0 || err != io.EOF {
		return token{}, errors.New("capability-size")
	}
	return key, nil
}

type token [32]byte
type frame struct {
	Op, ID      byte
	Observation Observation
}

const (
	opBegin   byte = 1
	opReady   byte = 2
	opClone   byte = 3
	opCloned  byte = 4
	opInspect byte = 5
	opResult  byte = 6
)

func writeFrame(w io.Writer, key token, f frame) error {
	if f.Op < opBegin || f.Op > opResult || f.ID < 1 || f.ID > 5 {
		return errors.New("invalid-frame")
	}
	var b bytes.Buffer
	b.Write(key[:])
	b.WriteByte(f.Op)
	b.WriteByte(f.ID)
	if err := binary.Write(&b, binary.LittleEndian, f.Observation); err != nil {
		return err
	}
	b.Write(make([]byte, 512-b.Len()))
	n, err := w.Write(b.Bytes())
	if err == nil && n != 512 {
		return io.ErrShortWrite
	}
	return err
}
func readFrame(r io.Reader, key token, op, id byte) (frame, error) {
	var b [512]byte
	var f frame
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return f, err
	}
	if subtle.ConstantTimeCompare(key[:], b[:32]) != 1 || b[32] != op || b[33] != id || op < opBegin || op > opResult || id < 1 || id > 5 {
		return f, errors.New("invalid-frame")
	}
	f.Op = op
	f.ID = id
	n := binary.Size(f.Observation)
	if err := binary.Read(bytes.NewReader(b[34:34+n]), binary.LittleEndian, &f.Observation); err != nil {
		return frame{}, err
	}
	for _, v := range b[34+n:] {
		if v != 0 {
			return frame{}, errors.New("invalid-padding")
		}
	}
	return f, nil
}

type sessionResult struct {
	Err         error
	Reaped      bool
	TimedOut    bool
	StderrBytes int
}
type cappedStderr struct {
	mu       sync.Mutex
	n        int
	overflow bool
}

func (w *cappedStderr) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	if n > 65536-w.n {
		n = 65536 - w.n
		w.overflow = true
	}
	w.n += n
	if n != len(p) {
		return n, errors.New("stderr-budget")
	}
	return n, nil
}

// Only the fixed self executable is supplied by the native harness. Tests use
// inert controlled workers. File-backed stdin/stdout avoid exec pipe-copy waits.
func childSession(cmd *exec.Cmd, interact func(io.Reader, io.Writer) error, budget time.Duration) sessionResult {
	result := sessionResult{Reaped: true}
	inR, inW, err := os.Pipe()
	if err != nil {
		result.Err = err
		return result
	}
	defer inR.Close()
	defer inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		result.Err = err
		return result
	}
	defer outR.Close()
	defer outW.Close()
	diagnostics := &cappedStderr{}
	cmd.Stdin = inR
	cmd.Stdout = outW
	cmd.Stderr = diagnostics
	cmd.WaitDelay = 100 * time.Millisecond
	start := time.Now()
	if err = cmd.Start(); err != nil {
		result.Err = err
		return result
	}
	result.Reaped = false
	inR.Close()
	outW.Close()
	reserve := budget / 2
	if reserve > 2*time.Second {
		reserve = 2 * time.Second
	}
	var timedOut atomic.Bool
	timer := time.AfterFunc(budget-reserve, func() { timedOut.Store(true); cmd.Process.Kill(); inW.Close(); outR.Close() })
	err = interact(outR, inW)
	inW.Close()
	if err != nil {
		cmd.Process.Kill()
		outR.Close()
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	left := time.Until(start.Add(budget))
	if left < 0 {
		left = 0
	}
	select {
	case waitErr := <-waited:
		result.Reaped = true
		if err == nil {
			err = waitErr
		}
	case <-time.After(left):
		cmd.Process.Kill()
		outR.Close()
		err = errors.New("unreaped-worker")
	}
	timer.Stop()
	result.TimedOut = timedOut.Load()
	if result.TimedOut {
		err = errors.New("worker-timeout")
	}
	diagnostics.mu.Lock()
	result.StderrBytes = diagnostics.n
	if diagnostics.overflow {
		err = errors.New("stderr-budget")
	}
	diagnostics.mu.Unlock()
	result.Err = err
	return result
}
