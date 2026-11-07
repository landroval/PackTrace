//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestScanTargetBackedStateRejectedBeforeContentOpen(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(map[bool]string{false: "inside", true: "aliased"}[alias], func(t *testing.T) {
			target, policy := scanFixture(t)
			state := filepath.Join(target, "state")
			if alias {
				state = filepath.Join(t.TempDir(), "state-alias")
				if e := os.Symlink(target, state); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := os.Mkdir(state, 0700); e != nil {
					t.Fatal(e)
				}
			}
			fd, e := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
			if e != nil {
				t.Fatal(e)
			}
			defer syscall.Close(fd)
			canary := filepath.Join(target, "package-lock.json")
			if _, e := syscall.InotifyAddWatch(fd, canary, syscall.IN_OPEN|syscall.IN_ACCESS); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--checks", "integrity", "--state-dir", state, "--format", "json", target)
			var out, diag bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &diag
			e = cmd.Run()
			if e == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 2 {
				t.Fatal("target-backed state admitted", e, cmd.ProcessState, out.String(), diag.String())
			}
			var events [4096]byte
			n, e := syscall.Read(fd, events[:])
			if n > 0 || e != syscall.EAGAIN {
				t.Fatal("state rejection followed target content admission", n, e)
			}
			f, e := os.Open(canary)
			if e != nil {
				t.Fatal(e)
			}
			var b [1]byte
			f.Read(b[:])
			f.Close()
			if n, e := syscall.Read(fd, events[:]); e != nil || n <= 0 {
				t.Fatal("native content-open canary had no positive control", n, e)
			}
		})
	}
}
