package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPrivateLifetimeInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--private-lifetime-fd"}, {"scan", "--private-lifetime-fd=2"},
		{"scan", "--private-lifetime-fd=03"}, {"scan", "--private-lifetime-fd=999999"},
		{"scan", "--private-lifetime-fd=3", "--private-lifetime-fd=4"},
		{"intel", "status", "--private-lifetime-fd=3"},
	} {
		var out, diag bytes.Buffer
		if code := runMain(args, forbiddenReader{}, &out, &diag); code != 2 || out.Len() != 0 {
			t.Fatalf("%v: %d %s", args, code, out.String())
		}
	}
}
func TestPrivateLifetimeStdioAlias(t *testing.T) {
	_, w := privatePipe(t)
	saved, e := syscall.Dup(1)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(saved)
	if e = syscall.Dup2(int(w.Fd()), 1); e != nil {
		t.Fatal(e)
	}
	accepted := validLifetimeFD(int(w.Fd()))
	if e = syscall.Dup2(saved, 1); e != nil {
		t.Fatal(e)
	}
	if accepted {
		t.Fatal("stdio alias accepted")
	}
}
func TestPrivateLifetimeCLIFailures(t *testing.T) {
	for _, mode := range []string{"broken", "blocked", "writer", "cancel", "partial"} {
		t.Run(mode, func(t *testing.T) {
			root, policy := scanFixture(t)
			if mode == "cancel" {
				for i := 0; i < 400; i++ {
					if e := os.WriteFile(filepath.Join(root, "node_modules/PRIVATE-pkg", fmt.Sprintf("extra-%03d", i)), nil, 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			r, w := privatePipe(t)
			args := []string{"-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--private-lifetime-fd=3", "--policy", policy, "--checks", "integrity", "--format", "json", root}
			if mode == "partial" {
				args[len(args)-1] = root + "/absent"
			}
			cmd := exec.Command(os.Args[0], args...)
			cmd.ExtraFiles = []*os.File{w}
			var out, diag bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &diag
			if mode == "broken" {
				r.Close()
			}
			if mode == "blocked" {
				for {
					_, e := syscall.Write(int(w.Fd()), make([]byte, 4096))
					if e == syscall.EAGAIN {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			if mode == "writer" {
				pr, pw, e := os.Pipe()
				if e != nil {
					t.Fatal(e)
				}
				pr.Close()
				defer pw.Close()
				cmd.Stdout = pw
			}
			if mode == "broken" || mode == "blocked" {
				// Transport failure must not perform unbounded post-Finish
				// diagnostic I/O to an independently blocked inherited stderr.
				_, blockedStderr := privatePipe(t)
				for {
					_, e := syscall.Write(int(blockedStderr.Fd()), make([]byte, 4096))
					if e == syscall.EAGAIN {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
				}
				if e := syscall.SetNonblock(int(blockedStderr.Fd()), false); e != nil {
					t.Fatal(e)
				}
				cmd.Stderr = blockedStderr
			}
			var publicRead, publicWrite *os.File
			if mode == "cancel" {
				var e error
				publicRead, publicWrite, e = os.Pipe()
				if e != nil {
					t.Fatal(e)
				}
				defer publicRead.Close()
				defer publicWrite.Close()
				cmd.Stdout = publicWrite
			}
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			w.Close()
			if mode == "cancel" {
				publicWrite.Close()
				_ = publicRead.SetReadDeadline(time.Now().Add(5 * time.Second))
				var first [1]byte
				if _, e := io.ReadFull(publicRead, first[:]); e != nil {
					cmd.Process.Kill()
					cmd.Wait()
					t.Fatal(e)
				}
				_ = cmd.Process.Signal(os.Interrupt)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				cmd.Process.Kill()
				<-done
				t.Fatal("unbounded transport")
			}
			want := 2
			if mode == "cancel" {
				want = 130
			}
			if cmd.ProcessState.ExitCode() != want {
				t.Fatalf("%s exit %v: %s", mode, cmd.ProcessState, diag.String())
			}
			if mode == "writer" || mode == "cancel" || mode == "partial" {
				var record lifetimeRecord
				if e := json.NewDecoder(r).Decode(&record); e != nil {
					t.Fatal(e)
				}
				if record.Exit != want {
					t.Fatal(record)
				}
				if mode == "writer" && (record.Fault[2] != "scan-writer" || record.Fault[0] != "exchange" && record.Fault[0] != "wait-exit") {
					t.Fatal(fmt.Sprint(record.Fault))
				}
				if mode == "partial" && (len(record.Roles) != 2 || record.Roles[0].Role != "scan" || record.Roles[1].Role != "scan-writer" || record.Fault[0] == "") {
					t.Fatal("lost partial admission/fault", record)
				}
			}
		})
	}
}
