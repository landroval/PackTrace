//go:build linux

package execution

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"packtrace/internal/cli"
)

func TestIntelProgressObservesBothChildrenAndKeepsParserPrivate(t *testing.T) {
	for _, mode := range []string{"complete", "cancel", "blocked", "closed", "budget"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s := newIntelRunState(ctx)
			s.scan = newScanLifecycle(ctx, s.deadline)
			s.scan.allowProgress = true
			run := IntelRun{lifecycle: ScanRun{output: BatchRun{state: s}}}
			file, e := os.Create(filepath.Join(t.TempDir(), "progress"))
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			var reader *os.File
			if mode == "blocked" || mode == "closed" {
				var err error
				reader, file, err = os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				defer reader.Close()
				if mode == "closed" {
					reader.Close()
				} else {
					conn, err := file.SyscallConn()
					if err != nil {
						t.Fatal(err)
					}
					var capacity uintptr
					if err := conn.Control(func(fd uintptr) { capacity, _, _ = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETPIPE_SZ, 0) }); err != nil || capacity > 1<<20 {
						t.Fatal("owned pipe capacity", err, capacity)
					}
					if _, err := file.Write(make([]byte, int(capacity))); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mode == "cancel" || mode == "blocked" {
				timer := time.AfterFunc(650*time.Millisecond, cancel)
				defer timer.Stop()
			}
			if mode == "budget" {
				s.budget.n = maxTraffic - maxProgressBytes
			}
			cmd := exec.Command(os.Args[0], "--intel-fault-driver", "progress-wait")
			identity, e := buildIdentity()
			if e != nil {
				t.Fatal(e)
			}
			req := cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelSync, Format: "terminal", StateDir: filepath.Join(t.TempDir(), "NEVER-OPEN-PRIVATE")}
			started := time.Now()
			failure := run.superviseIntel(ctx, req, cmd, identity, file)
			receipt, finish := run.Finish()
			if !receipt.CleanupConfirmed || !receipt.Finished || time.Since(started) > 4*time.Second {
				t.Fatal("cleanup/deadline", failure, finish, receipt)
			}
			for _, role := range receipt.Roles {
				if !role.Reaped || !role.WaitReturned || !role.ExchangeJoined || !role.StderrJoined || role.Samples == 0 {
					t.Fatal("unobserved or unreaped role", role)
				}
			}
			if mode == "complete" {
				if failure != nil || finish != nil || !run.Usable || len(receipt.Roles) != 2 || receipt.ConcurrentSamples < 2 {
					t.Fatal("paired observation", failure, finish, receipt)
				}
				raw, e := os.ReadFile(file.Name())
				if e != nil {
					t.Fatal(e)
				}
				if bytes.Count(raw, []byte("Syncing security advisory database")) < 2 || !bytes.HasSuffix(raw, []byte("\r\x1b[K")) || bytes.Contains(raw, []byte("PRIVATE")) || bytes.Contains(raw, []byte("%")) {
					t.Fatal("not a fixed animated/cleared display", string(raw))
				}
				if receipt.Roles[0].Role != "intel" || receipt.Roles[1].Role != "intel-progress" {
					t.Fatal(receipt)
				}
			} else if failure == nil || run.Usable {
				t.Fatal("failed/cancelled progress granted success", mode, failure, receipt)
			}
			if mode == "budget" && len(receipt.Roles) != 1 {
				t.Fatal("over-budget spinner launched", receipt)
			}
		})
	}
}

func TestIntelProgressRefusesMachineFormatBeforeStoreIO(t *testing.T) {
	out, e := os.Create(filepath.Join(t.TempDir(), "progress"))
	if e != nil {
		t.Fatal(e)
	}
	defer out.Close()
	state := filepath.Join(t.TempDir(), "absent")
	run, e := RunIntelWithProgress(context.Background(), cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelSync, Format: "json", StateDir: state}, out)
	defer run.Finish()
	if e == nil || run.Usable {
		t.Fatal("machine progress accepted")
	}
	if _, e := os.Stat(state); !os.IsNotExist(e) {
		t.Fatal("state initialized")
	}
}
