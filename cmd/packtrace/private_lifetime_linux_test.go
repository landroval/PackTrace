package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"packtrace/internal/execution"
)

func privatePipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	var pair [2]int
	if e := syscall.Pipe(pair[:]); e != nil {
		t.Fatal(e)
	}
	r, w := os.NewFile(uintptr(pair[0]), "read"), os.NewFile(uintptr(pair[1]), "write")
	t.Cleanup(func() { r.Close(); w.Close() })
	if e := syscall.SetNonblock(int(w.Fd()), true); e != nil {
		t.Fatal(e)
	}
	return r, w
}
func TestPrivateLifetimeEndpoint(t *testing.T) {
	r, w := privatePipe(t)
	if !validLifetimeFD(int(w.Fd())) {
		t.Fatal("anonymous nonblocking writer rejected")
	}
	if validLifetimeFD(int(r.Fd())) || validLifetimeFD(1) || validLifetimeFD(-1) {
		t.Fatal("invalid endpoint accepted")
	}
	f, e := os.CreateTemp(t.TempDir(), "regular")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if validLifetimeFD(int(f.Fd())) {
		t.Fatal("regular file accepted")
	}
	pair, e := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(pair[0])
	defer syscall.Close(pair[1])
	if validLifetimeFD(pair[0]) {
		t.Fatal("socket accepted")
	}
	fifo := t.TempDir() + "/fifo"
	if e = syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	fd, e := syscall.Open(fifo, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(fd)
	if validLifetimeFD(fd) {
		t.Fatal("named FIFO accepted")
	}
	if e = syscall.SetNonblock(int(w.Fd()), false); e != nil {
		t.Fatal(e)
	}
	if validLifetimeFD(int(w.Fd())) {
		t.Fatal("blocking pipe accepted")
	}
}
func TestPrivateLifetimeRecord(t *testing.T) {
	receipt := execution.ScanReceipt{Finished: true, CleanupConfirmed: true, Roles: []execution.ScanRoleReceipt{{Role: "scan", PID: 987654, WaitPeakResidentBytes: 1024}}, FirstFault: execution.ScanFault{Stage: "PRIVATE/path", Code: "PRIVATE/package", Role: "PRIVATE"}}
	b, e := lifetimeBytes(receipt, 3)
	if e != nil || len(b) > 4096 || bytes.Contains(b, []byte("PRIVATE")) || bytes.Contains(b, []byte("987654")) {
		t.Fatalf("unsafe record: %s %v", b, e)
	}
	var record lifetimeRecord
	if e = json.Unmarshal(b, &record); e != nil || record.Exit != 3 {
		t.Fatal(e)
	}
	receipt.Roles[0].Role = "PRIVATE"
	if _, e = lifetimeBytes(receipt, 3); e == nil {
		t.Fatal("unknown role accepted")
	}
	receipt.Roles = make([]execution.ScanRoleReceipt, 17)
	if _, e = lifetimeBytes(receipt, 3); e == nil {
		t.Fatal("excess roles accepted")
	}
	receipt.Roles = nil
	if _, e = lifetimeBytes(receipt, 99); e == nil {
		t.Fatal("invalid exit accepted")
	}
	receipt.Resources.SupervisorSamples = -1
	if _, e = lifetimeBytes(receipt, 3); e == nil {
		t.Fatal("negative counter accepted")
	}
	receipt.Resources.SupervisorSamples = 1
	receipt.FirstFault = execution.ScanFault{Stage: "intelligence-close", Code: "operation-failed"}
	receipt.Finalization.Status = "missing"
	b, e = lifetimeBytes(receipt, 2)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &record); e != nil || record.Fault[0] != "intelligence-close" || record.Final != "missing" || record.Exit != 2 {
		t.Fatal("late first fault/missing observation lost", string(b), e)
	}
}
func TestPrivateLifetimeBrokenBlocked(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprint(broken), func(t *testing.T) {
			r, w := privatePipe(t)
			fd := int(w.Fd())
			if broken {
				r.Close()
			} else {
				for {
					_, e := syscall.Write(fd, make([]byte, 4096))
					if e == syscall.EAGAIN {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			if emitLifetime(fd, execution.ScanReceipt{}, 3) == nil {
				t.Fatal("failed transport accepted")
			}
		})
	}
	for _, code := range []int{0, 1, 2, 3, 130} {
		want := 2
		if code == 130 {
			want = 130
		}
		if lifetimeFailureExit(code) != want {
			t.Fatal(code)
		}
	}
}
func TestPrivateLifetimeCLI(t *testing.T) {
	root, policy := scanFixture(t)
	r, w := privatePipe(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--private-lifetime-fd=3", "--policy", policy, "--checks", "integrity", "--format", "json", root)
	cmd.ExtraFiles = []*os.File{w}
	var out, diag bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &diag
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	w.Close()
	var record lifetimeRecord
	if e := json.NewDecoder(r).Decode(&record); e != nil {
		t.Fatal(e)
	}
	cmd.Wait()
	if cmd.ProcessState.ExitCode() != 3 || record.Exit != 3 || !record.Finished || !record.Cleanup || len(record.Roles) != 3 {
		t.Fatalf("exit/receipt %v %+v %s", cmd.ProcessState, record, diag.String())
	}
	counts := map[string]int{}
	for _, role := range record.Roles {
		counts[role.Role]++
		if !role.Wait || !role.Reaped || !role.Exchange || !role.Success || !role.Stderr || role.Exit != 0 || role.Peak == 0 {
			t.Fatal(role)
		}
	}
	if counts["scan"] != 2 || counts["scan-writer"] != 1 {
		t.Fatal(counts)
	}
}
