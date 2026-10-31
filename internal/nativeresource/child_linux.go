//go:build linux && (amd64 || arm64)

// Package nativeresource observes retained, unreaped children, never arbitrary
// target-supplied PIDs. RSS observations are admission samples, not hard limits.
package nativeresource

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var ErrUnavailable = errors.New("scan: retained-resident-query-unavailable")

// Child binds a pidfd and proc directory BEFORE the caller starts Wait. The
// unreaped direct-child requirement prevents reuse during this acquisition;
// subsequent queries never reopen a numeric PID. A pidfd exit indication is not
// a reap receipt: the caller must still confirm Wait separately.
type Child struct {
	pidfd, proc *os.File
	pid         int
	start       string
}

// PinChild must be called immediately after Start, before ANY Wait/reap.
func PinChild(pid int) (*Child, error) {
	if pid <= 0 {
		return nil, queryFailure("pin-pid", nil, 0)
	}
	fd, _, errno := syscall.Syscall(434, uintptr(pid), 0, 0) // Linux pidfd_open, amd64/arm64
	if errno != 0 {
		return nil, queryFailure("pin-pidfd-open", errno, 0)
	}
	c := &Child{pidfd: os.NewFile(fd, "scan-owned-pidfd"), pid: pid}
	root, e := syscall.Open("/proc", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		c.Close()
		return nil, queryFailure("pin-proc-open", e, 0)
	}
	defer syscall.Close(root)
	var fs syscall.Statfs_t
	if e := syscall.Fstatfs(root, &fs); e != nil || uint64(fs.Type) != 0x9fa0 {
		c.Close()
		return nil, queryFailure("pin-proc-filesystem", e, 0)
	}
	proc, e := syscall.Openat(root, strconv.Itoa(pid), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		c.Close()
		return nil, queryFailure("pin-child-proc-open", e, 0)
	}
	c.proc = os.NewFile(uintptr(proc), "scan-owned-proc")
	fields, e := c.stat()
	if e != nil {
		c.Close()
		return nil, e
	}
	if fields[1] != strconv.Itoa(os.Getpid()) || fields[19] == "0" {
		c.Close()
		return nil, queryFailure("pin-child-identity", nil, 0)
	}
	c.start = fields[19]
	return c, nil
}

func (c *Child) read(name string) ([]byte, error) {
	fd, e := syscall.Openat(int(c.proc.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, queryFailure(name+"-open", e, 0)
	}
	f := os.NewFile(uintptr(fd), "scan-owned-proc-query")
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 64<<10))
	if e != nil || len(b) == 64<<10 {
		return nil, queryFailure(name+"-read", e, 0)
	}
	return b, nil
}
func (c *Child) stat() ([]string, error) {
	b, e := c.read("stat")
	if e != nil {
		return nil, e
	}
	// comm may contain spaces and ')'; state is after the LAST closing ')'.
	text := string(b)
	end := strings.LastIndex(text, ") ")
	begin := strings.Index(text, " (")
	if begin < 0 || end < begin || text[:begin] != strconv.Itoa(c.pid) {
		return nil, queryFailure("stat-parse", nil, 0)
	}
	fields := strings.Fields(text[end+2:]) // state = field 3, starttime = field 22
	if len(fields) < 22 {
		return nil, queryFailure("stat-parse", nil, 0)
	}
	return fields, nil
}
func (c *Child) exited() (bool, error) { return c.exitWithin(0) }

func (c *Child) exitWithin(bound time.Duration) (bool, error) {
	deadline := time.Now().Add(bound)
	for {
		// Linux UAPI pollfd. Only this retained pidfd can establish exit;
		// a zombie leader, ESRCH or a missing proc file cannot establish it.
		p := struct {
			FD              int32
			Events, Revents int16
		}{FD: int32(c.pidfd.Fd()), Events: 1}
		remaining := time.Duration(0)
		if bound > 0 {
			remaining = max(time.Until(deadline), 0)
		}
		timeout := syscall.NsecToTimespec(int64(remaining))
		_, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&p)), 1, uintptr(unsafe.Pointer(&timeout)), 0, 0, 0)
		if errno == syscall.EINTR && bound > 0 && time.Now().Before(deadline) {
			continue
		}
		if errno != 0 || p.Revents & ^int16(1|16) != 0 {
			return false, queryFailure("pidfd-poll", errno, p.Revents)
		}
		return p.Revents&(1|16) != 0, nil
	}
}

// Sample returns live=false ONLY on a retained pidfd exit indication. Missing,
// zero, failed or inaccessible live RSS is never converted into a zero sample.
func (c *Child) Sample() (rss uint64, live bool, failure error) {
	if c == nil || c.pidfd == nil || c.proc == nil {
		return 0, false, queryFailure("capability", nil, 0)
	}
	exited, e := c.exited()
	if e != nil || exited {
		return 0, !exited, e
	}
	defer func() {
		// Exit can race the proc read. Only this same retained pidfd can explain
		// that race; an unrelated query error on a live process remains failure.
		if failure != nil {
			exited, e := c.exited()
			var query *QueryFailure
			if !exited && errors.As(failure, &query) && query.Errno == int(syscall.ESRCH) && (query.Stage == "smaps_rollup-open" || query.Stage == "smaps_rollup-read") {
				// exit_mm can remove the leader's RSS before the whole thread
				// group signals pidfd exit. Resolve only that observed teardown
				// race, within a quarter of the 100ms sampling interval. Never
				// turn a still-live/unknown process into a successful zero sample.
				exited, e = c.exitWithin(25 * time.Millisecond)
			}
			if e == nil && exited {
				rss, live, failure = 0, false, nil
			}
		}
	}()
	fields, e := c.stat()
	if e != nil {
		return 0, true, e
	}
	if fields[19] != c.start {
		return 0, true, queryFailure("stat-identity", nil, 0)
	}
	b, e := c.read("smaps_rollup")
	if e != nil {
		return 0, true, e
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "Rss:" && f[2] == "kB" {
			n, e := strconv.ParseUint(f[1], 10, 64)
			if e == nil && n > 0 && n <= ^uint64(0)/1024 {
				return n * 1024, true, nil
			}
		}
	}
	return 0, true, queryFailure("smaps_rollup-parse", nil, 0)
}
func (c *Child) Close() error {
	var a, b error
	if c.pidfd != nil {
		a = c.pidfd.Close()
		c.pidfd = nil
	}
	if c.proc != nil {
		b = c.proc.Close()
		c.proc = nil
	}
	return errors.Join(a, b)
}
