//go:build darwin && cgo && (amd64 || arm64)

package nativeresource

/*
#cgo CFLAGS: -D_DARWIN_C_SOURCE -Wno-deprecated-declarations
#cgo LDFLAGS: -lproc
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <stdint.h>
#include <sys/event.h>
#include <sys/proc_info.h>
#include <unistd.h>

struct pt_pin { uint32_t port; uint64_t sec, usec; int stage, code; };
static int pt_pin_child(int pid, struct pt_pin *out) {
    struct proc_bsdinfo before = {0}, after = {0};
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, sizeof(before)) != (int)sizeof(before)) {
        out->stage=1; out->code=errno; return -1;
    }
    if (before.pbi_pid != (uint32_t)pid || before.pbi_ppid != (uint32_t)getpid() || before.pbi_start_tvsec == 0) {
        out->stage=2; return -1;
    }
    mach_port_t port=MACH_PORT_NULL;
    kern_return_t k=task_name_for_pid(mach_task_self(),pid,&port);
    if (k != KERN_SUCCESS || port == MACH_PORT_NULL) {
        out->stage=3;out->code=k;
        if (port != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(),port);
        return -1;
    }
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after)) != (int)sizeof(after) ||
        after.pbi_pid != before.pbi_pid || after.pbi_ppid != before.pbi_ppid ||
        after.pbi_start_tvsec != before.pbi_start_tvsec || after.pbi_start_tvusec != before.pbi_start_tvusec) {
        out->stage=4;out->code=errno;mach_port_deallocate(mach_task_self(),port);return -1;
    }
    out->port=port;out->sec=before.pbi_start_tvsec;out->usec=before.pbi_start_tvusec;
    return 0;
}
static int pt_child_resident(uint32_t port, uint64_t *resident) {
    mach_task_basic_info_data_t info={0};
    mach_msg_type_number_t count=MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t k=task_info(port,MACH_TASK_BASIC_INFO,(task_info_t)&info,&count);
    if (k != KERN_SUCCESS) return (int)k;
    if (count != MACH_TASK_BASIC_INFO_COUNT || info.resident_size == 0) return -1;
    *resident=info.resident_size;return 0;
}
static int pt_release_child(uint32_t port) { return mach_port_deallocate(mach_task_self(),port); }
static int pt_exit_queue(void) {
    int q=kqueue(); if (q<0) return -1;
    if (fcntl(q,F_SETFD,FD_CLOEXEC)!=0) {int saved=errno;close(q);errno=saved;return -1;}
    return q;
}
*/
import "C"

import (
	"errors"
	"strconv"
	"sync"
	"syscall"
	"time"
)

var ErrUnavailable = errors.New("scan: retained-resident-query-unavailable")

type darwinResourceFailure struct {
	Stage string
	Code  int
}

func (e *darwinResourceFailure) Error() string { return ErrUnavailable.Error() }
func (e *darwinResourceFailure) Unwrap() error { return ErrUnavailable }
func darwinErrno(stage string, err error) error {
	var n syscall.Errno
	errors.As(err, &n)
	return &darwinResourceFailure{stage, int(n)}
}

// The Mach task-name send right identifies the captured task object. An owned
// EVFILT_PROC knote independently latches that original process's NOTE_EXIT.
// PID-based APIs are used only during pinning, before the launch owner may Wait;
// subsequent resident queries never reopen a numeric PID. Exit is not reaping.
type Child struct {
	mu                      sync.Mutex
	port                    uint32
	queue, pid              int
	createdSec, createdUsec uint64
	exited, closed          bool
}

func PinChild(pid int) (*Child, error) {
	if pid <= 0 || int(C.int(pid)) != pid {
		return nil, ErrUnavailable
	}
	var pin C.struct_pt_pin
	if C.pt_pin_child(C.int(pid), &pin) != 0 {
		return nil, &darwinResourceFailure{"pin-stage-" + strconv.Itoa(int(pin.stage)), int(pin.code)}
	}
	// Darwin kqueue has no close-on-exec argument. Use the same ForkLock
	// protocol as stdlib descriptor creation so concurrent exec cannot inherit
	// the brief pre-CLOEXEC descriptor. No global process/security setting.
	syscall.ForkLock.RLock()
	queue, e := C.pt_exit_queue()
	syscall.ForkLock.RUnlock()
	if queue < 0 {
		C.pt_release_child(pin.port)
		return nil, darwinErrno("exit-queue-create", e)
	}
	q := int(queue)
	changes := []syscall.Kevent_t{{Ident: uint64(pid), Filter: syscall.EVFILT_PROC, Flags: syscall.EV_ADD | syscall.EV_ENABLE | syscall.EV_ONESHOT, Fflags: syscall.NOTE_EXIT}}
	if _, e = syscall.Kevent(q, changes, nil, nil); e != nil {
		syscall.Close(q)
		C.pt_release_child(pin.port)
		return nil, darwinErrno("exit-knote-register", e)
	}
	return &Child{port: uint32(pin.port), queue: q, pid: pid, createdSec: uint64(pin.sec), createdUsec: uint64(pin.usec)}, nil
}
func (c *Child) exitWithin(bound time.Duration) (bool, error) {
	if c.exited {
		return true, nil
	}
	end := time.Now().Add(bound)
	for {
		remaining := time.Until(end)
		if remaining < 0 {
			remaining = 0
		}
		ts := syscall.NsecToTimespec(remaining.Nanoseconds())
		var events [1]syscall.Kevent_t
		n, e := syscall.Kevent(c.queue, nil, events[:], &ts)
		if e == syscall.EINTR && time.Now().Before(end) {
			continue
		}
		if e != nil {
			return false, darwinErrno("exit-knote-query", e)
		}
		if n == 0 {
			return false, nil
		}
		x := events[0]
		if n != 1 || x.Ident != uint64(c.pid) || x.Filter != syscall.EVFILT_PROC || x.Flags&syscall.EV_ERROR != 0 || x.Fflags&syscall.NOTE_EXIT == 0 {
			return false, &darwinResourceFailure{"exit-knote-shape", int(x.Flags)}
		}
		c.exited = true
		return true, nil
	}
}
func (c *Child) Sample() (uint64, bool, error) {
	if c == nil {
		return 0, false, ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, true, ErrUnavailable
	}
	exited, e := c.exitWithin(0)
	if e != nil {
		return 0, true, e
	}
	if exited {
		return 0, false, nil
	}
	var n C.uint64_t
	code := C.pt_child_resident(C.uint32_t(c.port), &n)
	if code != 0 {
		// A failed task query is never a zero live sample. Permit only a
		// positive event on this retained original knote to establish exit.
		exited, e = c.exitWithin(25 * time.Millisecond)
		if e != nil {
			return 0, true, e
		}
		if exited {
			return 0, false, nil
		}
		return 0, true, &darwinResourceFailure{"mach-task-basic-info", int(code)}
	}
	return uint64(n), true, nil
}
func (c *Child) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	e := syscall.Close(c.queue)
	if code := C.pt_release_child(C.uint32_t(c.port)); code != 0 {
		return errors.Join(e, &darwinResourceFailure{"mach-port-release", int(code)})
	}
	return e
}
