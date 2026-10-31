//go:build darwin && cgo && (amd64 || arm64)

package nativefs

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <unistd.h>
#include <stdint.h>

// SDK owns the ABI, constant, sizeof, structure layout and declaration. Never
// copy a Go approximation of proc_taskinfo or use a guessed raw syscall.
static int pt_own_resident(uint64_t *result) {
    struct proc_taskinfo info = {0};
    int n = proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &info, sizeof(info));
    if (n != sizeof(info) || info.pti_resident_size == 0) return -1;
    *result = info.pti_resident_size;
    return 0;
}
*/
import "C"

// OwnResidentBytes queries the calling process, not commit charge, physical
// footprint, peak rusage, another PID or a purported hard resident ceiling.
// The C binding is source-only until executed on both approved Darwin rows.
func OwnResidentBytes() (uint64, error) {
	var n C.uint64_t
	if C.pt_own_resident(&n) != 0 {
		return 0, ErrUnavailable
	}
	return uint64(n), nil
}
