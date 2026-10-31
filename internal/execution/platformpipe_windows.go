//go:build windows

package execution

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// platformPipe creates one local byte channel, not a listener or public entry.
// Both handles are overlapped and noninheritable. Only os.File owns them after
// wrapping; privatePipe must still verify actual Go deadline support.
func platformPipe() (*os.File, *os.File, error) {
	// These exact names are registered by syscall in Go's system-DLL allowlist:
	// LoadDLL uses LoadLibraryExW(LOAD_LIBRARY_SEARCH_SYSTEM32), not PATH/CWD.
	kernel, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return nil, nil, errProtocol
	}
	defer kernel.Release()
	createPipe, err := kernel.FindProc("CreateNamedPipeW")
	if err != nil {
		return nil, nil, errProtocol
	}
	security, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return nil, nil, errProtocol
	}
	defer security.Release()
	convert, err := security.FindProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	if err != nil {
		return nil, nil, errProtocol
	}

	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return nil, nil, errProtocol
	}
	defer token.Close()
	// TOKEN_USER plus the maximum Windows SID (8 + 15*4 bytes), aligned by
	// Tokenuser. One bounded query, no resize/retry or account-name lookup.
	var user struct {
		info syscall.Tokenuser
		sid  [68]byte
	}
	var needed uint32
	err = syscall.GetTokenInformation(token, syscall.TokenUser, (*byte)(unsafe.Pointer(&user)), uint32(unsafe.Sizeof(user)), &needed)
	if err != nil || user.info.User.Sid == nil {
		return nil, nil, errProtocol
	}
	sid, err := user.info.User.Sid.String()
	runtime.KeepAlive(&user)
	if err != nil {
		return nil, nil, errProtocol
	}
	// Protected DACL: only the process-token user SID has access. No inherited
	// ACEs, default DACL, Everyone/group grant, privilege or persistent change.
	// Same-user processes are not a sandbox boundary; random naming also keeps
	// accidental/racing connections out of this single private instance.
	sddl, err := syscall.UTF16PtrFromString("O:" + sid + "D:P(A;;GA;;;" + sid + ")")
	if err != nil {
		return nil, nil, errProtocol
	}
	var descriptor unsafe.Pointer
	ok, _, _ := convert.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		return nil, nil, errProtocol
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(descriptor)))
	attributes := syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: uintptr(descriptor),
		// InheritHandle remains zero; owned child duplicates are made elsewhere.
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, errProtocol
	}
	name, err := syscall.UTF16PtrFromString(`\\.\pipe\packtrace-` + hex.EncodeToString(nonce[:]))
	if err != nil {
		return nil, nil, errProtocol
	}
	const (
		pipeAccessInbound       = 0x00000001
		fileFlagFirstInstance   = 0x00080000
		pipeRejectRemoteClients = 0x00000008
		securitySQOSPresent     = 0x00100000 // anonymous client impersonation level
	)
	h, _, _ := createPipe.Call(
		uintptr(unsafe.Pointer(name)),
		pipeAccessInbound|fileFlagFirstInstance|syscall.FILE_FLAG_OVERLAPPED,
		pipeRejectRemoteClients, // byte type/read mode, blocking mode (not NOWAIT)
		1, 0, 64<<10, 0, uintptr(unsafe.Pointer(&attributes)),
	)
	readHandle := syscall.Handle(h)
	if readHandle == syscall.InvalidHandle {
		// Includes name collisions: fail closed, with no connect/retry loop.
		return nil, nil, errProtocol
	}
	defer func() {
		if readHandle != syscall.InvalidHandle {
			syscall.CloseHandle(readHandle)
		}
	}()
	writeHandle, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OVERLAPPED|securitySQOSPresent, 0)
	if err != nil {
		return nil, nil, errProtocol
	}
	// CreateFile has already connected the client to our exclusive instance.
	// No ConnectNamedPipe is needed (including the connect-before-call case),
	// so no pending native connect/event/OVERLAPPED buffer outlives this call.
	// OPEN_EXISTING never waits for a busy instance; there is no WaitNamedPipe.
	r := os.NewFile(uintptr(readHandle), "packtrace-private-read")
	readHandle = syscall.InvalidHandle // ownership transferred exactly once
	w := os.NewFile(uintptr(writeHandle), "packtrace-private-write")
	return r, w, nil
}

// Go deliberately wraps the exact standard-input handle as synchronous. A new
// owned handle lets NewFile detect OVERLAPPED and use Go's normal IOCP path.
// Only the private child control stream reaches this boundary, not original
// input/public output or a parent goroutine; no caller mode is changed.
func platformControlInput(in io.Reader) (io.Reader, func(), error) {
	f, ok := in.(*os.File)
	if !ok {
		return in, func() {}, nil
	}
	if f == nil {
		return nil, nil, errProtocol
	}
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, nil, errProtocol
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, nil, errProtocol
	}
	var handle syscall.Handle
	var duplicateErr error
	err = raw.Control(func(source uintptr) {
		duplicateErr = syscall.DuplicateHandle(process, syscall.Handle(source), process, &handle, 0, false, syscall.DUPLICATE_SAME_ACCESS)
	})
	if err != nil || duplicateErr != nil {
		return nil, nil, errProtocol
	}
	owned := os.NewFile(uintptr(handle), "inspect-batch-child-control")
	if owned.SetReadDeadline(time.Time{}) != nil {
		owned.Close()
		return nil, nil, errProtocol
	}
	return owned, func() { owned.Close() }, nil
}
