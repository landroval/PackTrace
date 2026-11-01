//go:build windows && amd64

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var createJob = kernel.NewProc("CreateJobObjectW")
var setJob = kernel.NewProc("SetInformationJobObject")
var queryJob = kernel.NewProc("QueryInformationJobObject")
var assignJob = kernel.NewProc("AssignProcessToJobObject")
var terminateJob = kernel.NewProc("TerminateJobObject")
var resumeProcess = syscall.NewLazyDLL("ntdll.dll").NewProc("NtResumeProcess")

type basicLimits struct {
	ProcessTime, JobTime int64
	Flags                uint32
	MinWS, MaxWS         uintptr
	Active               uint32
	Affinity             uintptr
	Priority, Scheduling uint32
}
type extendedLimits struct {
	Basic                                                      basicLimits
	IO                                                         [6]uint64
	ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory uintptr
}
type accounting struct {
	User, Kernel, PeriodUser, PeriodKernel int64
	Faults, Total, Active, Terminated      uint32
}

var _ [144]byte = [unsafe.Sizeof(extendedLimits{})]byte{}
var _ [48]byte = [unsafe.Sizeof(accounting{})]byte{}

type phase struct {
	Name, State                         string
	Exit                                int
	Seconds                             float64
	Reaped, GroupClean, CaptureComplete bool
	StdoutBytes, StderrBytes            int
	StdoutSHA256, StderrSHA256          string
	Counts                              *counts `json:",omitempty"`
}
type receipt struct {
	Schema, SourceSHA, Tree, GoVersion, Compiler, Qualification string
	Setup, Native                                               string
	StartedUTC                                                  string
	Phases                                                      []phase
	ValidationPassed                                            bool
	DiagnosticCompleted                                         bool   `json:",omitempty"`
	CompatibilityPassed                                         bool   `json:",omitempty"`
	CompatibilityScope                                          string `json:",omitempty"`
	Wow64Machine, HostMachine                                   uint16 `json:",omitempty"`
	ProcessArchitecture                                         string `json:",omitempty"`
	HostArchitectureQuerySucceeded                              bool   `json:",omitempty"`
	HostArchitectureQueryError                                  uint32 `json:",omitempty"`
	Failure                                                     string `json:",omitempty"`
	BoundSeconds                                                int
	CommitLimitBytes                                            uint64
}

func job() (syscall.Handle, error) {
	for _, p := range []*syscall.LazyProc{createJob, setJob, queryJob, assignJob, terminateJob, resumeProcess} {
		if e := p.Find(); e != nil {
			return 0, errors.New("job-api-unavailable")
		}
	}
	h, _, _ := createJob.Call(0, 0)
	if h == 0 {
		return 0, errors.New("job-create-failed")
	}
	limits := extendedLimits{Basic: basicLimits{Flags: 0x2000 | 0x200 | 0x8, Active: 64}, JobMemory: 2 << 30}
	ok, _, _ := setJob.Call(h, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	runtime.KeepAlive(limits)
	if ok == 0 {
		syscall.CloseHandle(syscall.Handle(h))
		return 0, errors.New("job-limits-failed")
	}
	return syscall.Handle(h), nil
}
func active(h syscall.Handle) (uint32, error) {
	var a accounting
	ok, _, _ := queryJob.Call(uintptr(h), 1, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a), 0)
	runtime.KeepAlive(a)
	if ok == 0 {
		return 0, errors.New("job-query-failed")
	}
	return a.Active, nil
}
func treeBytes(root string) (int64, error) {
	var total int64
	e := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		info, e := os.Lstat(path)
		if errors.Is(e, fs.ErrNotExist) {
			return nil
		}
		if e != nil {
			return e
		}
		m := info.Mode()
		if !m.IsRegular() && !m.IsDir() && m&os.ModeSymlink == 0 {
			return errors.New("owned-storage-type")
		}
		total += info.Size()
		if total > 2<<30 {
			return errors.New("owned-storage-limit")
		}
		return nil
	})
	return total, e
}
func run(ctx context.Context, name, exe, dir, work string, args, env []string, limit time.Duration) (phase, []byte, []byte) {
	started := time.Now()
	p := phase{Name: name, State: "setup-failed", Exit: -1}
	h, e := job()
	if e != nil {
		return p, nil, nil
	}
	defer syscall.CloseHandle(h)
	child, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	out := capture{cap: 4 << 20, complete: true, stop: cancel}
	diag := capture{cap: 64 << 10, complete: true, stop: cancel}
	cmd := exec.CommandContext(child, exe, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = &out
	cmd.Stderr = &diag
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x4}
	cmd.WaitDelay = 2 * time.Second
	var launch sync.Mutex
	assigned := false
	cmd.Cancel = func() error {
		launch.Lock()
		defer launch.Unlock()
		if assigned {
			ok, _, _ := terminateJob.Call(uintptr(h), 2)
			if ok == 0 {
				return errors.New("job-stop-failed")
			}
			return nil
		}
		if cmd.Process != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	if e = cmd.Start(); e != nil {
		return p, nil, nil
	}
	launch.Lock()
	var startErr error
	e = cmd.Process.WithHandle(func(process uintptr) {
		if child.Err() != nil {
			startErr = child.Err()
			return
		}
		ok, _, _ := assignJob.Call(uintptr(h), process)
		if ok == 0 {
			startErr = errors.New("job-assign-failed")
			return
		}
		assigned = true
		status, _, _ := resumeProcess.Call(process)
		if uint32(status) != 0 {
			startErr = errors.New("job-resume-failed")
		}
	})
	if e != nil {
		startErr = e
	}
	launch.Unlock()
	if startErr != nil {
		cancel()
		_ = cmd.Cancel()
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var waitErr error
	waiting := true
	for waiting {
		select {
		case waitErr = <-done:
			waiting = false
		case <-ticker.C:
			a, e := treeBytes(filepath.Join(work, "cache"))
			if e == nil {
				var b int64
				b, e = treeBytes(filepath.Join(work, "build"))
				a += b
			}
			if e != nil || a > 2<<30 {
				p.State = "storage-failed"
				cancel()
			}
		}
	}
	p.Reaped = cmd.ProcessState != nil
	if p.Reaped {
		p.Exit = cmd.ProcessState.ExitCode()
	}
	cleanUntil := time.Now().Add(2 * time.Second)
	for {
		n, e := active(h)
		if e != nil {
			break
		}
		if n == 0 {
			p.GroupClean = true
			break
		}
		_, _, _ = terminateJob.Call(uintptr(h), 2)
		if !time.Now().Before(cleanUntil) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	p.CaptureComplete = out.complete && diag.complete && !errors.Is(waitErr, exec.ErrWaitDelay)
	p.StdoutBytes, p.StderrBytes = len(out.data), len(diag.data)
	a, b := sha256.Sum256(out.data), sha256.Sum256(diag.data)
	p.StdoutSHA256, p.StderrSHA256 = hex.EncodeToString(a[:]), hex.EncodeToString(b[:])
	if startErr == nil && p.State != "storage-failed" {
		p.State = "exited"
		if child.Err() != nil {
			p.State = "deadline-or-capture-limit"
		}
	}
	p.Seconds = time.Since(started).Seconds()
	return p, out.data, diag.data
}
func diagnostics(name, stream string, data []byte) {
	for offset := 0; offset < len(data); offset += 3072 {
		end := min(offset+3072, len(data))
		b, _ := json.Marshal(map[string]any{"phase": name, "stream": stream, "offset": offset, "base64": base64.StdEncoding.EncodeToString(data[offset:end])})
		fmt.Printf("WINDOWS_NATIVE_DIAGNOSTIC %s\n", b)
	}
}
func main() { os.Exit(mainCode()) }
func mainCode() (code int) {
	r := receipt{Schema: "packtrace.windows-native.v1", SourceSHA: os.Getenv("SOURCE_SHA"), Qualification: "not-qualified", Setup: "not-run", Native: "not-run", StartedUTC: time.Now().UTC().Format(time.RFC3339), BoundSeconds: 900, CommitLimitBytes: 2 << 30}
	code = 2
	defer func() {
		b, e := json.Marshal(r)
		if e == nil && len(b) <= 64<<10 {
			if len(os.Args) == 4 {
				_ = os.WriteFile(filepath.Join(os.Args[3], "receipt.json"), b, 0600)
			}
			fmt.Printf("WINDOWS_NATIVE_RECEIPT %s\n", b)
		} else {
			fmt.Println(`WINDOWS_NATIVE_RECEIPT {"failure":"receipt-limit","ValidationPassed":false}`)
		}
	}()
	if len(os.Args) != 4 || runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		r.Failure = "runner-arguments"
		return
	}
	diagnosticOnly, profileErr := volumeDiagnostic(os.Getenv("VALIDATION_PROFILE"))
	if profileErr != nil {
		r.Failure = "runner-profile"
		return
	}
	compatibility := os.Getenv("VALIDATION_PROFILE") == "windows11-x64-compat-arm64-v1"
	if compatibility {
		r.CompatibilityScope = "Windows11-client-ARM64-host-x64-emulation; CGO0; race-not-run; not-native-x64-qualification"
		r.Qualification = "not-qualified-native-windows11-x64"
		proc := kernel.NewProc("IsWow64Process2")
		owner, e := syscall.GetCurrentProcess()
		if e != nil || proc.Find() != nil {
			r.Failure = "emulation-query-unavailable"
			return
		}
		r.ProcessArchitecture = runtime.GOARCH
		ok, _, queryErr := proc.Call(uintptr(owner), uintptr(unsafe.Pointer(&r.Wow64Machine)), uintptr(unsafe.Pointer(&r.HostMachine)))
		runtime.KeepAlive(r.Wow64Machine)
		runtime.KeepAlive(r.HostMachine)
		r.HostArchitectureQuerySucceeded = ok != 0
		if ok == 0 {
			if code, ok := queryErr.(syscall.Errno); ok {
				r.HostArchitectureQueryError = uint32(code)
			}
			r.Failure = "host-architecture-query-failed"
			return
		}
		if !desktopEmulation(r.ProcessArchitecture, r.HostMachine) {
			r.Failure = "not-x64-emulated-on-arm64"
			return
		}
	}
	repo, goexe, work := os.Args[1], os.Args[2], os.Args[3]
	ctx, cancel := context.WithTimeout(context.Background(), 890*time.Second)
	defer cancel()
	env := append(os.Environ(), "GOROOT="+filepath.Dir(filepath.Dir(goexe)), "GOOS=windows", "GOARCH=amd64", "GOFLAGS=", "GOEXPERIMENT=", "GODEBUG=", "GORACE=", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_COUNT=0", "GIT_CONFIG_GLOBAL="+filepath.Join(work, "empty-git-config"), "GIT_TERMINAL_PROMPT=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOENV=off", "GOMAXPROCS=2", "GOMEMLIMIT=512MiB", "GOCACHE="+filepath.Join(work, "cache"), "GOTMPDIR="+filepath.Join(work, "build"), "TMP="+filepath.Join(work, "build"), "TEMP="+filepath.Join(work, "build"))
	env = append(env, "PATH="+filepath.Dir(goexe)+string(os.PathListSeparator)+os.Getenv("PATH"))
	command := func(name, exe string, args []string, seconds int, cgo string) ([]byte, bool) {
		p, out, errout := run(ctx, name, exe, repo, work, args, append(env, "CGO_ENABLED="+cgo), time.Duration(seconds)*time.Second)
		r.Phases = append(r.Phases, p)
		ok := p.State == "exited" && p.Exit == 0 && p.Reaped && p.GroupClean && p.CaptureComplete
		if !ok {
			r.Failure = name
			diagnostics(name, "stdout", out)
			diagnostics(name, "stderr", errout)
		}
		return out, ok
	}
	source, ok := command("source", "git", []string{"rev-parse", "HEAD", "HEAD^{tree}"}, 10, "0")
	if !ok {
		return
	}
	fields := strings.Fields(string(source))
	if len(fields) != 2 || fields[0] != r.SourceSHA {
		r.Failure = "source-identity"
		return
	}
	r.Tree = fields[1]
	version, ok := command("go-version", goexe, []string{"version"}, 10, "0")
	if !ok {
		return
	}
	r.GoVersion = strings.TrimSpace(string(version))
	if r.GoVersion != "go version go1.27.1 windows/amd64" {
		r.Failure = "go-version-profile"
		return
	}
	if compatibility {
		r.Compiler = "not-required; CGO0 compatibility probe"
	} else {
		compiler := os.Getenv("CC")
		if compiler == "" {
			compiler = "gcc"
		}
		cc, ok := command("gcc-version", compiler, []string{"-dumpfullversion"}, 10, "0")
		if !ok {
			return
		}
		r.Compiler = strings.TrimSpace(string(cc))
	}
	r.Setup = "passed"
	r.Native = "failed"
	if diagnosticOnly {
		out, ok := command("volume-options-diagnostic", goexe, []string{"test", "-count=1", "-json", "-timeout=70s", "-run=^TestWindowsVolumeBootstrapPairedOptions$", "./internal/nativefs"}, 75, "0")
		if !ok {
			return
		}
		c, e := testCounts(out)
		r.Phases[len(r.Phases)-1].Counts = &c
		diagnostics("volume-options-diagnostic", "stdout", out)
		if e != nil || c.Failed != 0 || c.BuildFailed != 0 {
			r.Failure = "diagnostic-stream"
			return
		}
		changed, ok := command("source-clean", "git", []string{"status", "--porcelain", "--untracked-files=all"}, 10, "0")
		if !ok || len(changed) != 0 {
			r.Failure = "source-mutated-or-unconfirmed"
			return
		}
		r.Native = "diagnostic-completed-not-product-validation"
		r.DiagnosticCompleted = true
		// Deliberately leave ValidationPassed false: these paired opens are
		// facts about a trusted volume, never product admission/qualification.
		code = 0
		return
	}
	packages := []string{"./internal/nativefs", "./internal/nativeresource", "./internal/integrityscan", "./internal/execution", "./cmd/packtrace"}
	tests := []struct {
		name, cgo string
		seconds   int
		args      []string
	}{
		{"root-corpus", "0", 270, []string{"./..."}},
		{"race-corpus", "1", 350, packages},
		{"race-original-wider-reproducer", "1", 230, []string{"./internal/integrityscan", "./internal/nativefs", "./cmd/packtrace"}},
	}
	if compatibility {
		tests = tests[:1]
	}
	for _, test := range tests {
		args := []string{"test", "-count=1", "-json", fmt.Sprintf("-timeout=%ds", test.seconds-5)}
		if test.cgo == "1" {
			args = append(args, "-race")
		}
		args = append(args, test.args...)
		out, ok := command(test.name, goexe, args, test.seconds, test.cgo)
		if !ok {
			return
		}
		c, e := testCounts(out)
		r.Phases[len(r.Phases)-1].Counts = &c
		if e != nil || c.Failed > 0 || c.BuildFailed > 0 {
			r.Failure = "test-stream"
			diagnostics(test.name, "stdout", out)
			return
		}
		if test.name == "root-corpus" {
			// Publish the already bounded owned-test stream even on success,
			// so relocation-blocked versus actually-moved evidence is auditable.
			diagnostics(test.name, "stdout", out)
		}
	}
	if _, ok = command("vet", goexe, []string{"vet", "./..."}, 25, "0"); !ok {
		return
	}
	changed, ok := command("source-clean", "git", []string{"status", "--porcelain", "--untracked-files=all"}, 10, "0")
	if !ok {
		return
	}
	if len(changed) != 0 {
		r.Failure = "source-mutated"
		return
	}
	if compatibility {
		r.Native = "emulated-compatibility-passed-not-native-x64"
		r.CompatibilityPassed = true
		// Deliberately keep ValidationPassed false; server native/race evidence
		// and desktop emulated compatibility remain separately attributable.
	} else {
		r.Native = "passed"
		r.ValidationPassed = true
	}
	code = 0
	return
}
