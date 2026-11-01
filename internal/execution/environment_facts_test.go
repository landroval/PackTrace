package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Owned test-executable diagnostics only: never output environment keys, values,
// paths or control capabilities. This does not admit any extra environment.
type ownedEnvironmentFacts struct {
	Total, LegacyRejected, RootCaseVariants, Architecture, ArchitectureW6432, SystemPaths, DriveEntries, Other int
	ArchitectureAMD64, ParentSentinelPresent                                                                   bool
}

func classifyOwnedEnvironment(env []string) ownedEnvironmentFacts {
	f := ownedEnvironmentFacts{Total: len(env)}
	for _, entry := range env {
		if strings.HasPrefix(entry, "SystemRoot=") || strings.HasPrefix(entry, "PACKTRACE_INTERNAL_") {
			continue
		}
		f.LegacyRejected++
		if strings.HasPrefix(entry, "=") {
			f.DriveEntries++
			continue
		}
		key, value, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "SYSTEMROOT":
			f.RootCaseVariants++
		case "PROCESSOR_ARCHITECTURE":
			f.Architecture++
			f.ArchitectureAMD64 = strings.EqualFold(value, "AMD64")
		case "PROCESSOR_ARCHITEW6432":
			f.ArchitectureW6432++
		case "PROGRAMFILES", "PROGRAMW6432", "PROGRAMFILES(X86)", "COMMONPROGRAMFILES", "COMMONPROGRAMW6432", "COMMONPROGRAMFILES(X86)":
			f.SystemPaths++
		default:
			f.Other++
			if key == "PACKTRACE_OWNED_TEST_SECRET" || key == "HTTP_PROXY" {
				f.ParentSentinelPresent = true
			}
		}
	}
	return f
}
func ownedWorkerEnvironmentAllowed(entry, goos, goarch string) bool {
	// Windows x64-on-Arm inserts this exact public architecture metadata even
	// into the reduced child environment. It is not inherited secret data or
	// architecture authority. Production's reducedEnvironment stays unchanged.
	return strings.HasPrefix(entry, "SystemRoot=") || strings.HasPrefix(entry, "PACKTRACE_INTERNAL_") ||
		(goos == "windows" && goarch == "amd64" && entry == "PROCESSOR_ARCHITECTURE=AMD64")
}

func TestOwnedWorkerEnvironmentOnlyAllowsExactWindowsArchitectureMetadata(t *testing.T) {
	for _, tc := range []struct {
		entry, goos, arch string
		want              bool
	}{
		{"PROCESSOR_ARCHITECTURE=AMD64", "windows", "amd64", true},
		{"PROCESSOR_ARCHITECTURE=ARM64", "windows", "amd64", false},
		{"PROCESSOR_ARCHITECTURE=AMD64PRIVATE", "windows", "amd64", false},
		{"PROCESSOR_ARCHITECTURE=AMD64", "linux", "amd64", false},
		{"PROCESSOR_ARCHITECTURE=AMD64", "windows", "arm64", false},
		{"HTTP_PROXY=PRIVATE", "windows", "amd64", false},
		{"PACKTRACE_OWNED_TEST_SECRET=PRIVATE", "windows", "amd64", false},
		{"UNKNOWN=PRIVATE", "windows", "amd64", false},
		{"SystemRoot=PRIVATE", "windows", "amd64", true},
		{"PACKTRACE_INTERNAL_ROLE=parser", "windows", "amd64", true},
	} {
		if got := ownedWorkerEnvironmentAllowed(tc.entry, tc.goos, tc.arch); got != tc.want {
			t.Fatalf("allowlist mismatch for fixture case: os=%s arch=%s want=%t got=%t", tc.goos, tc.arch, tc.want, got)
		}
	}
}

func writeOwnedEnvironmentFacts() int {
	if json.NewEncoder(os.Stdout).Encode(classifyOwnedEnvironment(os.Environ())) != nil {
		return 2
	}
	return 0
}

func TestOwnedEnvironmentFactsAreCategoricalAndPrivate(t *testing.T) {
	env := []string{"SystemRoot=PRIVATE", "PACKTRACE_INTERNAL_NONCE=PRIVATE", "PROCESSOR_ARCHITECTURE=AMD64", "PROCESSOR_ARCHITEW6432=ARM64", "ProgramFiles=PRIVATE", "=C:=PRIVATE", "UNEXPECTED_PRIVATE=PRIVATE"}
	f := classifyOwnedEnvironment(env)
	if f.Total != 7 || f.LegacyRejected != 5 || f.Architecture != 1 || !f.ArchitectureAMD64 || f.ArchitectureW6432 != 1 || f.SystemPaths != 1 || f.DriveEntries != 1 || f.Other != 1 {
		t.Fatal(f)
	}
	b, e := json.Marshal(f)
	if e != nil || bytes.Contains(b, []byte("PRIVATE")) || bytes.Contains(b, []byte("NONCE")) {
		t.Fatal("private data in fixed-category facts")
	}
	f = classifyOwnedEnvironment([]string{"SYSTEMROOT=PRIVATE", "PACKTRACE_OWNED_TEST_SECRET=PRIVATE", "HTTP_PROXY=PRIVATE"})
	if f.RootCaseVariants != 1 || !f.ParentSentinelPresent || f.LegacyRejected != 3 || f.Other != 2 {
		t.Fatal(f)
	}
}

func TestOwnedWorkerEnvironmentBoundaryFacts(t *testing.T) {
	t.Setenv("PACKTRACE_OWNED_TEST_SECRET", "PRIVATE")
	t.Setenv("HTTP_PROXY", "PRIVATE")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "--owned-worker-environment-facts")
	cmd.Env = reducedEnvironment()
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	// The fixed child emits one categorical record. Bound even a broken entry.
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal("facts pipe")
	}
	if e = cmd.Start(); e != nil {
		t.Fatal("facts start")
	}
	data, readErr := io.ReadAll(io.LimitReader(out, 4097))
	if readErr != nil || len(data) > 4096 {
		cancel()
	}
	waitErr := cmd.Wait()
	if readErr != nil || waitErr != nil || len(data) > 4096 {
		t.Fatal("facts incomplete")
	}
	var f ownedEnvironmentFacts
	if json.Unmarshal(data, &f) != nil {
		t.Fatal("facts shape")
	}
	t.Logf("owned environment categories: %+v", f)
	if f.ParentSentinelPresent {
		t.Fatal("parent sentinel inherited")
	}
	// Exercise the original worker entry, without bypassing its environment gate.
	worker, e := childCommand(WorkerArgument)
	if e != nil {
		t.Fatal("worker command")
	}
	identity, e := buildIdentity()
	if e != nil {
		t.Fatal("worker identity")
	}
	result, runErr := supervise(ctx, strings.NewReader(fixture), "explicit-only", worker, identity)
	exit := -1
	if worker.ProcessState != nil {
		exit = worker.ProcessState.ExitCode()
	}
	t.Logf("owned standard worker: usable=%t error=%v wait_returned=%t exit=%d", result.Usable, runErr, worker.ProcessState != nil, exit)
	if runErr != nil || !result.Usable {
		t.Fatal("original worker boundary refused; retain fixed facts above")
	}
}
