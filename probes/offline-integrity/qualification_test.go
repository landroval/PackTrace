//go:build nativequalification

package offlineintegrity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"packtrace/internal/nativefs"
)

type record struct {
	Type     string
	Case     string
	Outcome  string
	Resident uint64
	Entries  int
	Digest   [32]byte
}
type boundedCapture struct {
	mu       sync.Mutex
	data     []byte
	limit    int
	overflow bool
}

func (b *boundedCapture) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if len(p) > b.limit-len(b.data) {
		p = p[:b.limit-len(b.data)]
		b.overflow = true
	}
	b.data = append(b.data, p...)
	return n, nil
}
func (b *boundedCapture) copy() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...), b.overflow
}
func parseRecords(data []byte) ([]record, error) {
	var out []record
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if len(line) > 1024 || len(out) >= 200 {
			return nil, errors.New("record-limit")
		}
		var r record
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			return nil, errors.New("invalid-record")
		}
		if r.Type != "rss" && r.Type != "result" {
			return nil, errors.New("invalid-record")
		}
		out = append(out, r)
	}
	return out, nil
}

// TestNativeQualification is NEVER selected by the default PR/push root tests.
// The coordinator's exclusive one-shot intent, independent source review,
// public-runner/SHA gates and bounded official build preparation are external
// prerequisites; this test cannot authorize dispatch or assert those facts.
func TestNativeQualification(t *testing.T) {
	var setup Setup
	raw := os.Getenv("PACKTRACE_NATIVE_SETUP")
	if len(raw) == 0 || len(raw) > 16<<10 {
		t.Fatal("BLOCKED: missing bounded preparation receipt")
	}
	dec := json.NewDecoder(bytes.NewBufferString(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&setup) != nil || setup.validate() != nil || setup.OS != runtime.GOOS || setup.Arch != runtime.GOARCH || runtime.Version() != setup.GoVersion {
		t.Fatal("BLOCKED: preparation/toolchain/profile mismatch")
	}
	if setup.OS == "darwin" {
		t.Fatal("BLOCKED: pre-device-open Seatbelt source/API proof missing; no target fixture access")
	}
	if setup.OS == "windows" {
		t.Fatal("BLOCKED: native acquisition candidate not implemented; no target fixture access")
	}

	// Own fixture creation/mutation belongs exclusively to this trusted parent,
	// never the observer. It has no investigated-project path option.
	fixture, err := os.MkdirTemp("", "packtrace-owned-native-")
	if err != nil {
		t.Fatal("BLOCKED: fixture setup")
	}
	cleanupCertain := true
	defer func() {
		if cleanupCertain {
			if os.RemoveAll(fixture) != nil {
				t.Error("BLOCKED: owned fixture cleanup failed")
			}
		}
	}()
	if os.WriteFile(filepath.Join(fixture, "a"), []byte("abc"), 0600) != nil || os.Symlink("a", filepath.Join(fixture, "link")) != nil {
		t.Fatal("BLOCKED: fixture setup; no privilege fallback")
	}
	rowEnd := time.Now().Add(rowDeadline)
	evidence := 0
	launches := 0
	for _, name := range []string{"positive", "limits", "cancel"} {
		if launches >= maxLaunches || time.Until(rowEnd) < childDeadline+cleanupDeadline {
			t.Fatal("BLOCKED: row/launch budget")
		}
		launches++
		stdout := &boundedCapture{limit: 64 << 10}
		stderr := &boundedCapture{limit: maxStderrBytes}
		cmd := exec.Command(os.Args[0], "-test.run=^TestNativeObserver$", "-test.count=1")
		// Fixed same test executable/role; no caller-selected observer executable.
		cmd.Env = []string{"PACKTRACE_NATIVE_OBSERVER=owned-fixtures-v1", "PACKTRACE_NATIVE_FIXTURE=" + fixture, "PACKTRACE_NATIVE_CASE=" + name}
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		cmd.WaitDelay = cleanupDeadline
		if cmd.Start() != nil {
			t.Fatal("BLOCKED: observer launch")
		}
		waited := make(chan error, 1)
		go func() { waited <- cmd.Wait() }()
		timer := time.NewTimer(childDeadline)
		ticker := time.NewTicker(100 * time.Millisecond)
		var processErr error
		completed := false
		stopReason := ""
		samples := 0
		for !completed && stopReason == "" {
			select {
			case processErr = <-waited:
				completed = true
			case <-timer.C:
				stopReason = "child-deadline"
			case <-ticker.C:
				samples++
				own, err := nativefs.OwnResidentBytes()
				data, over := stdout.copy()
				_, errOver := stderr.copy()
				if err != nil || over || errOver {
					stopReason = "sample-or-output-gap"
					break
				}
				// Only complete lines are decoded during a running write.
				if at := bytes.LastIndexByte(data, '\n'); at >= 0 {
					rows, err := parseRecords(data[:at+1])
					if err != nil {
						stopReason = "protocol-gap"
						break
					}
					var child uint64
					for _, r := range rows {
						if r.Type == "rss" {
							child = r.Resident
						}
					}
					if child == 0 {
						stopReason = "worker-rss-gap"
					} else if own > observedStopBytes || child > observedStopBytes-own {
						stopReason = "sampled-resident-stop"
					}
				} else if samples >= 3 {
					stopReason = "worker-rss-missing"
				}
			}
		}
		ticker.Stop()
		timer.Stop()
		if !completed {
			// The independent trusted parent watchdog acts only on the exec.Cmd handle
			// it started. A kill request is not proof of exit; require Wait/reaping.
			_ = cmd.Process.Kill()
			select {
			case processErr = <-waited:
				completed = true
			case <-time.After(cleanupDeadline):
				cleanupCertain = false
				t.Fatal("UNCERTAIN: observer not reaped; fixture deliberately retained; STOP ROW")
			}
		}
		data, over := stdout.copy()
		diagnostic, stderrOver := stderr.copy()
		evidence += len(data) + len(diagnostic)
		if evidence > maxEvidenceBytes || over || stderrOver || stopReason != "" || processErr != nil {
			t.Fatal("FAIL/BLOCKED: observer supervision; raw stderr not forwarded")
		}
		rows, err := parseRecords(data)
		if err != nil {
			t.Fatal("FAIL: observer protocol")
		}
		results := 0
		rss := 0
		for _, r := range rows {
			if r.Type == "rss" {
				if r.Resident == 0 {
					t.Fatal("BLOCKED: RSS query")
				}
				rss++
				continue
			}
			results++
			if r.Case != name || r.Outcome != "observed" {
				t.Fatal("BLOCKED/FAIL: native acquisition case")
			}
			if name == "positive" && (r.Entries != 2 || r.Digest != sha256.Sum256([]byte("abc"))) {
				t.Fatal("FAIL: positive expected/actual mismatch")
			}
		}
		if results != 1 || rss < 2 || samples < 2 {
			t.Fatal("BLOCKED: missing completion or 100ms resident observations")
		}
		t.Logf("case=%s actual=observed source=%s launches=%d sampling=100ms hardCeiling=false", name, setup.SourceSHA, launches)
	}
	// Do not turn a partial fixture harness into a qualification label. No device,
	// mount/volume, deterministic acquisition-window race, parent-death, crash,
	// pipe-backpressure, setup-cache quota or independent integration proof exists
	// in this initial probe. A row cannot PASS while these obligations are gaps.
	t.Fatal("BLOCKED: partial candidate harness; required native boundary/lifecycle cases absent")
}

func TestNativeObserver(t *testing.T) {
	if os.Getenv("PACKTRACE_NATIVE_OBSERVER") != "owned-fixtures-v1" {
		t.Skip("private observer role")
	}
	name := os.Getenv("PACKTRACE_NATIVE_CASE")
	result := record{Type: "result", Case: name, Outcome: "blocked"}
	if nativefs.PrepareProcess() != nil {
		_ = json.NewEncoder(os.Stdout).Encode(result)
		os.Exit(0)
	}
	done := make(chan record, 1)
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		enc := json.NewEncoder(os.Stdout)
		sample := func() {
			n, err := nativefs.OwnResidentBytes()
			if err != nil {
				n = 0
			}
			_ = enc.Encode(record{Type: "rss", Resident: n})
		}
		sample()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				sample()
			case r := <-done:
				sample()
				_ = enc.Encode(r)
				return
			}
		}
	}()
	// Eight MiB deliberately touched, below the 64 MiB per-process fixture bound.
	touched := make([]byte, 8<<20)
	for i := 0; i < len(touched); i += 4096 {
		touched[i] = 1
	}
	time.Sleep(250 * time.Millisecond)
	ctx := context.Background()
	root, err := nativefs.OpenRoot(ctx, os.Getenv("PACKTRACE_NATIVE_FIXTURE"))
	if err == nil {
		switch name {
		case "positive":
			f, e := root.OpenRegular(ctx, "link", 3)
			if e == nil {
				b, readErr := io.ReadAll(f)
				stableErr := f.Stable()
				closeErr := f.Close()
				s, snapErr := root.Snapshot(ctx, nativefs.Limits{FileBytes: 1 << 20, TotalBytes: maxFixtureBytes, Entries: maxEntries, Depth: 8})
				if readErr == nil && stableErr == nil && closeErr == nil && snapErr == nil && s.Complete {
					result.Outcome = "observed"
					result.Digest = sha256.Sum256(b)
					result.Entries = len(s.Entries)
				}
			}
		case "limits":
			f, e := root.OpenRegular(ctx, "a", 2)
			if f != nil {
				f.Close()
			}
			s, se := root.Snapshot(ctx, nativefs.Limits{FileBytes: 2, TotalBytes: 8, Entries: 4, Depth: 2})
			if errors.Is(e, nativefs.ErrLimit) && se != nil && !s.Complete {
				result.Outcome = "observed"
			}
		case "cancel":
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			f, e := root.OpenRegular(canceled, "a", 3)
			if f != nil {
				f.Close()
			}
			if errors.Is(e, context.Canceled) {
				result.Outcome = "observed"
			}
		}
		if root.Close() != nil {
			result.Outcome = "blocked"
		}
	}
	runtime.KeepAlive(touched)
	done <- result
	<-sent
	// Suppress the testing driver's non-protocol PASS line in this private child.
	os.Exit(0)
}
