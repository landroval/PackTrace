//go:build linux && (amd64 || arm64)

package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"packtrace/internal/nativefs"
)

func fileTransportFixture(t *testing.T, reference bool) (*ScanRun, string, string) {
	t.Helper()
	base := t.TempDir()
	for _, name := range []string{"target", "reference", "output"} {
		if e := os.Mkdir(filepath.Join(base, name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	s := newRunState(context.Background())
	s.scan = newScanLifecycle(s.caller, s.deadline)
	r := &ScanRun{output: BatchRun{state: s}}
	ref := ""
	if reference {
		ref = filepath.Join(base, "reference")
	}
	dest := filepath.Join(base, "output", "report")
	if e := r.prepareFileOutput(context.Background(), filepath.Join(base, "target"), ref, dest); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = r.Finish() })
	return r, base, dest
}

func TestScanFileTransportObservedPublication(t *testing.T) {
	t.Parallel()
	for _, refs := range []bool{false, true} {
		t.Run(map[bool]string{false: "builtin", true: "reference"}[refs], func(t *testing.T) {
			r, _, dest := fileTransportFixture(t, refs)
			entries, e := os.ReadDir(filepath.Dir(dest))
			if e != nil || len(entries) != 0 {
				t.Fatal("prepare mutated output", entries, e)
			}
			var diagnostics bytes.Buffer
			if e := r.WriteOutput(context.Background(), &diagnostics, []byte("historical diagnostic")); e != nil || diagnostics.String() != "historical diagnostic" {
				t.Fatal(e)
			}
			if _, e := os.Stat(dest); !os.IsNotExist(e) {
				t.Fatal("diagnostic routed to report", e)
			}
			data := []byte("approved \x00 report\n\"<>&☃\"")
			if e := r.WriteReportOutput(context.Background(), panicWriter{}, data); e != nil {
				t.Fatal(e)
			}
			got, e := os.ReadFile(dest)
			if e != nil || !bytes.Equal(got, data) {
				t.Fatal("bytes", got, e)
			}
			if !r.fileOutput.fulfilled || r.fileOutput.closed {
				t.Fatal("missing fulfillment or premature release")
			}
			if e := r.Checkpoint(); e != nil {
				t.Fatal("own output invalidated source", e)
			}
			if e := r.WriteReportOutput(context.Background(), nil, data); e == nil {
				t.Fatal("repeat publication")
			}
			receipt, e := r.Finish()
			if e != nil || !receipt.CleanupConfirmed || !receipt.Finished || len(receipt.Roles) != 1 {
				t.Fatal(receipt, e)
			}
			role := receipt.Roles[0]
			if role.Role != "scan-writer" || role.PID <= 0 || role.Samples < 1 || !role.Reaped || !role.WaitReturned || !role.ExchangeSucceeded || !role.ExchangeJoined || !role.StderrJoined {
				t.Fatal(role)
			}
			if !r.fileOutput.closed {
				t.Fatal("originals not released at Finish")
			}
		})
	}
}

func TestScanFileTransportNoClobberAndRetainedSources(t *testing.T) {
	t.Parallel()
	r, base, dest := fileTransportFixture(t, false)
	// This mutation is before fresh admission; it is an existing-file test, not
	// an epoch replacement which should fail even earlier.
	_, _ = r.Finish()
	if e := os.WriteFile(dest, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	s := newRunState(context.Background())
	s.scan = newScanLifecycle(s.caller, s.deadline)
	r = &ScanRun{output: BatchRun{state: s}}
	if e := r.prepareFileOutput(context.Background(), filepath.Join(base, "target"), "", dest); e != nil {
		t.Fatal(e)
	}
	defer r.Finish()
	if e := r.WriteReportOutput(context.Background(), nil, []byte("replacement")); e == nil {
		t.Fatal("clobber")
	}
	if r.fileOutput.fulfilled || r.fileOutput.closed {
		t.Fatal("failed publication promoted or originals dropped")
	}
	if e := r.fileOutput.plan.CheckSources(); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(dest)
	if e != nil || string(got) != "original" {
		t.Fatal(string(got), e)
	}
	if !s.scan.snapshot().CleanupConfirmed {
		t.Fatal("failed writer not reaped")
	}
}

func TestScanFileTransportBindingActualAcquisition(t *testing.T) {
	t.Parallel()
	r, base, _ := fileTransportFixture(t, true)
	ctx := context.Background()
	target, e := nativefs.OpenRoot(ctx, filepath.Join(base, "target"))
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	ref, e := target.OpenExternalRoot(ctx, filepath.Join(base, "reference"))
	if e != nil {
		t.Fatal(e)
	}
	defer ref.Close()
	cfg := r.fileOutputConfig()
	p, e := bindScanFileAcquisition(ctx, target, nil, ref, cfg)
	if e != nil {
		t.Fatal(e)
	}
	p.Close()
	cfg.Binding = "sha256-" + strings.Repeat("0", 64)
	if p, e := bindScanFileAcquisition(ctx, target, nil, ref, cfg); e == nil {
		p.Close()
		t.Fatal("foreign receipt")
	}
	cfg = r.fileOutputConfig()
	if p, e := bindScanFileAcquisition(ctx, target, nil, nil, cfg); e == nil {
		p.Close()
		t.Fatal("missing actual reference")
	}
	if e := os.Rename(filepath.Join(base, "reference"), filepath.Join(base, "moved")); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(base, "reference"), 0700); e != nil {
		t.Fatal(e)
	}
	if p, e := bindScanFileAcquisition(ctx, target, nil, ref, cfg); e == nil {
		p.Close()
		t.Fatal("changed original reference")
	}
	if e := r.WriteReportOutput(ctx, nil, []byte("never")); e == nil {
		t.Fatal("replaced source accepted")
	}
}

// Use the REAL fixed same-executable writer and observed supervisor, not a
// generic Writer bridge. Invalid transfer must leave even temporary names absent.
func TestScanFileTransportRejectsBeforeNativeOutput(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"hash", "short", "extra", "binding", "extra-control", "wrong-role"} {
		t.Run(mode, func(t *testing.T) {
			r, _, dest := fileTransportFixture(t, false)
			ctx := context.Background()
			witness, empty, e := privatePipe()
			if e != nil {
				t.Fatal(e)
			}
			defer witness.Close()
			empty.Close()
			raw, feed, e := privatePipe()
			if e != nil {
				t.Fatal(e)
			}
			defer raw.Close()
			defer feed.Close()
			cmd, e := childCommand(WriterArgument)
			if e != nil {
				t.Fatal(e)
			}
			role := "scan-writer"
			if mode == "wrong-role" {
				role = "writer"
			}
			nonce, release, e := configureLaunch(cmd, role, witness, raw)
			if e != nil {
				t.Fatal(e)
			}
			identity, e := buildIdentity()
			if e != nil {
				t.Fatal(e)
			}
			data := []byte("APPROVED")
			sum := sha256.Sum256(data)
			cfg := writerLaunchConfig{Nonce: nonce, Size: len(data), SHA256: hex.EncodeToString(sum[:]), File: r.fileOutputConfig()}
			switch mode {
			case "hash":
				cfg.SHA256 = strings.Repeat("0", 64)
			case "short":
				data = data[:2]
			case "extra":
				data = append(data, 'x')
			case "binding":
				cfg.File.Binding = "sha256-" + strings.Repeat("0", 64)
			}
			e = r.output.state.runChild(ctx, cmd, release, func(_ context.Context, c *channel, input io.Closer) error {
				var h hello
				if e := c.expect("hello", &h); e != nil || h.Build != identity {
					return errProtocol
				}
				if e := c.send("hello", hello{identity}); e != nil {
					return e
				}
				if e := c.send("config", cfg); e != nil {
					return e
				}
				if mode == "extra-control" {
					_ = c.send("done", done{})
				}
				_ = input.Close()
				_, _ = feed.Write(data)
				_ = feed.Close()
				var d writerDone
				return c.expect("written", &d)
			})
			if e == nil || !r.output.state.scan.snapshot().CleanupConfirmed {
				t.Fatal("invalid writer success or unreaped", e)
			}
			entries, e := os.ReadDir(filepath.Dir(dest))
			if e != nil || len(entries) != 0 {
				t.Fatal("unapproved output mutation", entries, e)
			}
		})
	}
}

func TestScanFileTransportPostPublicationSourceMutation(t *testing.T) {
	t.Parallel()
	r, base, _ := fileTransportFixture(t, true)
	if e := r.WriteReportOutput(context.Background(), nil, []byte("approved")); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(base, "reference", "new-entry"), []byte("changed"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := r.Checkpoint(); e == nil {
		t.Fatal("fulfilled plan dropped source proof")
	}
	if _, e := r.Finish(); e == nil {
		t.Fatal("changed source accepted at Finish")
	}
	if !r.fileOutput.closed {
		t.Fatal("confirmed cleanup did not release originals")
	}
}

func TestScanFileTransportTerminatesBlockedWitness(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"witness", "data-eof"} {
		t.Run(mode, func(t *testing.T) { testScanFileBlocked(t, mode) })
	}
}

func testScanFileBlocked(t *testing.T, mode string) {
	r, _, dest := fileTransportFixture(t, false)
	witness, blocked, e := privatePipe()
	if e != nil {
		t.Fatal(e)
	}
	defer witness.Close()
	defer blocked.Close()
	if mode == "data-eof" {
		_ = blocked.Close()
	}
	raw, feed, e := privatePipe()
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	defer feed.Close()
	cmd, e := childCommand(WriterArgument)
	if e != nil {
		t.Fatal(e)
	}
	nonce, release, e := configureLaunch(cmd, "scan-writer", witness, raw)
	if e != nil {
		t.Fatal(e)
	}
	identity, e := buildIdentity()
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(nil)
	cfg := writerLaunchConfig{Nonce: nonce, Size: 0, SHA256: hex.EncodeToString(sum[:]), File: r.fileOutputConfig()}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	e = r.output.state.runChild(ctx, cmd, release, func(_ context.Context, c *channel, input io.Closer) error {
		var h hello
		if e := c.expect("hello", &h); e != nil {
			return e
		}
		if e := c.send("hello", hello{identity}); e != nil {
			return e
		}
		if e := c.send("config", cfg); e != nil {
			return e
		}
		_ = input.Close()
		if mode == "witness" {
			_ = feed.Close()
		}
		var d writerDone
		return c.expect("written", &d)
	})
	if e == nil || !r.output.state.scan.snapshot().CleanupConfirmed || cmd.ProcessState == nil {
		t.Fatal("blocked writer survived deadline", e)
	}
	entries, e := os.ReadDir(filepath.Dir(dest))
	if e != nil || len(entries) != 0 {
		t.Fatal(entries, e)
	}
	if r.fileOutput.closed {
		t.Fatal("original closed before Finish")
	}
}

func TestScanFileTransportFinishKeepsUncertainOriginals(t *testing.T) {
	t.Parallel()
	r, _, _ := fileTransportFixture(t, false)
	r.output.state.broken = true
	r.output.state.scan.mu.Lock()
	r.output.state.scan.cleanup = false
	r.output.state.scan.mu.Unlock()
	_, e := r.Finish()
	if !errors.Is(e, errReap) || r.fileOutput.closed || r.fileOutput.plan.CheckSources() != nil {
		t.Fatal("uncertain live originals released", e)
	}
	// Fixture has no actual child: release only for test-owned teardown.
	r.output.state.broken = false
	if e := r.fileOutput.finish(); e != nil {
		t.Fatal(e)
	}
}
