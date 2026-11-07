package intelstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestQuotaProcessHelper(t *testing.T) {
	path := os.Getenv("PACKTRACE_TEST_TRANSACTION_STORE")
	if path == "" {
		t.Skip("private transaction child")
	}
	s, e := Open(context.Background(), path, CreateOwned)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	tx, e := s.begin(context.Background(), operationSync, &Budget{StagingBytes: 1 << 20})
	if os.Getenv("PACKTRACE_TEST_TRANSACTION_BUSY") == "1" {
		if !errors.Is(e, ErrBusy) || tx != nil {
			t.Fatal("actual second writer not excluded", e)
		}
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	if _, e := tx.put(context.Background(), bytes.NewBufferString("retained"), 8); e != nil {
		t.Fatal(e)
	}
	ready := os.Getenv("PACKTRACE_TEST_TRANSACTION_READY")
	data, _ := json.Marshal(struct {
		PID int `json:"pid"`
	}{os.Getpid()})
	if os.WriteFile(ready+".tmp", data, 0600) != nil || os.Rename(ready+".tmp", ready) != nil {
		t.Fatal("atomic owned readiness")
	}
	for {
		time.Sleep(time.Second)
	}
}

func TestQuotaReconcilesKilledOriginalWriterAfterWait(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows transaction")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	parent := t.TempDir()
	path := filepath.Join(parent, "store")
	signals := filepath.Join(parent, "signals")
	if os.Mkdir(signals, 0700) != nil {
		t.Fatal("owned signal directory")
	}
	ready := filepath.Join(signals, "ready")
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQuotaProcessHelper$")
	cmd.Env = append(os.Environ(), "PACKTRACE_TEST_TRANSACTION_STORE="+path, "PACKTRACE_TEST_TRANSACTION_READY="+ready)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	for {
		data, e := os.ReadFile(ready)
		if e == nil {
			var r struct {
				PID int `json:"pid"`
			}
			if json.Unmarshal(data, &r) != nil || r.PID != cmd.Process.Pid {
				t.Fatal("invalid readiness")
			}
			break
		}
		if ctx.Err() != nil {
			t.Fatal("owned child not ready", ctx.Err())
		}
		time.Sleep(5 * time.Millisecond)
	}
	other := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQuotaProcessHelper$")
	other.Env = append(os.Environ(), "PACKTRACE_TEST_TRANSACTION_STORE="+path, "PACKTRACE_TEST_TRANSACTION_BUSY=1")
	if out, e := other.CombinedOutput(); e != nil || other.ProcessState == nil || other.ProcessState.ExitCode() != 0 {
		t.Fatal("second actual process", e, string(out))
	}
	if e := cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e := cmd.Wait(); e == nil || cmd.ProcessState == nil {
		t.Fatal("original kill/reap not observed")
	}
	waited = true
	var used uint64
	e := filepath.WalkDir(path, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() {
			st, e := d.Info()
			if e != nil {
				return e
			}
			used += uint64(st.Size())
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	s, e := Open(context.Background(), path, CreateOwned)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.quotaLimit = used + (1 << 20)
	tx, e := s.begin(context.Background(), operationImport, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal("unused crashed reservation not reconciled from retained bytes", e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
}
