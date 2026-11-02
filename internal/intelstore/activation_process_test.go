package intelstore

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestActivationProcessHelper(t *testing.T) {
	path := os.Getenv("PACKTRACE_TEST_ACTIVATION_STORE")
	if path == "" {
		t.Skip("private activation child")
	}
	ctx := context.Background()
	s, e := Open(ctx, path, CreateOwned)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	draft := storageDraft(t, tx, "child-generation")
	var id ID
	if os.Getenv("PACKTRACE_TEST_ACTIVATION_PHASE") != "pending" {
		id, e = tx.seal(ctx, draft)
		if e != nil {
			t.Fatal(e)
		}
	}
	if os.Getenv("PACKTRACE_TEST_ACTIVATION_PHASE") == "activated" {
		if e := tx.activate(ctx, id); e != nil {
			t.Fatal(e)
		}
	}
	ready := os.Getenv("PACKTRACE_TEST_ACTIVATION_READY")
	data, _ := json.Marshal(struct {
		PID int
		ID  ID
	}{os.Getpid(), id})
	if os.WriteFile(ready+".tmp", data, 0600) != nil || os.Rename(ready+".tmp", ready) != nil {
		t.Fatal("owned atomic readiness")
	}
	for {
		time.Sleep(time.Second)
	}
}
func TestActivationOriginalProcessCrashBeforeAndAfterPublication(t *testing.T) {
	for _, phase := range []string{"pending", "sealed", "activated"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			s, path := transactionFixture(t)
			tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 4 << 20})
			if e != nil {
				t.Fatal(e)
			}
			first, e := tx.seal(ctx, storageDraft(t, tx, "first"))
			if e != nil {
				t.Fatal(e)
			}
			if e := tx.activate(ctx, first); e != nil {
				t.Fatal(e)
			}
			if e := tx.Close(); e != nil {
				t.Fatal(e)
			}
			ready := filepath.Join(t.TempDir(), "ready")
			childCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestActivationProcessHelper$")
			cmd.Env = append(os.Environ(), "PACKTRACE_TEST_ACTIVATION_STORE="+path, "PACKTRACE_TEST_ACTIVATION_PHASE="+phase, "PACKTRACE_TEST_ACTIVATION_READY="+ready)
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
			var r struct {
				PID int
				ID  ID
			}
			for {
				data, e := os.ReadFile(ready)
				if e == nil {
					if json.Unmarshal(data, &r) != nil || r.PID != cmd.Process.Pid {
						t.Fatal("readiness identity")
					}
					break
				}
				if childCtx.Err() != nil {
					t.Fatal("child not ready")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if e := cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			if e := cmd.Wait(); e == nil || cmd.ProcessState == nil {
				t.Fatal("kill/reap not confirmed")
			}
			waited = true
			record, fallback, e := s.readSelection(ctx)
			if e != nil || fallback {
				t.Fatal("crash lost selected complete generation", e)
			}
			got, e := parseID(record.Current)
			if e != nil {
				t.Fatal(e)
			}
			if (phase == "pending" || phase == "sealed") && got != first || phase == "activated" && got != r.ID {
				t.Fatal("crash rebound incomplete/old generation")
			}
		})
	}
}
