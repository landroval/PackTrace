//go:build linux && (amd64 || arm64)

package nativefs

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type processReceipt struct {
	Bytes    string
	Stable   bool
	Complete bool
	RSS      uint64
}

func TestLinuxOwnedProcessAcquisition(t *testing.T) {
	d := t.TempDir()
	if os.WriteFile(filepath.Join(d, "a"), []byte("abc"), 0600) != nil {
		t.Fatal("setup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLinuxOwnedProcessObserver$", "-test.count=1")
	cmd.Env = []string{"PACKTRACE_OWNED_NATIVE_UNIT=" + d}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		t.Fatal("owned observer did not exit normally", err)
	}
	if out.Len() > 4096 {
		t.Fatal("unexpected test evidence size")
	}
	var p processReceipt
	if json.Unmarshal(out.Bytes(), &p) != nil || p.Bytes != "abc" || !p.Stable || !p.Complete || p.RSS == 0 {
		t.Fatal("invalid process acquisition receipt")
	}
}
func TestLinuxOwnedProcessObserver(t *testing.T) {
	d := os.Getenv("PACKTRACE_OWNED_NATIVE_UNIT")
	if d == "" {
		t.Skip("private unit observer")
	}
	result := processReceipt{}
	if PrepareProcess() == nil {
		r, err := OpenRoot(context.Background(), d)
		if err == nil {
			f, e := r.OpenRegular(context.Background(), "a", 3)
			if e == nil {
				b, re := io.ReadAll(f)
				result.Bytes = string(b)
				result.Stable = re == nil && f.Stable() == nil
				f.Close()
			}
			s, se := r.Snapshot(context.Background(), Limits{FileBytes: 8, TotalBytes: 32, Entries: 4, Depth: 2})
			result.Complete = se == nil && s.Complete && len(s.Entries) == 1
			result.RSS, _ = OwnResidentBytes()
			r.Close()
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
	os.Exit(0)
}
