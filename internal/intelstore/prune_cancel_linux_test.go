//go:build linux && (amd64 || arm64)

package intelstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPruneLateStageAdditionPreservesFinalOwnershipJournal(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	tx, e := s.begin(ctx, operationImport, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	stage := tx.path
	for i := 0; i < 128; i++ {
		if _, e := tx.put(ctx, bytes.NewReader([]byte("owned-duplicate")), 15); e != nil {
			t.Fatal(e)
		}
	}
	tx.Close()
	preview, e := s.PreviewPrune(ctx)
	if e != nil {
		t.Fatal(e)
	}
	fd, e := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if e != nil {
		t.Fatal(e)
	}
	watch := os.NewFile(uintptr(fd), "")
	defer watch.Close()
	if _, e := syscall.InotifyAddWatch(fd, filepath.Join(path, filepath.FromSlash(stage)), syscall.IN_MOVED_FROM); e != nil {
		t.Fatal(e)
	}
	added := make(chan error, 1)
	late := filepath.Join(path, filepath.FromSlash(stage), "object-ffffffffffffffff")
	go func() {
		var data [8192]byte
		count := 0
		for {
			n, e := watch.Read(data[:])
			if e != nil {
				added <- e
				return
			}
			for at := 0; at+16 <= n; {
				length := int(binary.LittleEndian.Uint32(data[at+12 : at+16]))
				if at+16+length > n {
					added <- ErrCorrupt
					return
				}
				if binary.LittleEndian.Uint32(data[at+4:at+8])&syscall.IN_MOVED_FROM != 0 {
					count++
					if count == 2 {
						added <- os.WriteFile(late, []byte("late"), 0600)
						return
					}
				}
				at += 16 + length
			}
		}
	}()
	result, e := s.ApplyPrune(ctx, preview.Token)
	if addErr := <-added; addErr != nil {
		t.Fatal(addErr)
	}
	if e == nil || !result.Partial {
		t.Fatal("late stage payload lost its required ownership journal", e)
	}
	if raw, e := os.ReadFile(late); e != nil || string(raw) != "late" {
		t.Fatal("late payload changed", e)
	}
	if _, e := os.Stat(filepath.Join(path, filepath.FromSlash(stage), "intent.json")); e != nil {
		t.Fatal("ownership journal removed before late payload", e)
	}
}

func TestPruneCancellationPreservesStageOwnershipAndPartialProgress(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	tx, e := s.begin(ctx, operationImport, &Budget{StagingBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	stage := tx.path
	for i := 0; i < 128; i++ {
		if _, e := tx.put(ctx, bytes.NewReader([]byte("owned-duplicate")), 15); e != nil {
			t.Fatal(e)
		}
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	preview, e := s.PreviewPrune(ctx)
	if e != nil {
		t.Fatal(e)
	}
	fd, e := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if e != nil {
		t.Fatal(e)
	}
	watch := os.NewFile(uintptr(fd), "")
	defer watch.Close()
	if _, e := syscall.InotifyAddWatch(fd, filepath.Join(path, filepath.FromSlash(stage)), syscall.IN_MOVED_FROM); e != nil {
		t.Fatal(e)
	}
	work, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	observed := make(chan bool, 1)
	go func() {
		var data [8192]byte
		count := 0
		for {
			n, e := watch.Read(data[:])
			if e != nil {
				observed <- false
				return
			}
			for at := 0; at+16 <= n; {
				length := int(binary.LittleEndian.Uint32(data[at+12 : at+16]))
				mask := binary.LittleEndian.Uint32(data[at+4 : at+8])
				if at+16+length > n {
					observed <- false
					return
				}
				if mask&syscall.IN_MOVED_FROM != 0 {
					count++
					if count == 2 {
						cancel()
						observed <- true
						return
					}
				}
				at += 16 + length
			}
		}
	}()
	result, e := s.ApplyPrune(work, preview.Token)
	if e == nil || !errors.Is(e, context.Canceled) || !result.Partial || result.RemovedFiles == 0 || result.RemovedBytes == 0 {
		watch.Close()
		t.Fatal("actual cancellation did not retain bounded partial accounting", result, e)
	}
	if !<-observed {
		t.Fatal("filesystem mutation not observed")
	}
	writer, e := s.pruneWriter(ctx)
	if e != nil {
		t.Fatal("partial cleanup lost remaining staging ownership evidence", e)
	}
	s.releasePruneWriter(writer)
}
