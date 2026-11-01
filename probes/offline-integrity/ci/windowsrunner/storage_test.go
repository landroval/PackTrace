package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type storageInfoEntry struct {
	fs.DirEntry
	info fs.FileInfo
	err  error
}

func (e storageInfoEntry) Info() (fs.FileInfo, error) { return e.info, e.err }

type storageModeInfo struct {
	fs.FileInfo
	mode fs.FileMode
}

func (i storageModeInfo) Mode() fs.FileMode { return i.mode }

func TestStorageCountsEnumeratedMetadataWithoutReopening(t *testing.T) {
	name := filepath.Join(t.TempDir(), "owned")
	if os.WriteFile(name, []byte("12345678"), 0600) != nil {
		t.Fatal("fixture write")
	}
	info, e := os.Lstat(name)
	if e != nil {
		t.Fatal("fixture stat")
	}
	entry := fs.FileInfoToDirEntry(info)
	if os.Remove(name) != nil {
		t.Fatal("fixture release")
	}
	// A Windows directory enumeration already supplies metadata, including for
	// entries that cannot be reopened with Lstat's sharing mode. The path below
	// is deliberately unavailable: a second lookup either skips or fails.
	size, e := storageEntryBytes(name, entry, nil)
	if e != nil || size != 8 {
		t.Fatalf("enumerated size lost to another path lookup: bytes=%d error=%v", size, e)
	}
	sharing := syscall.Errno(32)
	if _, e = storageEntryBytes(name, storageInfoEntry{DirEntry: entry, err: sharing}, nil); !errors.Is(e, sharing) {
		t.Fatal("metadata error was hidden")
	}
	if _, e = storageEntryBytes(name, entry, sharing); !errors.Is(e, sharing) {
		t.Fatal("directory observation error was hidden")
	}
	bad := storageModeInfo{FileInfo: info, mode: os.ModeDevice}
	if _, e = storageEntryBytes(name, storageInfoEntry{DirEntry: entry, info: bad}, nil); !errors.Is(e, errStorageType) {
		t.Fatal("unsupported type admitted")
	}
	link := storageModeInfo{FileInfo: info, mode: os.ModeSymlink}
	if n, e := storageEntryBytes(name, storageInfoEntry{DirEntry: entry, info: link}, nil); e != nil || n != 8 {
		t.Fatal("link metadata not accounted without following")
	}
}

func TestStorageTreeCountsAllOwnedRegularBytes(t *testing.T) {
	root := t.TempDir()
	if os.Mkdir(filepath.Join(root, "nested"), 0700) != nil {
		t.Fatal("fixture directory")
	}
	if os.WriteFile(filepath.Join(root, "a"), make([]byte, 13), 0600) != nil || os.WriteFile(filepath.Join(root, "nested", "b"), make([]byte, 19), 0600) != nil {
		t.Fatal("fixture files")
	}
	n, e := treeBytes(root)
	if e != nil || n < 32 {
		t.Fatal("owned tree undercount", n, e)
	}
}
