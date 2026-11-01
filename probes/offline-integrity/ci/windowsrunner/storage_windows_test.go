//go:build windows && amd64

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStorageEnumerationCoexistsWithOwnedDeleteHandle(t *testing.T) {
	root := t.TempDir()
	if os.WriteFile(filepath.Join(root, "owned"), make([]byte, 37), 0600) != nil {
		t.Fatal("owned file")
	}
	name, e := syscall.UTF16PtrFromString(root)
	if e != nil {
		t.Fatal("path")
	}
	// Own DELETE access is enough to reproduce Go's default Open sharing conflict;
	// no deletion, privilege, security configuration or foreign handle is involved.
	h, e := syscall.CreateFile(name, 0x10000, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		t.Fatal("owned delete-access handle", e)
	}
	defer syscall.CloseHandle(h)
	if _, e = os.ReadDir(root); !errors.Is(e, syscall.Errno(32)) {
		t.Fatal("old directory-open sharing conflict not reproduced", e)
	}
	n, e := treeBytes(root)
	if e != nil || n < 37 {
		t.Fatal("paired storage enumeration failed or undercounted", n, e)
	}
	t.Logf("paired owned directory: ordinary ReadDir sharing violation=32; metadata enumeration succeeded; observed bytes=%d", n)
}
