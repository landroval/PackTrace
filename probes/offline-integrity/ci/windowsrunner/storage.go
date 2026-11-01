package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

func storageEntryBytes(path string, d fs.DirEntry, walkErr error) (int64, error) {
	if errors.Is(walkErr, fs.ErrNotExist) {
		return 0, nil
	}
	if walkErr != nil {
		return 0, walkErr
	}
	// Go 1.27.1 os/dir_windows.go stores the native directory record in
	// DirEntry.Info. Re-Lstat can open a reparse point with share mode zero,
	// conflicting with the very owned descriptor under test. Use the existing
	// no-follow enumeration metadata; never turn an Info/read-dir error to zero.
	info, e := d.Info()
	if errors.Is(e, fs.ErrNotExist) {
		return 0, nil
	}
	if e != nil {
		return 0, e
	}
	m := info.Mode()
	if !m.IsRegular() && !m.IsDir() && m&os.ModeSymlink == 0 {
		return 0, errStorageType
	}
	return info.Size(), nil
}

func treeBytes(root string) (int64, error) {
	var total int64
	e := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		n, e := storageEntryBytes(path, d, err)
		if e != nil {
			return e
		}
		total += n
		if total > 2<<30 {
			return errStorageLimit
		}
		return nil
	})
	return total, e
}
