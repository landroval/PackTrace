package main

import (
	"errors"
	"io"
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

type storageObservation struct {
	stage string
	err   error
}

func (e *storageObservation) Error() string { return "owned-storage-observation" }
func (e *storageObservation) Unwrap() error { return e.err }

func treeBytes(root string) (int64, error) {
	var total int64
	var walk func(string, bool) error
	walk = func(name string, first bool) (err error) {
		dir, e := openStorageDirectory(name)
		if errors.Is(e, fs.ErrNotExist) {
			return nil
		}
		if e != nil {
			return &storageObservation{"directory-open", e}
		}
		defer func() {
			if e := dir.Close(); e != nil {
				err = errors.Join(err, &storageObservation{"directory-close", e})
			}
		}()
		info, e := dir.Stat()
		if e != nil {
			return &storageObservation{"directory-stat", e}
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errStorageType
		}
		if first {
			total += info.Size()
			if total > 2<<30 {
				return errStorageLimit
			}
		}
		for {
			entries, readErr := dir.ReadDir(64)
			for _, entry := range entries {
				child := filepath.Join(name, entry.Name())
				n, e := storageEntryBytes(child, entry, nil)
				if e != nil {
					return &storageObservation{"entry-info", e}
				}
				total += n
				if total > 2<<30 {
					return errStorageLimit
				}
				if entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
					if e := walk(child, false); e != nil {
						return e
					}
				}
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if readErr != nil {
				return &storageObservation{"directory-read", readErr}
			}
		}
	}
	e := walk(root, true)
	return total, e
}
