//go:build !windows

package main

import (
	"os"
	"syscall"
)

func openStorageDirectory(name string) (*os.File, error) {
	fd, e := syscall.Open(name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), name), nil
}
