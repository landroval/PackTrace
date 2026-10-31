//go:build darwin && arm64

package main

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"runtime"
	"runtime/debug"

	"golang.org/x/sys/unix"
)

// Header-reviewed, not exported by x/sys v0.44.0. Apple XNU xnu-11215.1.10,
// bsd/sys/clonefile.h:36; SHA256 c997483d78d303ac7d695ef9cf1848915ab3bde60b024d73080c7204a42326d8.
// https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.1.10/bsd/sys/clonefile.h
// The pin is a source reference, NOT a claim about the installed kernel.
const cloneNoFollowAny = 0x8
const cloneFlags = cloneNoFollowAny | unix.CLONE_NOOWNERCOPY

func actualEnvironment() Environment {
	e := Environment{OS: runtime.GOOS, Arch: runtime.GOARCH, Go: runtime.Version(), UID: os.Getuid(), API: "clonefileat", Flags: cloneFlags}
	if b, ok := debug.ReadBuildInfo(); ok {
		for _, s := range b.Settings {
			if s.Key == "CGO_ENABLED" {
				e.CGO = s.Value
			}
		}
	}
	e.OSVersion, _ = unix.Sysctl("kern.osproductversion")
	e.OSBuild, _ = unix.Sysctl("kern.osversion")
	e.Kernel, _ = unix.Sysctl("kern.osrelease")
	// Kernel strings are metadata, not an unbounded diagnostic channel.
	if len(e.OSVersion) > 64 || len(e.OSBuild) > 64 || len(e.Kernel) > 128 {
		e.OSVersion = ""
		e.OSBuild = ""
		e.Kernel = ""
	}
	return e
}
func sample(s unix.Stat_t) Sample {
	return Sample{Device: uint64(uint32(s.Dev)), Inode: s.Ino, CtimeSec: s.Ctim.Sec, CtimeNsec: s.Ctim.Nsec, Nlink: uint64(s.Nlink), Mode: uint32(s.Mode), Size: s.Size}
}
func sampleAt(dir *os.File, name string) (Sample, error) {
	var s unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), name, &s, unix.AT_SYMLINK_NOFOLLOW)
	return sample(s), err
}
func sampleFD(f *os.File) (Sample, error) {
	var s unix.Stat_t
	err := unix.Fstat(int(f.Fd()), &s)
	return sample(s), err
}
func plainFD(f *os.File, kind uint32) error {
	var s unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &s); err != nil {
		return err
	}
	perm := uint16(0600)
	if kind == unix.S_IFDIR {
		perm = 0700
	}
	if uint32(s.Mode)&unix.S_IFMT != kind || s.Mode&07777 != perm || int(s.Uid) != os.Getuid() || s.Flags != 0 {
		return errors.New("nonplain-owned-object")
	}
	n, err := unix.Flistxattr(int(f.Fd()), nil)
	if err != nil {
		return err
	}
	if n != 0 {
		return errors.New("unexpected-xattrs")
	}
	return nil
}
func openDirAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func observer() int {
	if !profileOK(actualEnvironment()) {
		return 2
	}
	src := os.NewFile(3, "owned-fixtures")
	stage := os.NewFile(4, "owned-stage")
	if src == nil || stage == nil {
		return 2
	}
	defer src.Close()
	defer stage.Close()
	if plainFD(src, unix.S_IFDIR) != nil || plainFD(stage, unix.S_IFDIR) != nil {
		return 2
	}
	a, err := sampleFD(src)
	if err != nil {
		return 2
	}
	b, err := sampleFD(stage)
	if err != nil || a.Device != b.Device || sameObject(a, b) {
		return 2
	}
	key, err := inheritedToken()
	if err != nil {
		return 2
	}
	if observe(src, stage, key) != nil {
		return 2
	}
	return 0
}
func observe(src, stage *os.File, key token) error {
	for id := byte(1); id <= 5; id++ {
		if _, err := readFrame(os.Stdin, key, opBegin, id); err != nil {
			return err
		}
		name := "source"
		if id == 3 {
			name = "link"
		}
		if id == 4 {
			// This is ONE known literal component, not a production link resolver.
			var target [7]byte
			n, err := unix.Readlinkat(int(src.Fd()), "link", target[:])
			if err != nil || string(target[:n]) != "source" {
				return errors.New("unexpected-owned-link")
			}
		}
		var o Observation
		var err error
		o.Before, err = sampleAt(src, name)
		if err != nil {
			return err
		}
		if err = writeFrame(os.Stdout, key, frame{Op: opReady, ID: id, Observation: o}); err != nil {
			return err
		}
		if _, err = readFrame(os.Stdin, key, opClone, id); err != nil {
			return err
		}
		if _, err = sampleAt(stage, "C"); err != unix.ENOENT {
			return errors.New("destination-not-fresh")
		}
		err = unix.Clonefileat(int(src.Fd()), name, int(stage.Fd()), "C", cloneFlags)
		if err != nil {
			var errno unix.Errno
			if !errors.As(err, &errno) {
				return errors.New("non-errno-clone-error")
			}
			o.Errno = uint32(errno)
		}
		o.AtClone, err = sampleAt(src, name)
		if err != nil {
			return err
		}
		if err = writeFrame(os.Stdout, key, frame{Op: opCloned, ID: id, Observation: o}); err != nil {
			return err
		}
		if _, err = readFrame(os.Stdin, key, opInspect, id); err != nil {
			return err
		}
		o.After, err = sampleAt(src, name)
		if err != nil {
			return err
		}
		o.Destination, err = sampleAt(stage, "C")
		if err != nil && err != unix.ENOENT {
			return err
		}
		if err == nil && regular(o.Destination) {
			// No source open/read/hash. Only classify-then-open the exclusively owned C.
			fd, err := unix.Openat(int(stage.Fd()), "C", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			c := os.NewFile(uintptr(fd), "C")
			s, err := sampleFD(c)
			if err != nil || !sameObject(s, o.Destination) || plainFD(c, unix.S_IFREG) != nil {
				c.Close()
				return errors.New("changed-destination")
			}
			data, err := io.ReadAll(io.LimitReader(c, int64(len(literalA)+1)))
			c.Close()
			if err != nil {
				return err
			}
			o.Bytes = int64(len(data))
			o.Digest = sha256.Sum256(data)
		}
		if err = writeFrame(os.Stdout, key, frame{Op: opResult, ID: id, Observation: o}); err != nil {
			return err
		}
	}
	return nil
}
