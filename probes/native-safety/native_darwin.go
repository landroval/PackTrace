//go:build darwin && arm64

package main

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type nativeState struct {
	root, src, stage, a, b *os.File
	directories            []Sample
	originals              []Sample
	link                   Sample
	attemptedClone         bool
}

func nativeRun(path string, r *Receipt) (code int) {
	// Defense in depth: no fixture creation before the actual native guard.
	if !profileOK(actualEnvironment()) {
		return finish(r, false)
	}
	// 11 maximum fixture entries, plus one external receipt; literal writes and
	// potential clones <=150 bytes, receipt reserved at 16KiB. No evidence files
	// are created in the supplied root. Binary/cache budgets belong to outer CI.
	if !plan(12, 150+16384) {
		r.Environment.Reason = "budget-rejected"
		return finish(r, true)
	}
	root, err := openEvidence(path)
	if err != nil {
		r.Environment.Reason = "invalid-evidence-directory"
		return finish(r, true)
	}
	defer root.Close()
	if err = plainFD(root, unix.S_IFDIR); err != nil {
		r.Environment.Reason = "nonplain-evidence-directory"
		return finish(r, false)
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(int(root.Fd()), &fs); err != nil {
		r.Environment.Reason = "filesystem-unavailable"
		return finish(r, false)
	}
	r.Environment.Filesystem = strings.TrimRight(string(fs.Fstypename[:]), "\x00")
	r.Environment.Mount = strings.TrimRight(string(fs.Mntonname[:]), "\x00")
	r.Environment.MountFlags = uint64(fs.Flags)
	if r.Environment.Filesystem != "apfs" || fs.Flags&unix.MNT_LOCAL == 0 || fs.Flags&unix.MNT_RDONLY != 0 {
		r.Environment.Reason = "unsupported-filesystem"
		return finish(r, false)
	}
	state := nativeState{root: root}
	fatal := false
	defer func() {
		if !r.Cleanup.WorkerReaped {
			r.Cleanup.Clean = false
			r.Cleanup.Residue = append(r.Cleanup.Residue, "unreaped-worker")
		} else {
			state.cleanup(&r.Cleanup)
		}
		for _, f := range []*os.File{state.a, state.b, state.src, state.stage} {
			if f != nil {
				f.Close()
			}
		}
		code = finish(r, fatal)
	}()
	if err = state.setup(); err != nil {
		r.Environment.Reason = "fixture-setup-failed"
		fatal = true
		return
	}
	s, err := sampleAt(state.src, "SOURCE")
	if err == unix.ENOENT {
		v := true
		r.Environment.CaseSensitive = &v
	} else if err == nil && sameObject(s, state.originals[0]) {
		v := false
		r.Environment.CaseSensitive = &v
	}
	executable, err := os.Executable()
	if err != nil {
		r.Environment.Reason = "self-executable-unavailable"
		fatal = true
		return
	}
	var key token
	if _, err = rand.Read(key[:]); err != nil || key == (token{}) {
		r.Environment.Reason = "capability-unavailable"
		fatal = true
		return
	}
	capR, capW, err := os.Pipe()
	if err != nil {
		r.Environment.Reason = "capability-pipe-failed"
		fatal = true
		return
	}
	defer capR.Close()
	n, err := capW.Write(key[:])
	capW.Close()
	if err != nil || n != len(key) {
		r.Environment.Reason = "capability-write-failed"
		fatal = true
		return
	}
	cmd := exec.Command(executable, "--observer")
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{state.src, state.stage, capR}
	mutator := caseMutator{write: func(data string) error { return overwrite(state.a, data) }, swap: func(in bool) error {
		first, second, third := "source", "held", "spare"
		if !in {
			first, second, third = "source", "spare", "held"
		}
		if err := unix.Renameat(int(state.src.Fd()), first, int(state.src.Fd()), second); err != nil {
			return err
		}
		return unix.Renameat(int(state.src.Fd()), third, int(state.src.Fd()), "source")
	}}
	before := func(id byte) error { state.attemptedClone = true; return mutator.before(id) }
	done := func(id byte, o Observation) error {
		want := state.originals[0]
		if id == 3 {
			want = state.link
		}
		if !sameObject(o.Before, want) || !sameObject(o.After, want) {
			return errors.New("unexpected-owned-source")
		}
		if id == 5 && !sameObject(o.AtClone, state.originals[1]) {
			return errors.New("unexpected-swap-source")
		}
		if err := state.cleanC(&o.Destination); err != nil {
			return err
		}
		return mutator.done(id)
	}
	session := childSession(cmd, func(reader io.Reader, writer io.Writer) error {
		return exchange(reader, writer, key, r, before, mutator.after, done)
	}, 10*time.Second)
	r.Cleanup.WorkerReaped = session.Reaped
	if session.Err != nil {
		fatal = true
		r.Environment.Reason = "observer-protocol-or-supervision-failed"
	} else {
		r.Environment.Reason = "controlled-cases-observed"
	}
	return
}
func overwrite(f *os.File, data string) error {
	if plainFD(f, unix.S_IFREG) != nil {
		return errors.New("nonplain-mutation-fd")
	}
	n, err := f.WriteAt([]byte(data), 0)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return f.Sync()
}
func (s *nativeState) setup() error {
	for _, name := range []string{"fixtures", "stage"} {
		if err := unix.Mkdirat(int(s.root.Fd()), name, 0700); err != nil {
			return err
		}
		identity, err := sampleAt(s.root, name)
		if err != nil {
			return err
		}
		s.directories = append(s.directories, identity)
		dir, err := openDirAt(s.root, name)
		if err != nil {
			return err
		}
		if name == "fixtures" {
			s.src = dir
		} else {
			s.stage = dir
		}
		if err = plainFD(dir, unix.S_IFDIR); err != nil {
			return err
		}
		rootSample, err := sampleFD(s.root)
		if err != nil || rootSample.Device != identity.Device {
			return errors.New("different-fixture-filesystem")
		}
	}
	for i, name := range []string{"source", "spare"} {
		fd, err := unix.Openat(int(s.src.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), name)
		if i == 0 {
			s.a = f
		} else {
			s.b = f
		}
		identity, err := sampleFD(f)
		if err != nil {
			return err
		}
		s.originals = append(s.originals, identity)
		data := literalA
		if i == 1 {
			data = literalB
		}
		if err = overwrite(f, data); err != nil {
			return err
		}
	}
	if err := unix.Symlinkat("source", int(s.src.Fd()), "link"); err != nil {
		return err
	}
	var err error
	s.link, err = sampleAt(s.src, "link")
	return err
}
func (s *nativeState) cleanC(expected *Sample) error {
	if s.stage == nil {
		return nil
	}
	actual, err := sampleAt(s.stage, "C")
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return err
	}
	// A fresh C can only have been created by the single owned clone operation.
	// On interrupted protocol, a reaped worker + private stage is its provenance.
	if !s.attemptedClone || (actual.Mode&unix.S_IFMT != unix.S_IFREG && actual.Mode&unix.S_IFMT != unix.S_IFLNK) || actual.Nlink != 1 {
		return errors.New("unknown-destination-residue")
	}
	if expected != nil && !canUnlink(actual, []Sample{*expected}) {
		return errors.New("changed-destination-residue")
	}
	return unix.Unlinkat(int(s.stage.Fd()), "C", 0)
}
func emptyOwned(dir *os.File) bool {
	f, err := openDirAt(dir, ".")
	if err != nil {
		return false
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	return len(names) == 0 && err == io.EOF
}
func (s *nativeState) cleanup(c *Cleanup) {
	residue := func(label string) { c.Clean = false; c.Residue = append(c.Residue, label) }
	if s.cleanC(nil) != nil {
		residue("stage-C")
	}
	if s.src != nil {
		allowed := append(append([]Sample(nil), s.originals...), s.link)
		for _, name := range []string{"source", "spare", "held", "link"} {
			actual, err := sampleAt(s.src, name)
			if err == unix.ENOENT {
				continue
			}
			if err != nil || !canUnlink(actual, allowed) || unix.Unlinkat(int(s.src.Fd()), name, 0) != nil {
				residue("fixture-artifact")
			}
		}
		if !emptyOwned(s.src) {
			residue("unknown-fixture-residue")
		}
	}
	if s.stage != nil && !emptyOwned(s.stage) {
		residue("unknown-stage-residue")
	}
	for i, name := range []string{"fixtures", "stage"} {
		actual, err := sampleAt(s.root, name)
		if err == unix.ENOENT {
			continue
		}
		if err != nil || i >= len(s.directories) || !canUnlink(actual, []Sample{s.directories[i]}) || unix.Unlinkat(int(s.root.Fd()), name, unix.AT_REMOVEDIR) != nil {
			residue("owned-directory")
		}
	}
	if !emptyOwned(s.root) {
		residue("unknown-root-residue")
	}
}
