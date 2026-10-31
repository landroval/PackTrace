package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Only the trusted harness supplies these fixed literal/fixed swap operations.
// Neither operation is reachable through caller/observer path or command input.
type caseMutator struct {
	write func(string) error
	swap  func(bool) error
}

func (m caseMutator) before(id byte) error {
	if id == 5 {
		return m.swap(true)
	}
	return nil
}
func (m caseMutator) after(id byte) error {
	if id == 2 {
		return m.write(literalB)
	}
	if id == 5 {
		return m.swap(false)
	}
	return nil
}
func (m caseMutator) done(id byte) error {
	if id == 2 {
		return m.write(literalA)
	}
	return nil
}

func canUnlink(actual Sample, expected []Sample) bool {
	for _, s := range expected {
		if s.Inode != 0 && sameObject(actual, s) && actual.Mode&0170000 == s.Mode&0170000 && (actual.Mode&0170000 == 0040000 || actual.Nlink == 1) {
			return true
		}
	}
	return false
}
func openEvidence(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid-output-root")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, errors.New("aliased-output-root")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if rel, err := filepath.Rel(cwd, path); err == nil && rel != ".." && !filepath.IsAbs(rel) && (rel == "." || len(rel) < 3 || rel[:3] != ".."+string(os.PathSeparator)) {
		return nil, errors.New("output-under-working-tree")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !ok || int(stat.Uid) != os.Getuid() {
		return nil, errors.New("nonprivate-output-root")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	now, err := f.Stat()
	if err != nil || !os.SameFile(info, now) {
		f.Close()
		return nil, errors.New("changed-output-root")
	}
	names, err := f.Readdirnames(1)
	if len(names) != 0 || err != io.EOF {
		f.Close()
		return nil, errors.New("nonempty-output-root")
	}
	return f, nil
}
func exchange(r io.Reader, w io.Writer, key token, receipt *Receipt, before, after func(byte) error, done func(byte, Observation) error) error {
	for id := byte(1); id <= 5; id++ {
		if err := writeFrame(w, key, frame{Op: opBegin, ID: id}); err != nil {
			return err
		}
		ready, err := readFrame(r, key, opReady, id)
		if err != nil {
			return err
		}
		if err = before(id); err != nil {
			return err
		}
		if err = writeFrame(w, key, frame{Op: opClone, ID: id}); err != nil {
			return err
		}
		cloned, err := readFrame(r, key, opCloned, id)
		if err != nil {
			return err
		}
		if err = after(id); err != nil {
			return err
		}
		if err = writeFrame(w, key, frame{Op: opInspect, ID: id}); err != nil {
			return err
		}
		result, err := readFrame(r, key, opResult, id)
		if err != nil {
			return err
		}
		o := result.Observation
		if ready.Observation.Before != o.Before || cloned.Observation.Errno != o.Errno || cloned.Observation.AtClone != o.AtClone {
			return errors.New("inconsistent-observation")
		}
		receipt.Cases[id-1] = classify(id, o)
		if err = done(id, o); err != nil {
			return err
		}
	}
	var extra [1]byte
	n, err := r.Read(extra[:])
	if n != 0 || err != io.EOF {
		return errors.New("trailing-worker-output")
	}
	return nil
}
