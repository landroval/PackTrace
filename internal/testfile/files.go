// Package testfile provides bounded authored-fixture I/O for tests only.
// It is not product admission, adoption, or an untrusted-path API.
package testfile

import (
	"errors"
	"io"
)

// These helpers do not create/adopt files or alter sharing/security of product
// handles. They read or corrupt an existing authored regular fixture while its
// original native capability remains retained, instead of closing that proof.
func Read(path string) (data []byte, failure error) {
	f, e := OpenExisting(path, false)
	if e != nil {
		return nil, e
	}
	defer func() { failure = errors.Join(failure, f.Close()) }()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.Join(errors.New("testfile: not-small-regular-file"), e)
	}
	data, e = io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if len(data) > 1<<20 {
		return nil, errors.New("testfile: limit")
	}
	return data, e
}
func Overwrite(path string, data []byte) (failure error) {
	if len(data) > 1<<20 {
		return errors.New("testfile: limit")
	}
	f, e := OpenExisting(path, true)
	if e != nil {
		return e
	}
	defer func() { failure = errors.Join(failure, f.Close()) }()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return errors.Join(errors.New("testfile: not-regular-file"), e)
	}
	if e := f.Truncate(int64(len(data))); e != nil {
		return e
	}
	if _, e := f.Write(data); e != nil {
		return e
	}
	return f.Sync()
}
