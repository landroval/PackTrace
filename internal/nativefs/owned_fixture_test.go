package nativefs

import (
	"errors"
	"io"
)

// These helpers do not create/adopt files or alter sharing/security of product
// handles. They read or corrupt an existing authored regular fixture while its
// original native capability remains retained, instead of closing that proof.
func readOwnedFixture(path string) (data []byte, failure error) {
	f, e := openOwnedFixture(path, false)
	if e != nil {
		return nil, e
	}
	defer func() { failure = errors.Join(failure, f.Close()) }()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.Join(ErrType, e)
	}
	data, e = io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if len(data) > 1<<20 {
		return nil, ErrLimit
	}
	return data, e
}
func writeOwnedFixture(path string, data []byte) (failure error) {
	if len(data) > 1<<20 {
		return ErrLimit
	}
	f, e := openOwnedFixture(path, true)
	if e != nil {
		return e
	}
	defer func() { failure = errors.Join(failure, f.Close()) }()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return errors.Join(ErrType, e)
	}
	if e := f.Truncate(int64(len(data))); e != nil {
		return e
	}
	if _, e := f.Write(data); e != nil {
		return e
	}
	return f.Sync()
}
