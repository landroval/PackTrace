package intelstore

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"packtrace/internal/nativefs"
	"strings"
)

type bundleInput struct {
	ctx           context.Context
	file          *nativefs.File
	used, members uint64
	dirs          map[string]bool
	ended         bool
}

func (b *bundleInput) Read(p []byte) (int, error) {
	if e := b.ctx.Err(); e != nil {
		return 0, e
	}
	if b.used >= 16<<30 {
		return 0, ErrLimit
	}
	if uint64(len(p)) > (16<<30)-b.used {
		p = p[:(16<<30)-b.used]
	}
	n, e := b.file.Read(p)
	if n < 0 || n > len(p) {
		return 0, ErrCorrupt
	}
	b.used += uint64(n)
	return n, e
}
func zeroBytes(data []byte) bool {
	for _, c := range data {
		if c != 0 {
			return false
		}
	}
	return true
}
func octalField(data []byte) bool {
	data = bytes.Trim(data, " \x00")
	for _, c := range data {
		if c < '0' || c > '7' {
			return false
		}
	}
	return true
}
func (b *bundleInput) next() (*tar.Header, error) {
	for {
		if b.ended {
			return nil, io.EOF
		}
		var raw [512]byte
		if _, e := io.ReadFull(b, raw[:]); e != nil {
			return nil, ErrCorrupt
		}
		if zeroBytes(raw[:]) {
			var second [512]byte
			if _, e := io.ReadFull(b, second[:]); e != nil || !zeroBytes(second[:]) {
				return nil, ErrCorrupt
			}
			if b.used == 16<<30 {
				if e := b.file.Stable(); e != nil {
					return nil, ErrCorrupt
				}
			} else {
				var extra [1]byte
				n, e := b.Read(extra[:])
				if n != 0 || e != io.EOF {
					return nil, ErrCorrupt
				}
			}
			b.ended = true
			return nil, io.EOF
		}
		b.members++
		if b.members > 2_001_024 {
			return nil, ErrLimit
		}
		if string(raw[257:263]) != "ustar\x00" || string(raw[263:265]) != "00" || raw[156] != 0 && raw[156] != tar.TypeReg && raw[156] != tar.TypeDir || !zeroBytes(raw[157:257]) || !zeroBytes(raw[345:500]) {
			return nil, ErrCorrupt
		}
		for _, field := range [][]byte{raw[100:108], raw[108:116], raw[116:124], raw[124:136], raw[136:148], raw[148:156], raw[329:337], raw[337:345]} {
			if !octalField(field) {
				return nil, ErrCorrupt
			}
		}
		name := raw[:100]
		if at := bytes.IndexByte(name, 0); at >= 0 && !zeroBytes(name[at:]) {
			return nil, ErrCorrupt
		}
		header, e := tar.NewReader(bytes.NewReader(raw[:])).Next()
		if e != nil || header.Format != tar.FormatUSTAR || header.Size < 0 || header.Size > 512<<20 {
			return nil, ErrCorrupt
		}
		if header.Typeflag == tar.TypeDir {
			valid := header.Name == "objects/"
			if strings.HasPrefix(header.Name, "objects/") && len(header.Name) == 11 && header.Name[10] == '/' {
				key := header.Name[8:10]
				valid = true
				for _, c := range key {
					if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
						valid = false
					}
				}
			}
			if !valid || header.Size != 0 || b.dirs[header.Name] {
				return nil, ErrCorrupt
			}
			if b.dirs == nil {
				b.dirs = make(map[string]bool)
			}
			b.dirs[header.Name] = true
			continue
		}
		return header, nil
	}
}
func (b *bundleInput) padding(size uint64) error {
	n := (512 - size%512) % 512
	var data [512]byte
	if _, e := io.ReadFull(b, data[:n]); e != nil || !zeroBytes(data[:n]) {
		return ErrCorrupt
	}
	return nil
}
func (b *bundleInput) small(header *tar.Header, expected string, max uint64) ([]byte, error) {
	if header == nil || header.Name != expected || uint64(header.Size) > max {
		return nil, ErrCorrupt
	}
	data := make([]byte, int(header.Size))
	if _, e := io.ReadFull(b, data); e != nil {
		return nil, ErrCorrupt
	}
	if e := b.padding(uint64(header.Size)); e != nil {
		return nil, e
	}
	return data, nil
}
func (b *bundleInput) object(t *Transaction, header *tar.Header, name string, expected ObjectRef) (ObjectRef, error) {
	if header == nil || header.Name != name || uint64(header.Size) != expected.Bytes {
		return ObjectRef{}, ErrCorrupt
	}
	limited := &io.LimitedReader{R: b, N: header.Size}
	ref, e := t.put(t.work, limited, expected.Bytes)
	if e != nil || limited.N != 0 || ref != expected {
		return ObjectRef{}, ErrCorrupt
	}
	if e := b.padding(expected.Bytes); e != nil {
		return ObjectRef{}, e
	}
	return ref, nil
}
