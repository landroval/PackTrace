package integrity

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

var errReferenceArchive = errors.New("reference archive unusable")

type archiveMeter struct {
	ctx          context.Context
	source       io.Reader
	digest       hash.Hash
	count, limit int64
}

func (m *archiveMeter) Read(p []byte) (int, error) {
	if err := m.ctx.Err(); err != nil {
		return 0, errReferenceArchive
	}
	if m.count > m.limit {
		return 0, errReferenceArchive
	}
	if int64(len(p)) > m.limit-m.count+1 {
		p = p[:int(m.limit-m.count+1)]
	}
	n, e := m.source.Read(p)
	if n > 0 {
		m.count += int64(n)
		m.digest.Write(p[:n])
	}
	if m.count > m.limit {
		return n, errReferenceArchive
	}
	return n, e
}
func (m *archiveMeter) ReadByte() (byte, error) {
	var one [1]byte
	_, e := io.ReadFull(m, one[:])
	return one[0], e
}

type expandedMeter struct {
	source       io.Reader
	count, limit int64
	ctx          context.Context
}

func (m *expandedMeter) Read(p []byte) (int, error) {
	if m.ctx.Err() != nil || m.count > m.limit {
		return 0, errReferenceArchive
	}
	if int64(len(p)) > m.limit-m.count+1 {
		p = p[:int(m.limit-m.count+1)]
	}
	n, e := m.source.Read(p)
	m.count += int64(n)
	if m.count > m.limit {
		return n, errReferenceArchive
	}
	return n, e
}

// InspectReferenceArchive checks a caller-supplied gzip USTAR package/ stream; it neither acquires nor authenticates its source.
// Invalid streams expose counters only; no partially usable entries escape.
func InspectReferenceArchive(ctx context.Context, b ReferenceBinding, r io.Reader, l Limits) (result ReferenceCatalog, err error) {
	if ctx == nil || r == nil || !b.usable || b.instanceID == "" || len(b.expectedDigests) == 0 {
		return result, errReferenceArchive
	}
	l, e := normalizedLimits(l)
	if e != nil {
		return result, errReferenceArchive
	}
	name, _, digest, ok := parseDigestToken(b.selectedToken)
	if !ok || name != b.selectedAlgorithm {
		return result, errReferenceArchive
	}
	limit := min(l.CompressedBytes, l.ReferenceReadBytes)
	compressed := &archiveMeter{ctx: ctx, source: r, digest: digest, limit: limit}
	defer func() { result.CompressedRead = compressed.count }()
	gz, e := gzip.NewReader(compressed)
	if e != nil {
		return result, errReferenceArchive
	}
	gz.Multistream(false)
	expanded := &expandedMeter{source: gz, ctx: ctx, limit: min(l.ExpandedBytes, l.AggregateExpandedBytes)}
	defer func() { result.ExpandedRead = expanded.count }()
	entries := make([]ReferenceEntry, 0)
	type node struct {
		spelling       string
		explicit, file bool
	}
	seen := make(map[string]node)
	var names int64
	var block [512]byte
	for {
		if _, e = io.ReadFull(expanded, block[:]); e != nil {
			return result, errReferenceArchive
		}
		if bytes.Equal(block[:], make([]byte, 512)) {
			if _, e = io.ReadFull(expanded, block[:]); e != nil || !bytes.Equal(block[:], make([]byte, 512)) {
				return result, errReferenceArchive
			}
			var one [1]byte
			if n, readErr := expanded.Read(one[:]); n != 0 || readErr != io.EOF {
				return result, errReferenceArchive
			}
			if n, readErr := compressed.Read(one[:]); n != 0 || readErr != io.EOF {
				return result, errReferenceArchive
			}
			observed := digest.Sum(nil)
			match := false
			for _, expected := range b.expectedDigests {
				if subtle.ConstantTimeCompare(observed, expected) == 1 {
					match = true
				}
			}
			if !match {
				return result, errReferenceArchive
			}
			result.instanceID = b.instanceID
			result.bindingFingerprint = b.fingerprint
			result.entries = entries
			result.verified = true
			return result, nil
		}
		if len(entries) >= l.Entries || !validUSTAR(block[:]) {
			return result, errReferenceArchive
		}
		raw := tarText(block[0:100])
		prefix := tarText(block[345:500])
		if prefix != "" {
			raw = prefix + "/" + raw
		}
		typ := block[156]
		if typ != '0' && typ != 0 && typ != '5' {
			return result, errReferenceArchive
		}
		size, valid := tarOctal(block[124:136])
		if !valid || size > l.FileBytes || (typ == '5' && size != 0) {
			return result, errReferenceArchive
		}
		path, valid := archiveName(raw, typ == '5', l)
		if !valid {
			return result, errReferenceArchive
		}
		names += int64(len(raw))
		if names > l.TotalNameBytes {
			return result, errReferenceArchive
		}
		key := strings.ToLower(path)
		old := seen[key]
		if old.explicit || old.file || (old.spelling != "" && (old.spelling != path || typ != '5')) {
			return result, errReferenceArchive
		}
		isFile := typ != '5'
		seen[key] = node{path, true, isFile}
		parts := strings.Split(path, "/")
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[:i], "/")
			k := strings.ToLower(parent)
			n := seen[k]
			if n.file || (n.spelling != "" && n.spelling != parent) {
				return result, errReferenceArchive
			}
			if n.spelling == "" {
				seen[k] = node{spelling: parent}
			}
		}
		entryName := strings.TrimPrefix(path, "package/")
		if path == "package" {
			entryName = ""
		} // envelope only; package/package remains package
		entry := ReferenceEntry{EntryID: strconv.Itoa(len(entries) + 1), Name: entryName, Size: size, Type: EntryDirectory}
		if isFile {
			entry.Type = EntryFile
			h := sha256.New()
			if e = archiveCopy(expanded, h, size); e != nil {
				return result, errReferenceArchive
			}
			copy(entry.SHA256[:], h.Sum(nil))
		}
		padding := (512 - size%512) % 512
		if padding > 0 {
			var pad [512]byte
			if _, e = io.ReadFull(expanded, pad[:padding]); e != nil || !bytes.Equal(pad[:padding], make([]byte, int(padding))) {
				return result, errReferenceArchive
			}
		}
		entries = append(entries, entry)
	}
}
func archiveCopy(r io.Reader, h hash.Hash, size int64) error {
	var buf [32 * 1024]byte
	for size > 0 {
		n, e := io.ReadFull(r, buf[:min(size, int64(len(buf)))])
		if n > 0 {
			h.Write(buf[:n])
			size -= int64(n)
		}
		if e != nil {
			return errReferenceArchive
		}
	}
	return nil
}
func tarText(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
func tarOctal(b []byte) (int64, bool) {
	if len(b) == 0 || b[0]&128 != 0 {
		return 0, false
	}
	s := strings.TrimRight(strings.TrimLeft(string(b), " "), " \x00")
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, false
		}
	}
	n, e := strconv.ParseInt(s, 8, 64)
	return n, e == nil && n >= 0
}
func validUSTAR(b []byte) bool {
	if string(b[257:263]) != "ustar\x00" || string(b[263:265]) != "00" {
		return false
	}
	sum, ok := tarOctal(b[148:156])
	if !ok {
		return false
	}
	var actual int64
	for i, v := range b {
		if i >= 148 && i < 156 {
			actual += 32
		} else {
			actual += int64(v)
		}
	}
	if actual != sum {
		return false
	}
	// Stdlib validates all USTAR metadata, not merely the checksum. Keep this
	// first profile octal-only; blank optional fields retain stdlib semantics.
	if _, err := tar.NewReader(bytes.NewReader(b)).Next(); err != nil {
		return false
	}
	for _, field := range [][]byte{b[100:108], b[108:116], b[116:124], b[136:148], b[329:337], b[337:345]} {
		if strings.Trim(string(field), " \x00") != "" {
			if _, ok := tarOctal(field); !ok {
				return false
			}
		}
	}
	for _, field := range [][]byte{b[:100], b[157:257], b[265:297], b[297:329], b[345:500]} {
		if i := bytes.IndexByte(field, 0); i >= 0 {
			for _, v := range field[i:] {
				if v != 0 {
					return false
				}
			}
		}
	}
	return true
}
func archiveName(raw string, dir bool, l Limits) (string, bool) {
	if int64(len(raw)) > l.NameBytes || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\\:\x00<>\"|?*") || strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "", false
	}
	if dir {
		if !strings.HasSuffix(raw, "/") {
			return "", false
		}
		raw = strings.TrimSuffix(raw, "/")
	} else if strings.HasSuffix(raw, "/") {
		return "", false
	}
	parts := strings.Split(raw, "/")
	if len(parts) > l.PathDepth+1 || parts[0] != "package" || len(parts) == 1 && !dir {
		return "", false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.HasSuffix(p, ".") || strings.HasSuffix(p, " ") {
			return "", false
		}
		for _, r := range p {
			if r < 32 || r > 126 {
				return "", false
			}
		}
		stem := strings.ToUpper(strings.SplitN(p, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9' {
			return "", false
		}
	}
	return raw, true
}
