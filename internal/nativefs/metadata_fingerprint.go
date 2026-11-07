package nativefs

import (
	"crypto/sha256"
	"encoding/binary"
)

// Fingerprint commits a successful live original/binding observation. It is
// not a lease, content digest or permission to mutate an ordinary target Root.
func (m *MetadataLease) Fingerprint() ([32]byte, error) {
	if e := m.Stable(); e != nil {
		return [32]byte{}, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.object == nil {
		return [32]byte{}, ErrClosed
	}
	s := m.object.initial
	hash := sha256.New()
	hash.Write([]byte("PackTrace native metadata v1\x00"))
	hash.Write([]byte(m.name))
	hash.Write([]byte{0})
	hash.Write([]byte(m.object.target))
	hash.Write([]byte{0})
	var scalar [8]byte
	for _, v := range []uint64{s.dev, s.ino, uint64(s.mode), uint64(s.size), uint64(s.mtSec), uint64(s.mtNS), uint64(s.ctSec), uint64(s.ctNS), s.links} {
		binary.LittleEndian.PutUint64(scalar[:], v)
		hash.Write(scalar[:])
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}
