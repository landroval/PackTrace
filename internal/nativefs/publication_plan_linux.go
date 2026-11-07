//go:build linux && (amd64 || arm64)

package nativefs

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sort"
)

func publicationPlanAvailable() error { return nil }

// Framed native coordinates; common ancestors carry identity only, since
// unrelated siblings may legitimately mutate them. Private branches carry the
// exact checked epoch stamps. No process descriptor numbers or path strings.
func planWord(h hash.Hash, n uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	h.Write(b[:])
}
func planChain(h hash.Hash, chain []ancestor) {
	planWord(h, uint64(len(chain)))
	for i, a := range chain {
		s := a.initial
		planWord(h, s.dev)
		planWord(h, s.ino)
		if i == len(chain)-1 {
			continue
		}
		planWord(h, uint64(s.mode))
		planWord(h, uint64(s.size))
		planWord(h, uint64(s.mtSec))
		planWord(h, uint64(s.mtNS))
		planWord(h, uint64(s.ctSec))
		planWord(h, uint64(s.ctNS))
		planWord(h, s.links)
	}
}
func planSeparation(h hash.Hash, s *separation) error {
	if s == nil || len(s.external) < 2 || len(s.investigated) < 2 {
		return ErrPath
	}
	// Chains ending at a source/output root would admit an ancestor. Plans
	// require strict disjointness, unlike historical publication admission.
	planWord(h, s.mount)
	planChain(h, s.external)
	planChain(h, s.investigated)
	return nil
}
func publicationPlanBinding(p *Publication) (string, error) {
	if e := p.ctx.Err(); e != nil {
		return "", e
	}
	_, release, e := p.lockSources()
	if e != nil {
		return "", e
	}
	defer release()
	parents := []*Root{p.parent}
	for _, x := range p.exclusions {
		parents = append(parents, x.parent)
	}
	receipts := make([]string, 0, len(parents))
	for _, r := range parents {
		if e := r.native.guard(); e != nil {
			return "", e
		}
		h := sha256.New()
		h.Write([]byte("packtrace-publication-coordinate-v1\x00"))
		if e := planSeparation(h, r.native.external); e != nil {
			return "", e
		}
		// Include the source's own external relationship (state/reference ->
		// target), not just the output/source common-ancestor cut.
		source := r.native.external.target
		if source.external != nil {
			planWord(h, 1)
			if e := planSeparation(h, source.external); e != nil {
				return "", e
			}
		} else {
			planWord(h, 0)
		}
		receipts = append(receipts, hex.EncodeToString(h.Sum(nil)))
	}
	// Leaf locking order is process-local; receipt order must not be.
	sort.Strings(receipts)
	h := sha256.New()
	h.Write([]byte("packtrace-publication-plan-v1\x00"))
	planWord(h, uint64(len(p.name)))
	h.Write([]byte(p.name))
	planWord(h, uint64(len(receipts)))
	for _, r := range receipts {
		h.Write([]byte(r))
	}
	return "sha256-" + hex.EncodeToString(h.Sum(nil)), nil
}
func publicationPlanSources(p *Publication) error {
	if e := p.ctx.Err(); e != nil {
		return e
	}
	_, release, e := p.lockSources()
	if e != nil {
		return e
	}
	defer release()
	parents := []*Root{p.parent}
	for _, x := range p.exclusions {
		parents = append(parents, x.parent)
	}
	for _, r := range parents {
		s := r.native.external
		if s == nil {
			return ErrUnavailable
		}
		id, e := s.target.mountID()
		if e != nil || id != s.mount {
			return ErrUnstable
		}
		if e := checkChain(s.target.root, s.investigated); e != nil {
			return e
		}
	}
	return nil
}
