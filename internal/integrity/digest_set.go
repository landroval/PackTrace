package integrity

import (
	"context"
	"crypto/subtle"
	"hash"
	"io"
	"strings"
)

// ReferenceDigestSetCheck describes digest equality, not identity or provenance.
type ReferenceDigestSetCheck struct {
	State           DigestState
	Algorithm       string
	ExpectedDigests [][]byte
	ObservedDigest  []byte
	BytesRead       int64
}

// CheckReferenceDigestSet checks a bounded, canonical SHA-2 token set.
// Every token must be supported; the strongest algorithm alone determines the verdict.
func CheckReferenceDigestSet(ctx context.Context, expectedSRI string, in io.Reader, maxBytes int64) (ReferenceDigestSetCheck, error) {
	var unknown ReferenceDigestSetCheck
	if ctx == nil || in == nil || maxBytes < 0 || maxBytes > 512*1024*1024 {
		return unknown, errDigestArgument
	}
	if len(expectedSRI) > 2048 {
		return unknown, nil
	}
	tokens := strings.FieldsFunc(expectedSRI, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' })
	if len(tokens) == 0 || len(tokens) > 16 {
		return unknown, nil
	}
	var algorithm string
	var expected [][]byte
	var selected hash.Hash
	rank := 0
	for _, token := range tokens {
		name, digest, h, ok := parseDigestToken(token)
		if !ok {
			return unknown, nil
		}
		strength := 1
		if name == "sha384" {
			strength = 2
		} else if name == "sha512" {
			strength = 3
		}
		if strength > rank {
			rank = strength
			algorithm = name
			expected = nil
			selected = h
		}
		if strength == rank {
			expected = append(expected, digest)
		}
	}
	observed, count, err := streamDigest(ctx, in, maxBytes, selected)
	if err != nil {
		return unknown, err
	}
	state := DigestMismatch
	for _, digest := range expected {
		if subtle.ConstantTimeCompare(digest, observed) == 1 {
			state = DigestMatch
		}
	}
	return ReferenceDigestSetCheck{State: state, Algorithm: algorithm, ExpectedDigests: expected, ObservedDigest: observed, BytesRead: count}, nil
}
