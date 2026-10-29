// Package integrity checks supplied reference digests over bounded streams.
package integrity

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
	"io"
)

type DigestState uint8

const (
	DigestUnknown DigestState = iota
	DigestMatch
	DigestMismatch
)

// ReferenceDigestCheck describes only a digest comparison, not artifact identity or provenance.
type ReferenceDigestCheck struct {
	State          DigestState
	Algorithm      string
	ExpectedDigest []byte
	ObservedDigest []byte
	BytesRead      int64
}

var (
	errDigestArgument = errors.New("invalid reference digest argument")
	errDigestLimit    = errors.New("reference digest byte limit exceeded")
	errDigestRead     = errors.New("reference digest read failed")
)

// CheckReferenceDigest supports a deliberately limited single-token SRI profile:
// exactly one canonical padded sha256, sha384 or sha512 token. Unsupported claims
// remain unverified without consuming the reader; there is no algorithm fallback.
// A successful comparison says nothing about provenance, archive safety or coverage.
func CheckReferenceDigest(ctx context.Context, expectedSRI string, in io.Reader, maxBytes int64) (ReferenceDigestCheck, error) {
	var unknown ReferenceDigestCheck
	if ctx == nil || in == nil || maxBytes < 0 || maxBytes > 512*1024*1024 {
		return unknown, errDigestArgument
	}
	var algorithm string
	var size int
	var h hash.Hash
	switch {
	case len(expectedSRI) == 7+44 && expectedSRI[:7] == "sha256-":
		algorithm, size, h = "sha256", sha256.Size, sha256.New()
	case len(expectedSRI) == 7+64 && expectedSRI[:7] == "sha384-":
		algorithm, size, h = "sha384", sha512.Size384, sha512.New384()
	case len(expectedSRI) == 7+88 && expectedSRI[:7] == "sha512-":
		algorithm, size, h = "sha512", sha512.Size, sha512.New()
	default:
		return unknown, nil
	}
	encoded := expectedSRI[7:]
	expected, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(expected) != size || base64.StdEncoding.EncodeToString(expected) != encoded {
		return unknown, nil
	}
	if err = ctx.Err(); err != nil {
		return unknown, err
	}
	var scratch [32 * 1024]byte
	var count int64
	stalls := 0
	for {
		if err = ctx.Err(); err != nil {
			return unknown, err
		}
		remaining := maxBytes - count
		request := len(scratch)
		if remaining < int64(request) {
			request = int(remaining) + 1
		}
		n, readErr := in.Read(scratch[:request])
		if err = ctx.Err(); err != nil {
			return unknown, err
		}
		if n < 0 || n > request {
			return unknown, errDigestRead
		}
		count += int64(n)
		if count > maxBytes {
			return unknown, errDigestLimit
		}
		if n > 0 {
			_, _ = h.Write(scratch[:n])
			stalls = 0
		} else {
			stalls++
		}
		if readErr != nil && readErr != io.EOF {
			return unknown, errDigestRead
		}
		if readErr == io.EOF {
			break
		}
		if stalls >= 100 {
			return unknown, errDigestRead
		}
	}
	if err = ctx.Err(); err != nil {
		return unknown, err
	}
	observed := h.Sum(nil)
	state := DigestMismatch
	if subtle.ConstantTimeCompare(expected, observed) == 1 {
		state = DigestMatch
	}
	return ReferenceDigestCheck{State: state, Algorithm: algorithm, ExpectedDigest: expected, ObservedDigest: observed, BytesRead: count}, nil
}
