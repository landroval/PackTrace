package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"packtrace/internal/integrity"
)

// ReferenceDigestResult reports equality over supplied bytes, not artifact assurance.
type ReferenceDigestResult struct {
	Schema       string   `json:"schema"`
	Experimental bool     `json:"experimental"`
	Scope        string   `json:"scope"`
	Privacy      string   `json:"privacy"`
	State        string   `json:"state"`
	Algorithm    string   `json:"algorithm"`
	BytesRead    int64    `json:"bytes_read"`
	ExitCode     int      `json:"exit_code"`
	Limitations  []string `json:"limitations"`
}

var errReferenceDigestCheck = errors.New("check-reference-digest: check-failed")
var errReferenceDigestReport = errors.New("check-reference-digest: report-failed")

func ReadReferenceDigest(ctx context.Context, expectedSRI string, in io.Reader, maxBytes int64) (ReferenceDigestResult, error) {
	check, err := integrity.CheckReferenceDigest(ctx, expectedSRI, in, maxBytes)
	if err != nil {
		return ReferenceDigestResult{}, errReferenceDigestCheck
	}
	state, algorithm := "unknown", "unknown"
	switch check.State {
	case integrity.DigestMatch:
		state = "match"
	case integrity.DigestMismatch:
		state = "mismatch"
	}
	if state != "unknown" {
		switch check.Algorithm {
		case "sha256", "sha384", "sha512":
			algorithm = check.Algorithm
		}
	}
	return ReferenceDigestResult{
		Schema: "packtrace.reference-digest.v1", Experimental: true, Scope: "supplied-reference-bytes", Privacy: "portable",
		State: state, Algorithm: algorithm, BytesRead: check.BytesRead, ExitCode: 3,
		Limitations: []string{"Digest equality only; not reference assurance, archive validity, coverage or security.", "Only a single canonical SHA-256/384/512 SRI token is supported; unknown is not a match."},
	}, nil
}

func RenderReferenceDigest(result ReferenceDigestResult, format string) ([]byte, error) {
	switch format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, errReferenceDigestReport
		}
		return append(data, '\n'), nil
	case "terminal":
		return []byte(fmt.Sprintf("EXPERIMENTAL reference digest — supplied bytes only\nState: %s\nAlgorithm: %s\nBytes read: %d\nLimitations: digest equality only; not reference assurance, archive validity, coverage or security. Single canonical SHA-256/384/512 SRI token only.\nExit: 3\n", result.State, result.Algorithm, result.BytesRead)), nil
	default:
		return nil, errReferenceDigestReport
	}
}
