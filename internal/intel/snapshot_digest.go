package intel

import (
	"encoding/base64"
	"errors"
	"strings"
)

var ErrSnapshotDigest = errors.New("intel: invalid-snapshot-digest")

// ParseSnapshotDigest accepts exactly one canonical SHA256 SRI selector. It
// performs no I/O and does not authenticate a publisher or approve a dataset.
func ParseSnapshotDigest(text string) ([32]byte, error) {
	var result [32]byte
	if !strings.HasPrefix(text, "sha256-") {
		return result, ErrSnapshotDigest
	}
	raw, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(text, "sha256-"))
	if e != nil || len(raw) != 32 || "sha256-"+base64.StdEncoding.EncodeToString(raw) != text {
		return result, ErrSnapshotDigest
	}
	copy(result[:], raw)
	return result, nil
}
