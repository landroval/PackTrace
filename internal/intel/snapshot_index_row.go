package intel

import "encoding/hex"

// SnapshotNPMIndexRow is a scalar projection of one strictly parsed v1 row.
// Parsing alone proves neither catalog binding nor original/source authority.
type SnapshotNPMIndexRow struct {
	V              int    `json:"v"`
	IdentityHash   string `json:"identityHash"`
	Ecosystem      string `json:"ecosystem"`
	Name           string `json:"name"`
	SourceOrdinal  uint64 `json:"sourceOrdinal"`
	OriginalSHA256 string `json:"originalSHA256"`
	OriginalBytes  uint64 `json:"originalBytes"`
	AffectedIndex  uint64 `json:"affectedIndex"`
}

func ParseSnapshotNPMIndexRow(raw []byte) (SnapshotNPMIndexRow, error) {
	row, code := parseSnapshotBlockRow(raw)
	if code != "" {
		return SnapshotNPMIndexRow{}, &ParseError{Code: code}
	}
	return SnapshotNPMIndexRow{1, hex.EncodeToString(row.identity[:]), row.ecosystem, row.name, row.ordinal, hex.EncodeToString(row.digest[:]), row.bytes, row.affected}, nil
}
