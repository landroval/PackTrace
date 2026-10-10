package intel

import "crypto/sha256"

const maxSnapshotObjectCheckBytes = 4 << 20

type SnapshotObjectCheckState uint8

const (
	SnapshotObjectCheckUnknown SnapshotObjectCheckState = iota
	SnapshotObjectCheckBytesEqual
	SnapshotObjectCheckLengthMismatch
	SnapshotObjectCheckDigestMismatch
)

type SnapshotObjectCheck struct {
	State                          SnapshotObjectCheckState
	ExpectedSHA256, ObservedSHA256 [32]byte
	ExpectedBytes, ObservedBytes   uint64
}

func CheckSnapshotObject(ref SnapshotObjectReference, data []byte) (SnapshotObjectCheck, error) {
	if ref.Bytes > maxSnapshotObjectCheckBytes || len(data) > maxSnapshotObjectCheckBytes {
		return SnapshotObjectCheck{}, &ParseError{Code: "limit-exceeded"}
	}

	observedSHA256 := sha256.Sum256(data)
	result := SnapshotObjectCheck{
		ExpectedSHA256: ref.SHA256,
		ObservedSHA256: observedSHA256,
		ExpectedBytes:  ref.Bytes,
		ObservedBytes:  uint64(len(data)),
	}
	switch {
	case result.ExpectedBytes != result.ObservedBytes:
		result.State = SnapshotObjectCheckLengthMismatch
	case result.ExpectedSHA256 != result.ObservedSHA256:
		result.State = SnapshotObjectCheckDigestMismatch
	default:
		result.State = SnapshotObjectCheckBytesEqual
	}
	return result, nil
}
