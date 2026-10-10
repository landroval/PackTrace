package intel

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
)

func TestCheckSnapshotObjectLiteralCases(t *testing.T) {
	data := []byte("owned-snapshot-fixture")
	ref := SnapshotObjectReference{SHA256: sha256.Sum256(data), Bytes: uint64(len(data))}
	wrongHash := ref
	wrongHash.SHA256[0] ^= 1
	wrongLength := ref
	wrongLength.Bytes++
	bothWrong := wrongHash
	bothWrong.Bytes++
	empty := SnapshotObjectReference{SHA256: sha256.Sum256(nil)}
	emptyWrongHash := empty
	emptyWrongHash.SHA256[0] ^= 1
	cases := []struct {
		name string
		ref  SnapshotObjectReference
		data []byte
		want SnapshotObjectCheckState
	}{
		{"same", ref, data, SnapshotObjectCheckBytesEqual},
		{"empty", empty, nil, SnapshotObjectCheckBytesEqual},
		{"empty-wrong-hash", emptyWrongHash, nil, SnapshotObjectCheckDigestMismatch},
		{"wrong-length", wrongLength, data, SnapshotObjectCheckLengthMismatch},
		{"wrong-hash", wrongHash, data, SnapshotObjectCheckDigestMismatch},
		{"length-before-hash", bothWrong, data, SnapshotObjectCheckLengthMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CheckSnapshotObject(tc.ref, tc.data)
			if err != nil || got.State != tc.want {
				t.Fatal("unexpected comparison outcome")
			}
			if got.ExpectedBytes != tc.ref.Bytes || got.ObservedBytes != uint64(len(tc.data)) ||
				got.ExpectedSHA256 != tc.ref.SHA256 || got.ObservedSHA256 != sha256.Sum256(tc.data) {
				t.Fatal("comparison evidence lost")
			}
		})
	}
}

func TestCheckSnapshotObjectLimitsAreWholeZero(t *testing.T) {
	oversized := make([]byte, (4<<20)+1)
	for _, tc := range []struct {
		ref  SnapshotObjectReference
		data []byte
	}{
		{SnapshotObjectReference{Bytes: (4 << 20) + 1}, nil},
		{SnapshotObjectReference{}, oversized},
	} {
		got, err := CheckSnapshotObject(tc.ref, tc.data)
		var parseErr *ParseError
		if got != (SnapshotObjectCheck{}) || !errors.As(err, &parseErr) || parseErr.Code != "limit-exceeded" || err.Error() != "intel: limit-exceeded" {
			t.Fatal("oversize did not fail privately with a whole-zero result")
		}
	}
}

func TestCheckSnapshotObjectExactLimit(t *testing.T) {
	data := make([]byte, 4<<20)
	data[0], data[len(data)-1] = 1, 2
	ref := SnapshotObjectReference{SHA256: sha256.Sum256(data), Bytes: 4 << 20}
	got, err := CheckSnapshotObject(ref, data)
	if err != nil || got.State != SnapshotObjectCheckBytesEqual || got.ObservedBytes != 4<<20 || got.ObservedSHA256 != sha256.Sum256(data) {
		t.Fatal("exact limit was not compared")
	}
}

func TestCheckSnapshotObjectOwnsResultAndIsRepeatable(t *testing.T) {
	data := []byte("mutable-input")
	ref := SnapshotObjectReference{SHA256: sha256.Sum256(data), Bytes: uint64(len(data))}
	wantDigest := ref.SHA256
	first, err := CheckSnapshotObject(ref, data)
	if err != nil {
		t.Fatal("first comparison failed")
	}
	second, err := CheckSnapshotObject(ref, data)
	if err != nil || second != first {
		t.Fatal("duplicate comparison changed result")
	}
	data[0] ^= 1
	ref.SHA256[0] ^= 1
	ref.Bytes++
	if first.State != SnapshotObjectCheckBytesEqual || first.ExpectedSHA256 != wantDigest || first.ObservedSHA256 != wantDigest || first.ExpectedBytes != uint64(len(data)) || first.ObservedBytes != uint64(len(data)) {
		t.Fatal("result retained mutable input")
	}
}

func TestCheckSnapshotObjectIgnoresRawFieldsAndRecords(t *testing.T) {
	data := []byte("literal-object")
	ref := SnapshotObjectReference{
		Fields: map[string]json.RawMessage{
			"path":    json.RawMessage(`"file:///missing/private/target"`),
			"sha256":  json.RawMessage(`"forged"`),
			"bytes":   json.RawMessage(`999999999`),
			"records": json.RawMessage(`999999999`),
		},
		SHA256:  sha256.Sum256(data),
		Bytes:   uint64(len(data)),
		Records: ^uint64(0),
	}
	got, err := CheckSnapshotObject(ref, data)
	if err != nil || got.State != SnapshotObjectCheckBytesEqual || got.ExpectedSHA256 != ref.SHA256 || got.ExpectedBytes != ref.Bytes {
		t.Fatal("non-comparison claims affected literal byte comparison")
	}
}
