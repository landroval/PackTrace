package intel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestGroupedReaderWindowCapsAcrossNames(t *testing.T) {
	names := batchNames(2)
	for _, mode := range []string{"bindings", "originals"} {
		t.Run(mode, func(t *testing.T) {
			original := []byte(streamTestOriginal)
			catalogLines := []string{streamTestCatalogLine(0, original)}
			var lines []string
			if mode == "bindings" {
				// Each identity alone fits; the combined window does not.
				for j, name := range names {
					for i := 0; i < maxSnapshotRetainedBindings/2+1; i++ {
						lines = append(lines, streamTestBlockLine(name, 0, original, uint64(j*(maxSnapshotRetainedBindings/2+1)+i)))
					}
				}
			} else {
				catalogLines = nil
				for j, name := range names {
					for i := 0; i < maxSnapshotUniqueOriginals/2+1; i++ {
						ordinal := uint64(j*(maxSnapshotUniqueOriginals/2+1) + i)
						raw := []byte(fmt.Sprintf(`{"id":"OWNED-%d"}`, ordinal))
						digest := sha256.Sum256(raw)
						catalogLines = append(catalogLines, streamTestCatalogRefLine(ordinal, digest, uint64(len(raw))))
						lines = append(lines, streamTestBlockRefLine(name, ordinal, digest, uint64(len(raw)), 0))
					}
				}
			}
			block, catalogRaw := streamTestRows(lines...), streamTestRows(catalogLines...)
			m := streamTestManifest(t, catalogRaw, snapshotNPMIdentityHash(names[0])[0], block)
			catalog, err := ReadSnapshotCatalog(context.Background(), m, bytes.NewReader(catalogRaw))
			if err != nil {
				t.Fatal(err)
			}
			r := &batchCountingReader{Reader: bytes.NewReader(block)}
			err = WalkSnapshotNPMIdentitiesWithCatalog(context.Background(), m, names, catalog, r, func(SnapshotObjectReference) (io.ReadCloser, error) {
				t.Fatal("opened over-cap original")
				return nil, nil
			}, func(string, SnapshotNPMEvidence) error { t.Fatal("emitted over-cap prefix"); return nil })
			var pe *ParseError
			if !errors.As(err, &pe) || pe.Code != "limit-exceeded" || r.bytes != len(block) {
				t.Fatal("window cap multiplied", mode, r.bytes, err)
			}
		})
	}
}

func TestGroupedReaderPerIdentityRawRetentionStillBounded(t *testing.T) {
	name := "left-pad"
	var catalogLines, blockLines []string
	originals := make(map[[32]byte][]byte)
	// Five 4MiB originals cannot fit the unchanged 16MiB retained-raw cap.
	for i := 0; i < 5; i++ {
		raw := streamTestPaddedOriginal(t, 4<<20, fmt.Sprintf("OWNED-RAW-%d", i), name)
		digest := sha256.Sum256(raw)
		originals[digest] = raw
		catalogLines = append(catalogLines, streamTestCatalogLine(uint64(i), raw))
		blockLines = append(blockLines, streamTestBlockLine(name, uint64(i), raw, 0))
	}
	block, catalogRaw := streamTestRows(blockLines...), streamTestRows(catalogLines...)
	m := streamTestManifest(t, catalogRaw, 0x2a, block)
	catalog, err := ReadSnapshotCatalog(context.Background(), m, bytes.NewReader(catalogRaw))
	if err != nil {
		t.Fatal(err)
	}
	var got SnapshotNPMEvidence
	err = WalkSnapshotNPMIdentitiesWithCatalog(context.Background(), m, []string{name}, catalog, bytes.NewReader(block), func(ref SnapshotObjectReference) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(originals[ref.SHA256])), nil
	}, func(_ string, e SnapshotNPMEvidence) error { got = e; return nil })
	if err != nil || len(got.Records) != 5 || !containsSnapshotGap(got.Gaps, SnapshotGapResource) {
		t.Fatal("retention cap absent", err)
	}
	var retained uint64
	for _, record := range got.Records {
		retained += uint64(len(record.Raw))
	}
	if retained > 16<<20 || got.Records[4].Problem != SnapshotOriginalProblemResource || got.Records[4].State == SnapshotOriginalVerified {
		t.Fatal("raw cap weakened", retained)
	}
}
