package intel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
)

func TestCatalogProofReusesVerifiedMetadataWithoutChangingLegacyGaps(t *testing.T) {
	ctx := context.Background()
	original := []byte(streamTestOriginal)
	catalogRaw := streamTestRows(streamTestCatalogLine(0, original))
	block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
	manifest := streamTestManifest(t, catalogRaw, 0x2a, block)
	catalog, e := ReadSnapshotCatalog(ctx, manifest, bytes.NewReader(catalogRaw))
	if e != nil {
		t.Fatal(e)
	}
	digest, size, ok := catalog.Reference(0)
	if !ok || digest != sha256.Sum256(original) || size != uint64(len(original)) {
		t.Fatal("verified ordinal reference changed")
	}
	if !catalog.Contains(sha256.Sum256(original), uint64(len(original))) || catalog.Contains(sha256.Sum256(original), uint64(len(original)+1)) {
		t.Fatal("original reference lookup is not digest+length bound")
	}
	for i := 0; i < 2; i++ {
		got, e := ReadSnapshotNPMIdentityWithCatalog(ctx, manifest, "left-pad", catalog, bytes.NewReader(block), []SnapshotOriginalStream{{SHA256: sha256.Sum256(original), Reader: bytes.NewReader(original)}})
		if e != nil || len(got.Records) != 1 || got.Records[0].State != SnapshotOriginalVerified || len(got.Gaps) != len(streamTestBaselineGaps()) {
			t.Fatal("cached catalog changed binding/baseline authority", e)
		}
	}
}
func TestCatalogProofRejectsForgedOrDifferentManifest(t *testing.T) {
	ctx := context.Background()
	original := []byte(streamTestOriginal)
	raw := streamTestRows(streamTestCatalogLine(0, original))
	block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
	manifest := streamTestManifest(t, raw, 0x2a, block)
	catalog, e := ReadSnapshotCatalog(ctx, manifest, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	other := manifest
	other.SHA256[0] ^= 1
	if _, e := ReadSnapshotNPMIdentityWithCatalog(ctx, other, "left-pad", catalog, bytes.NewReader(block), nil); e == nil {
		t.Fatal("proof used for another manifest")
	}
	if _, e := ReadSnapshotNPMIdentityWithCatalog(ctx, manifest, "left-pad", &SnapshotVerifiedCatalog{}, bytes.NewReader(block), nil); e == nil {
		t.Fatal("zero proof forged verified metadata")
	}
}
