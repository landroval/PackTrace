package intel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const streamTestOriginal = `{"id":"OSV-SYNTHETIC-1","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["1.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`

func streamTestDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func streamTestRows(lines ...string) []byte {
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func streamTestCatalogLine(ordinal uint64, original []byte) string {
	return streamTestCatalogRefLine(ordinal, sha256.Sum256(original), uint64(len(original)))
}

func streamTestCatalogRefLine(ordinal uint64, digest [32]byte, size uint64) string {
	return fmt.Sprintf(`{"v":1,"sourceOrdinal":%d,"sha256":"%s","bytes":%d}`,
		ordinal, hex.EncodeToString(digest[:]), size)
}

func streamTestBlockLine(name string, ordinal uint64, original []byte, affected uint64) string {
	return streamTestBlockRefLine(name, ordinal, sha256.Sum256(original), uint64(len(original)), affected)
}

func streamTestBlockRefLine(name string, ordinal uint64, digest [32]byte, size, affected uint64) string {
	hash := sha256.Sum256(append([]byte("npm\x00"), []byte(name)...))
	return fmt.Sprintf(`{"v":1,"identityHash":"%s","ecosystem":"npm","name":%q,"sourceOrdinal":%d,"originalSHA256":"%s","originalBytes":%d,"affectedIndex":%d}`,
		hex.EncodeToString(hash[:]), name, ordinal, hex.EncodeToString(digest[:]), size, affected)
}

func streamTestManifest(t *testing.T, catalog []byte, blockIndex byte, block []byte) SnapshotManifest {
	t.Helper()
	empty := sha256.Sum256(nil)
	refs := make([]any, 256)
	for i := range refs {
		refs[i] = map[string]any{"index": i, "sha256": hex.EncodeToString(empty[:]), "bytes": 0, "records": 0}
	}
	blockSum := sha256.Sum256(block)
	refs[int(blockIndex)] = map[string]any{"index": int(blockIndex), "sha256": hex.EncodeToString(blockSum[:]), "bytes": len(block), "records": bytes.Count(block, []byte{'\n'})}
	catalogSum := sha256.Sum256(catalog)
	raw, err := json.Marshal(map[string]any{
		"schemaVersion": "1.1",
		"source":        map[string]any{"id": "packtrace-synthetic-stream"},
		"originals":     map[string]any{"sha256": hex.EncodeToString(catalogSum[:]), "bytes": len(catalog), "records": bytes.Count(catalog, []byte{'\n'})},
		"blocks":        refs,
	})
	if err != nil {
		t.Fatal("fixture marshal failed")
	}
	manifest, err := ParseSnapshotManifestV11(raw)
	if err != nil {
		t.Fatal("fixture manifest failed", err)
	}
	return manifest
}

func streamTestCall(t *testing.T, original []byte) SnapshotNPMEvidence {
	t.Helper()
	catalog := streamTestRows(streamTestCatalogLine(0, original))
	block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
	manifest := streamTestManifest(t, catalog, 0x2a, block)
	digest := sha256.Sum256(original)
	got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{
		Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog),
		Originals: []SnapshotOriginalStream{{SHA256: digest, Reader: bytes.NewReader(original)}},
	})
	if err != nil {
		t.Fatal("unexpected stream failure", err)
	}
	return got
}

func streamTestFatal(t *testing.T, manifest SnapshotManifest, streams SnapshotNPMStreams, code string) {
	t.Helper()
	got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", streams)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != code || err.Error() != "intel: "+code ||
		!reflect.DeepEqual(got, SnapshotNPMEvidence{}) {
		t.Fatalf("missing private whole-zero failure: got=%#v err=%v want=%s", got, err, code)
	}
}

func streamTestBaselineGaps() []SnapshotGapKind {
	return []SnapshotGapKind{
		SnapshotGapIndexCompleteness, SnapshotGapCorrection, SnapshotGapActivity,
		SnapshotGapSourceQualification, SnapshotGapRegistryCorrespondence,
		SnapshotGapFindingAuthority, SnapshotGapGlobalStoreQuota,
		SnapshotGapPreparationByteIdentity,
	}
}

func streamTestEvidence(t *testing.T, name string, originals [][]byte, affected []uint64, supplied []SnapshotOriginalStream) SnapshotNPMEvidence {
	t.Helper()
	catalogLines := make([]string, len(originals))
	blockLines := make([]string, len(originals))
	for i, original := range originals {
		catalogLines[i] = streamTestCatalogLine(uint64(i), original)
		blockLines[i] = streamTestBlockLine(name, uint64(i), original, affected[i])
	}
	catalog, block := streamTestRows(catalogLines...), streamTestRows(blockLines...)
	index := sha256.Sum256(append([]byte("npm\x00"), []byte(name)...))[0]
	manifest := streamTestManifest(t, catalog, index, block)
	got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, name, SnapshotNPMStreams{
		Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog), Originals: supplied,
	})
	if err != nil {
		t.Fatal("unexpected stream failure", err)
	}
	return got
}

func streamTestPaddedOriginal(t *testing.T, size int, id, name string) []byte {
	t.Helper()
	prefix := fmt.Sprintf(`{"id":%q,"modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":%q}}],"pad":"`, id, name)
	suffix := `"}`
	if len(prefix)+len(suffix) > size {
		t.Fatal("padded fixture too small")
	}
	return []byte(prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix)
}

func TestReadSnapshotNPMIdentityExactEvidence(t *testing.T) {
	original := []byte(streamTestOriginal)
	got := streamTestCall(t, original)
	digest := sha256.Sum256(original)
	expectedManifest := streamTestManifest(t,
		streamTestRows(streamTestCatalogLine(0, original)), 0x2a,
		streamTestRows(streamTestBlockLine("left-pad", 0, original, 0)))
	if got.ManifestSHA256 != expectedManifest.SHA256 ||
		got.IdentityHash != ([32]byte{0x2a, 0x7a, 0xb3, 0xd5, 0x63, 0x56, 0x2f, 0x66, 0x6c, 0xa1, 0xb4, 0xd2, 0x49, 0x4f, 0xf2, 0x0b, 0xc1, 0x14, 0xb8, 0xfc, 0xd8, 0x1d, 0x9d, 0xc1, 0xe4, 0xcb, 0x22, 0x1d, 0x5c, 0x47, 0xc1, 0xbc}) ||
		got.Ecosystem != "npm" || got.Name != "left-pad" || got.BlockIndex != 42 ||
		got.BlockState != SnapshotStreamStructured || got.CatalogState != SnapshotStreamStructured ||
		got.Declaration != SnapshotDeclarationVerified || !reflect.DeepEqual(got.Gaps, streamTestBaselineGaps()) || len(got.Records) != 1 {
		t.Fatal("literal query/object state changed")
	}
	record := got.Records[0]
	if record.SHA256 != digest || record.Header.SourceSHA256 != digest ||
		record.Affected.SourceSHA256 != digest || record.Identity.SourceSHA256 != digest ||
		record.Times.SourceSHA256 != digest || record.Bytes != uint64(len(original)) ||
		record.State != SnapshotOriginalVerified || record.Problem != SnapshotOriginalProblemNone ||
		!bytes.Equal(record.Raw, original) || record.Header.ID.Value != "OSV-SYNTHETIC-1" ||
		record.Affected.State != OSVFieldValue || len(record.Affected.Entries) != 1 ||
		record.Affected.Entries[0].Versions.Entries[0].Value != "1.0.0" ||
		record.Affected.Entries[0].Ranges.Entries[0].Type.Value != "SEMVER" ||
		record.Identity.Entries[0].Qualification != OSVNPMIdentityCandidate ||
		record.Times.Withdrawal != WithdrawalNotDeclared ||
		!reflect.DeepEqual(record.Bindings, []SnapshotAffectedBinding{{
			SourceOrdinal: 0, AffectedIndex: 0,
			State: SnapshotBindingEligible, Problem: SnapshotBindingProblemNone,
		}}) {
		t.Fatal("owned original/projection/binding evidence changed")
	}
	if got.BytesRead != uint64(len(streamTestRows(streamTestBlockLine("left-pad", 0, original, 0)))+
		len(streamTestRows(streamTestCatalogLine(0, original)))+len(original)) {
		t.Fatal("actual read accounting charged declarations or missed bytes")
	}
}

func TestReadSnapshotNPMIdentityJSONLFailures(t *testing.T) {
	original := []byte(streamTestOriginal)
	validCatalog := streamTestRows(streamTestCatalogLine(0, original))
	validBlock := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
	cases := []struct {
		name, code string
		data       []byte
	}{
		{"bom", "invalid-shape", append([]byte{0xef, 0xbb, 0xbf}, validBlock...)},
		{"bom-over-profile", "invalid-shape", append(append([]byte{0xef, 0xbb, 0xbf}, bytes.Repeat([]byte{' '}, (1<<20)+1)...), '\n')},
		{"crlf", "invalid-shape", bytes.ReplaceAll(validBlock, []byte("\n"), []byte("\r\n"))},
		{"blank", "invalid-shape", append(validBlock, '\n')},
		{"missing-final-lf", "invalid-shape", validBlock[:len(validBlock)-1]},
		{"invalid-utf8", "invalid-json", append([]byte{0xff}, '\n')},
		{"surrogate", "invalid-json", streamTestRows(`{"v":1,"identityHash":"\ud800"}`)},
		{"duplicate-key", "duplicate-key", streamTestRows(strings.Replace(streamTestBlockLine("left-pad", 0, original, 0), `"v":1`, `"v":1,"\u0076":1`, 1))},
		{"unknown-field", "invalid-shape", streamTestRows(strings.Replace(streamTestBlockLine("left-pad", 0, original, 0), `"v":1`, `"v":1,"extra":0`, 1))},
		{"noncanonical-integer", "invalid-json", bytes.Replace(validBlock, []byte(`"sourceOrdinal":0`), []byte(`"sourceOrdinal":01`), 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := streamTestManifest(t, validCatalog, 0x2a, tc.data)
			digest := sha256.Sum256(original)
			streamTestFatal(t, manifest, SnapshotNPMStreams{
				Block: bytes.NewReader(tc.data), Catalog: bytes.NewReader(validCatalog),
				Originals: []SnapshotOriginalStream{{SHA256: digest, Reader: bytes.NewReader(original)}},
			}, tc.code)
		})
	}

	t.Run("catalog-zero-byte", func(t *testing.T) {
		manifest := streamTestManifest(t, nil, 0x2a, nil)
		got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{Block: bytes.NewReader(nil), Catalog: bytes.NewReader(nil)})
		if err != nil || got.BlockState != SnapshotStreamStructured || got.CatalogState != SnapshotStreamStructured ||
			got.Declaration != SnapshotDeclarationVerified || len(got.Records) != 0 || !reflect.DeepEqual(got.Gaps, streamTestBaselineGaps()) {
			t.Fatal("zero-byte objects changed")
		}
	})
	catalogCases := []struct {
		name  string
		lines []string
	}{
		{"catalog-skipped-ordinal", []string{streamTestCatalogLine(1, original)}},
		{"catalog-repeated-ordinal", []string{streamTestCatalogLine(0, original), streamTestCatalogLine(0, original)}},
		{"catalog-conflicting-length", []string{streamTestCatalogRefLine(0, sha256.Sum256(original), 1), streamTestCatalogRefLine(1, sha256.Sum256(original), 2)}},
	}
	for _, tc := range catalogCases {
		t.Run(tc.name, func(t *testing.T) {
			catalog := streamTestRows(tc.lines...)
			manifest := streamTestManifest(t, catalog, 0x2a, validBlock)
			streamTestFatal(t, manifest, SnapshotNPMStreams{Block: bytes.NewReader(validBlock), Catalog: bytes.NewReader(catalog)}, "invalid-shape")
		})
	}
	t.Run("block-sort", func(t *testing.T) {
		one := streamTestBlockLine("left-pad", 1, original, 0)
		two := streamTestBlockLine("left-pad", 0, original, 0)
		block := streamTestRows(one, two)
		manifest := streamTestManifest(t, validCatalog, 0x2a, block)
		streamTestFatal(t, manifest, SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(validCatalog)}, "invalid-shape")
	})
	t.Run("block-duplicate-tuple", func(t *testing.T) {
		line := streamTestBlockLine("left-pad", 0, original, 0)
		block := streamTestRows(line, line)
		manifest := streamTestManifest(t, validCatalog, 0x2a, block)
		streamTestFatal(t, manifest, SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(validCatalog)}, "invalid-shape")
	})
	t.Run("block-wrong-slot", func(t *testing.T) {
		line := streamTestBlockLine("pkg-3", 0, original, 0)
		block := streamTestRows(line)
		manifest := streamTestManifest(t, validCatalog, 0x2a, block)
		streamTestFatal(t, manifest, SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(validCatalog)}, "invalid-shape")
	})
	t.Run("block-forged-hash", func(t *testing.T) {
		line := streamTestBlockLine("left-pad", 0, original, 0)
		line = strings.Replace(line, `"identityHash":"2`, `"identityHash":"3`, 1)
		block := streamTestRows(line)
		manifest := streamTestManifest(t, validCatalog, 0x2a, block)
		streamTestFatal(t, manifest, SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(validCatalog)}, "invalid-shape")
	})
	t.Run("block-record-count", func(t *testing.T) {
		manifest := streamTestManifest(t, validCatalog, 0x2a, validBlock)
		manifest.Blocks[0x2a].Reference.Records++
		streamTestFatal(t, manifest, SnapshotNPMStreams{Block: bytes.NewReader(validBlock), Catalog: bytes.NewReader(validCatalog)}, "invalid-shape")
	})
	for _, which := range []string{"block-digest", "catalog-digest"} {
		t.Run(which, func(t *testing.T) {
			block := append([]byte{' '}, validBlock...)
			catalog := append([]byte{' '}, validCatalog...)
			manifest := streamTestManifest(t, catalog, 0x2a, block)
			if which == "block-digest" {
				block[0] = '\t'
			} else {
				catalog[0] = '\t'
			}
			streamTestFatal(t, manifest, SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog)}, "digest-mismatch")
		})
	}
	t.Run("line-profile", func(t *testing.T) {
		line := []byte(streamTestBlockLine("left-pad", 0, original, 0))
		line = append(line, bytes.Repeat([]byte{' '}, (1<<20)+1-len(line))...)
		block := append(line, '\n')
		manifest := streamTestManifest(t, validCatalog, 0x2a, block)
		got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(validCatalog)})
		if err != nil || got.BlockState != SnapshotStreamBytesVerified || got.CatalogState != SnapshotStreamUnknown ||
			got.Declaration != SnapshotDeclarationGap || len(got.Records) != 0 || !containsSnapshotGap(got.Gaps, SnapshotGapResource) {
			t.Fatal("line profile did not remain a resource gap")
		}
	})
}

func containsSnapshotGap(gaps []SnapshotGapKind, want SnapshotGapKind) bool {
	for _, gap := range gaps {
		if gap == want {
			return true
		}
	}
	return false
}

func TestReadSnapshotNPMIdentityDistinctSameBlockPrefix(t *testing.T) {
	one := []byte(`{"id":"ONE","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"pkg-3"}}]}`)
	two := []byte(`{"id":"TWO","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"pkg-6"}}]}`)
	catalog := streamTestRows(streamTestCatalogLine(0, one), streamTestCatalogLine(1, two))
	block := streamTestRows(streamTestBlockLine("pkg-6", 1, two, 0), streamTestBlockLine("pkg-3", 0, one, 0))
	manifest := streamTestManifest(t, catalog, 0x26, block)
	oneDigest, twoDigest := sha256.Sum256(one), sha256.Sum256(two)
	got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "pkg-3", SnapshotNPMStreams{
		Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog),
		Originals: []SnapshotOriginalStream{{SHA256: oneDigest, Reader: bytes.NewReader(one)}, {SHA256: twoDigest, Reader: bytes.NewReader(two)}},
	})
	if err != nil || len(got.Records) != 1 || got.Records[0].Header.ID.Value != "ONE" || got.Records[0].Bindings[0].State != SnapshotBindingEligible {
		t.Fatal("same-prefix identity was combined or discarded")
	}
}

func TestReadSnapshotNPMIdentityDuplicateOccurrenceSingleOriginal(t *testing.T) {
	original := []byte(streamTestOriginal)
	catalog := streamTestRows(streamTestCatalogLine(0, original), streamTestCatalogLine(1, original))
	block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0), streamTestBlockLine("left-pad", 1, original, 0))
	manifest := streamTestManifest(t, catalog, 0x2a, block)
	digest := sha256.Sum256(original)
	got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{
		Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog),
		Originals: []SnapshotOriginalStream{{SHA256: digest, Reader: bytes.NewReader(original)}},
	})
	want := []SnapshotAffectedBinding{{SourceOrdinal: 0, AffectedIndex: 0, State: SnapshotBindingEligible}, {SourceOrdinal: 1, AffectedIndex: 0, State: SnapshotBindingEligible}}
	if err != nil || len(got.Records) != 1 || !reflect.DeepEqual(got.Records[0].Bindings, want) {
		t.Fatal("duplicate occurrence duplicated raw/projections or lost bindings")
	}
}

func TestReadSnapshotNPMIdentityBindingFailures(t *testing.T) {
	original := []byte(streamTestOriginal)
	catalog := streamTestRows(streamTestCatalogLine(0, original))
	block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
	base := streamTestManifest(t, catalog, 0x2a, block)
	t.Run("manifest-guards-before-read", func(t *testing.T) {
		cases := map[string]func(*SnapshotManifest){
			"schema":          func(m *SnapshotManifest) { m.SchemaVersion = "1.0" },
			"index":           func(m *SnapshotManifest) { m.Blocks[3].Index = 4 },
			"source-id":       func(m *SnapshotManifest) { m.Source.ID = "" },
			"source-fields":   func(m *SnapshotManifest) { m.Source.Fields = nil },
			"direct-overflow": func(m *SnapshotManifest) { m.Originals.Bytes = maxSnapshotManifestObjectBytes + 1 },
			"record-overflow": func(m *SnapshotManifest) { m.Blocks[0].Reference.Records = maxSnapshotManifestRecords + 1 },
			"block-record-sum": func(m *SnapshotManifest) {
				m.Blocks[0].Reference.Records = maxSnapshotManifestRecords
				m.Blocks[1].Reference.Records = 1
			},
			"same-digest-length": func(m *SnapshotManifest) {
				m.Blocks[1].Reference.SHA256 = m.Blocks[0].Reference.SHA256
				m.Blocks[1].Reference.Bytes = 1
			},
			"repeated-block-count": func(m *SnapshotManifest) {
				m.Blocks[1].Reference.SHA256 = m.Blocks[0].Reference.SHA256
				m.Blocks[1].Reference.Records = 1
			},
			"unique-byte-sum": func(m *SnapshotManifest) {
				m.Originals.Bytes = maxSnapshotManifestObjectBytes
				m.Blocks[0].Reference.SHA256 = sha256.Sum256([]byte("distinct"))
				m.Blocks[0].Reference.Bytes = 1
			},
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				m := base
				m.Blocks = append([]SnapshotBlockReference(nil), base.Blocks...)
				mutate(&m)
				blockReader, catalogReader := &snapshotCountingReader{}, &snapshotCountingReader{}
				streamTestFatal(t, m, SnapshotNPMStreams{Block: blockReader, Catalog: catalogReader}, "invalid-shape")
				if blockReader.calls != 0 || catalogReader.calls != 0 {
					t.Fatal("manifest guard read a stream")
				}
			})
		}
	})
	for _, tc := range []struct {
		name  string
		block []byte
	}{
		{"block-original-digest", streamTestRows(strings.Replace(streamTestBlockLine("left-pad", 0, original, 0), streamTestDigest(original), strings.Repeat("0", 64), 1))},
		{"block-original-bytes", streamTestRows(strings.Replace(streamTestBlockLine("left-pad", 0, original, 0), fmt.Sprintf(`"originalBytes":%d`, len(original)), `"originalBytes":1`, 1))},
		{"selected-ordinal-absent", streamTestRows(streamTestBlockLine("left-pad", 1, original, 0))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := streamTestManifest(t, catalog, 0x2a, tc.block)
			streamTestFatal(t, m, SnapshotNPMStreams{Block: bytes.NewReader(tc.block), Catalog: bytes.NewReader(catalog)}, "invalid-shape")
		})
	}
	cases := []struct {
		name     string
		original []byte
		affected uint64
		problem  SnapshotBindingProblem
	}{
		{"affected-index", original, 1, SnapshotBindingProblemAffectedIndex},
		{"identity", []byte(`{"id":"X","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"other"}}]}`), 0, SnapshotBindingProblemIdentity},
		{"no-cross-slot", []byte(`{"id":"X","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"other"}},{"package":{"ecosystem":"npm","name":"left-pad"}}]}`), 0, SnapshotBindingProblemIdentity},
		{"purl-conflict", []byte(`{"id":"X","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad","purl":"pkg:npm/other"}}]}`), 0, SnapshotBindingProblemIdentity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			digest := sha256.Sum256(tc.original)
			got := streamTestEvidence(t, "left-pad", [][]byte{tc.original}, []uint64{tc.affected}, []SnapshotOriginalStream{{SHA256: digest, Reader: bytes.NewReader(tc.original)}})
			if len(got.Records) != 1 || got.Records[0].State != SnapshotOriginalVerified || got.Records[0].Bindings[0].State != SnapshotBindingGap || got.Records[0].Bindings[0].Problem != tc.problem {
				t.Fatal("binding failure borrowed authority")
			}
		})
	}
	t.Run("projection-source-hashes", func(t *testing.T) {
		got := streamTestCall(t, original)
		if len(got.Records) != 1 || len(got.Records[0].Bindings) != 1 {
			t.Fatal("exact source hash binding missing")
		}
		d := sha256.Sum256(original)
		r := got.Records[0]
		if r.Header.SourceSHA256 != d || r.Affected.SourceSHA256 != d || r.Identity.SourceSHA256 != d || r.Times.SourceSHA256 != d || r.Bindings[0].State != SnapshotBindingEligible {
			t.Fatal("exact source hash binding changed")
		}
	})
	t.Run("nonsemantic-source-field-mutation", func(t *testing.T) {
		m := base
		m.Source.ID = "another-nonempty-id"
		m.Source.Fields = map[string]json.RawMessage{"id": json.RawMessage(`"arbitrary"`), "extra": json.RawMessage(`true`)}
		got, err := ReadSnapshotNPMIdentity(context.Background(), m, "left-pad", SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog)})
		if err != nil || got.Declaration != SnapshotDeclarationVerified {
			t.Fatal("consumer reparsed unauthenticated raw source fields")
		}
	})
}

type snapshotCountingReader struct{ calls int }

func (r *snapshotCountingReader) Read([]byte) (int, error) { r.calls++; return 0, io.EOF }

type snapshotTestErrorReader struct{}

func (snapshotTestErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("private-path:/secret/raw-marker")
}

type eofWithDataReader struct {
	data []byte
	done bool
}

func (r *eofWithDataReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, r.data), io.EOF
}

type exactWithoutEOFReader struct {
	data []byte
	done bool
}

func (r *exactWithoutEOFReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, r.data), nil
	}
	return 0, nil
}

type snapshotTestCancelReader struct {
	cancel context.CancelFunc
	data   []byte
	calls  int
}

func (r *snapshotTestCancelReader) Read(p []byte) (int, error) {
	r.calls++
	n := copy(p, r.data)
	r.cancel()
	return n, io.EOF
}

func TestSnapshotReadBudgetAndEOF(t *testing.T) {
	t.Run("counter-math", func(t *testing.T) {
		b := snapshotReadBudget{used: maxSnapshotReadBytes - 1}
		if b.remaining() != 1 || !b.canStart(1) || b.canStart(2) {
			t.Fatal("8 GiB preflight arithmetic changed")
		}
		if !b.charge(1) || b.used != maxSnapshotReadBytes || b.charge(1) {
			t.Fatal("actual-byte counter overflow/double-charge guard changed")
		}
	})
	t.Run("same-read-eof", func(t *testing.T) {
		b := snapshotReadBudget{}
		data, resource, code := readSnapshotOriginalBytes(context.Background(), &eofWithDataReader{data: []byte("abc")}, 3, &b)
		if code != "" || resource || string(data) != "abc" || b.used != 3 {
			t.Fatal("(n, EOF) did not establish exact end byte")
		}
	})
	t.Run("detection-byte", func(t *testing.T) {
		b := snapshotReadBudget{}
		_, resource, code := readSnapshotOriginalBytes(context.Background(), bytes.NewReader([]byte("abcd")), 3, &b)
		if code != "length-mismatch" || resource || b.used != 4 {
			t.Fatal("positive detection byte was not charged")
		}
	})
	t.Run("no-budget-for-eof", func(t *testing.T) {
		b := snapshotReadBudget{used: maxSnapshotReadBytes - 3}
		_, resource, code := readSnapshotOriginalBytes(context.Background(), &exactWithoutEOFReader{data: []byte("abc")}, 3, &b)
		if code != "" || !resource || b.used != maxSnapshotReadBytes {
			t.Fatal("EOF was inferred after budget exhaustion")
		}
	})
	t.Run("reread-counts", func(t *testing.T) {
		b := snapshotReadBudget{}
		for range 2 {
			data, resource, code := readSnapshotOriginalBytes(context.Background(), bytes.NewReader([]byte("abc")), 3, &b)
			if code != "" || resource || string(data) != "abc" {
				t.Fatal("small reread failed")
			}
		}
		if b.used != 6 {
			t.Fatal("reread was not charged")
		}
	})
}

func TestReadSnapshotNPMIdentityStreamReadErrors(t *testing.T) {
	original := []byte(streamTestOriginal)
	catalog := streamTestRows(streamTestCatalogLine(0, original))
	block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
	manifest := streamTestManifest(t, catalog, 0x2a, block)
	for _, which := range []string{"block-read-error", "catalog-read-error"} {
		t.Run(which, func(t *testing.T) {
			streams := SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog)}
			if which == "block-read-error" {
				streams.Block = snapshotTestErrorReader{}
			}
			if which == "catalog-read-error" {
				streams.Catalog = snapshotTestErrorReader{}
			}
			streamTestFatal(t, manifest, streams, "read-failed")
		})
	}
}

func TestReadSnapshotNPMIdentityCancellationBoundary(t *testing.T) {
	original := []byte(streamTestOriginal)
	catalog := streamTestRows(streamTestCatalogLine(0, original))
	block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
	manifest := streamTestManifest(t, catalog, 0x2a, block)
	for _, tc := range []struct {
		name   string
		data   []byte
		before bool
	}{
		{"before-read", block, true}, {"after-valid-read", block, false}, {"cancel-plus-malformed", []byte("{broken\n"), false}, {"cancel-plus-extra-byte", append(append([]byte(nil), block...), 'x'), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &snapshotTestCancelReader{cancel: cancel, data: tc.data}
			if tc.before {
				cancel()
			}
			got, err := ReadSnapshotNPMIdentity(ctx, manifest, "left-pad", SnapshotNPMStreams{Block: reader, Catalog: bytes.NewReader(catalog)})
			var pe *ParseError
			wantCalls := 1
			if tc.before {
				wantCalls = 0
			}
			if !errors.As(err, &pe) || pe.Code != "canceled" || err.Error() != "intel: canceled" || !reflect.DeepEqual(got, SnapshotNPMEvidence{}) || reader.calls != wantCalls {
				t.Fatal("cancellation precedence or zero-result boundary changed")
			}
		})
	}
}

func TestSnapshotReadBudgetCancellationCharge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &snapshotTestCancelReader{cancel: cancel, data: []byte("x")}
	budget := snapshotReadBudget{used: 3}
	called := false
	_, observed, resource, code := readSnapshotStream(ctx, reader, 0, &budget, func([]byte) string { called = true; return "invalid-shape" })
	if code != "canceled" || resource || observed != 1 || budget.used != 4 || called || reader.calls != 1 {
		t.Fatal("returned byte charging or cancellation-before-sink changed")
	}
}

func TestSnapshotReadBudgetPhysicalRows(t *testing.T) {
	rows := uint64(maxSnapshotManifestRecords - 1)
	if code := snapshotPhysicalRowNext(&rows); code != "" || rows != maxSnapshotManifestRecords {
		t.Fatal("last permitted physical row rejected")
	}
	if code := snapshotPhysicalRowNext(&rows); code != "limit-exceeded" || rows != maxSnapshotManifestRecords {
		t.Fatal("production physical-row ceiling changed")
	}
}

func TestReadSnapshotNPMIdentityNilStreams(t *testing.T) {
	original := []byte(streamTestOriginal)
	catalog := streamTestRows(streamTestCatalogLine(0, original))
	block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
	manifest := streamTestManifest(t, catalog, 0x2a, block)
	digest := sha256.Sum256(original)
	for _, usable := range []bool{false, true} {
		originals := []SnapshotOriginalStream{{SHA256: digest}, {SHA256: digest}}
		if usable {
			originals[1].Reader = bytes.NewReader(original)
		}
		got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog), Originals: originals})
		if err != nil || len(got.Records) != 1 {
			t.Fatal("nil slots became fatal or discarded the occurrence")
		}
		record := got.Records[0]
		if usable {
			if record.State != SnapshotOriginalVerified || record.Bindings[0].State != SnapshotBindingEligible {
				t.Fatal("nil followed by usable same-digest stream was not retained")
			}
		} else if record.State != SnapshotOriginalUnavailable || record.Problem != SnapshotOriginalProblemMissing || record.Bindings[0].State != SnapshotBindingGap {
			t.Fatal("nil streams became usable or absent evidence")
		}
	}
}

func TestReadSnapshotNPMIdentitySuppliedDuplicates(t *testing.T) {
	original := []byte(streamTestOriginal)
	catalog := streamTestRows(streamTestCatalogLine(0, original))
	block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
	manifest := streamTestManifest(t, catalog, 0x2a, block)
	digest := sha256.Sum256(original)
	streamTestFatal(t, manifest, SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog), Originals: []SnapshotOriginalStream{{SHA256: digest, Reader: bytes.NewReader(original)}, {SHA256: digest, Reader: bytes.NewReader(original)}}}, "invalid-shape")
}

func TestReadSnapshotNPMIdentityOriginalSiblingRetention(t *testing.T) {
	good := []byte(`{"id":"GOOD","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"}}]}`)
	badBase := []byte(`{"id":"BAD!","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"}}]}`)
	goodDigest := sha256.Sum256(good)
	cases := []struct {
		name    string
		bad     []byte
		reader  io.Reader
		problem SnapshotOriginalProblem
	}{
		{"missing", badBase, nil, SnapshotOriginalProblemMissing},
		{"read", badBase, snapshotTestErrorReader{}, SnapshotOriginalProblemRead},
		{"short", badBase, bytes.NewReader(badBase[:len(badBase)-1]), SnapshotOriginalProblemLength},
		{"extra", badBase, bytes.NewReader(append(append([]byte(nil), badBase...), 'x')), SnapshotOriginalProblemLength},
		{"digest", badBase, bytes.NewReader(append([]byte(nil), append([]byte{'X'}, badBase[1:]...)...)), SnapshotOriginalProblemDigest},
		{"parse", []byte(`{"id":"BAD","modified":`), bytes.NewReader([]byte(`{"id":"BAD","modified":`)), SnapshotOriginalProblemParse},
	}
	projectionBad := []byte(`{"id":"BAD","modified":"2026-10-02T00:00:00Z","affected":[` + strings.Repeat(`null,`, maxAffectedEntries) + `null]}`)
	cases = append(cases, struct {
		name    string
		bad     []byte
		reader  io.Reader
		problem SnapshotOriginalProblem
	}{"projection", projectionBad, bytes.NewReader(projectionBad), SnapshotOriginalProblemProjection})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			badDigest := sha256.Sum256(tc.bad)
			supplied := []SnapshotOriginalStream{{SHA256: goodDigest, Reader: bytes.NewReader(good)}}
			if tc.reader != nil {
				supplied = append(supplied, SnapshotOriginalStream{SHA256: badDigest, Reader: tc.reader})
			}
			got := streamTestEvidence(t, "left-pad", [][]byte{good, tc.bad}, []uint64{0, 0}, supplied)
			if len(got.Records) != 2 || got.Records[0].State != SnapshotOriginalVerified || got.Records[0].Bindings[0].State != SnapshotBindingEligible || got.Records[1].State != SnapshotOriginalUnavailable || got.Records[1].Problem != tc.problem || got.Records[1].Bindings[0].State != SnapshotBindingGap {
				t.Fatal("bad original removed or contaminated verified sibling")
			}
			if strings.Contains(fmt.Sprint(got), "private-path:/secret/raw-marker") {
				t.Fatal("reader detail leaked")
			}
		})
	}
	t.Run("retained-raw-resource", func(t *testing.T) {
		originals := make([][]byte, 5)
		supplied := make([]SnapshotOriginalStream, 5)
		for i := range originals {
			originals[i] = streamTestPaddedOriginal(t, 4<<20, fmt.Sprintf("BIG-%d", i), "left-pad")
			d := sha256.Sum256(originals[i])
			supplied[i] = SnapshotOriginalStream{SHA256: d, Reader: bytes.NewReader(originals[i])}
		}
		got := streamTestEvidence(t, "left-pad", originals, []uint64{0, 0, 0, 0, 0}, supplied)
		if len(got.Records) != 5 || got.Records[0].State != SnapshotOriginalVerified || got.Records[4].Problem != SnapshotOriginalProblemResource || !containsSnapshotGap(got.Gaps, SnapshotGapResource) {
			t.Fatal("aggregate retained raw bound discarded prior siblings")
		}
	})
}

func TestReadSnapshotNPMIdentityTimesAndUnevaluatedConditions(t *testing.T) {
	originals := [][]byte{
		[]byte(`{"id":"WITHDRAWN","modified":"2026-10-02T00:00:00Z","withdrawn":"2026-10-03T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["not-semver"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"raw"}]}]}]}`),
		[]byte(`{"id":"ABSENT","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"}}]}`),
		[]byte(`{"id":"UNKNOWN","modified":"2026-10-02T00:00:00Z","withdrawn":"malformed","affected":[{"package":{"ecosystem":"npm","name":"left-pad"}}]}`),
		[]byte(`{"schema_version":"2.0.0","id":"UNSUPPORTED-HEADER","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"}}]}`),
	}
	supplied := make([]SnapshotOriginalStream, len(originals))
	for i, original := range originals {
		supplied[i] = SnapshotOriginalStream{SHA256: sha256.Sum256(original), Reader: bytes.NewReader(original)}
	}
	got := streamTestEvidence(t, "left-pad", originals, []uint64{0, 0, 0, 0}, supplied)
	if len(got.Records) != 4 || got.Records[0].Times.Withdrawal != WithdrawalReported || got.Records[1].Times.Withdrawal != WithdrawalNotDeclared || got.Records[2].Times.Withdrawal != WithdrawalUnknown || got.Records[0].Affected.Entries[0].Versions.Entries[0].Value != "not-semver" || got.Records[0].Affected.Entries[0].Ranges.Entries[0].Type.Value != "ECOSYSTEM" || got.Records[3].State != SnapshotOriginalVerified || got.Records[3].Header.Schema != OSVHeaderSchemaUnsupported || len(got.Records[3].Bindings) != 1 || got.Records[3].Bindings[0].State != SnapshotBindingGap || got.Records[3].Bindings[0].Problem != SnapshotBindingProblemIdentity {
		t.Fatal("times, unsupported header, or unevaluated version/range evidence changed")
	}
}

func TestReadSnapshotNPMIdentityLimits(t *testing.T) {
	t.Run("original-4MiB", func(t *testing.T) {
		original := streamTestPaddedOriginal(t, 4<<20, "MAX", "left-pad")
		d := sha256.Sum256(original)
		got := streamTestEvidence(t, "left-pad", [][]byte{original}, []uint64{0}, []SnapshotOriginalStream{{SHA256: d, Reader: bytes.NewReader(original)}})
		if len(got.Records) != 1 || got.Records[0].State != SnapshotOriginalVerified {
			t.Fatal("4 MiB original rejected")
		}
		catalog := streamTestRows(streamTestCatalogRefLine(0, d, (4<<20)+1))
		block := streamTestRows(streamTestBlockRefLine("left-pad", 0, d, (4<<20)+1, 0))
		manifest := streamTestManifest(t, catalog, 0x2a, block)
		streamTestFatal(t, manifest, SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog)}, "limit-exceeded")
	})
	t.Run("block-over-4MiB", func(t *testing.T) {
		groups := map[byte][]string{}
		var names []string
		var index byte
		for i := 0; len(names) < 6; i++ {
			name := fmt.Sprintf("large-%d", i)
			h := sha256.Sum256(append([]byte("npm\x00"), []byte(name)...))
			groups[h[0]] = append(groups[h[0]], name)
			if len(groups[h[0]]) == 6 {
				names, index = groups[h[0]], h[0]
			}
		}
		query, rowNames := names[5], names[:5]
		sort.Slice(rowNames, func(i, j int) bool {
			a := sha256.Sum256(append([]byte("npm\x00"), []byte(rowNames[i])...))
			b := sha256.Sum256(append([]byte("npm\x00"), []byte(rowNames[j])...))
			return bytes.Compare(a[:], b[:]) < 0
		})
		lines := make([]string, 5)
		for i, name := range rowNames {
			line := streamTestBlockRefLine(name, uint64(i), sha256.Sum256([]byte{name[0]}), 1, 0)
			lines[i] = line + strings.Repeat(" ", 900_000-len(line))
		}
		block := streamTestRows(lines...)
		manifest := streamTestManifest(t, nil, index, block)
		got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, query, SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(nil)})
		if err != nil || got.BlockState != SnapshotStreamStructured || got.Declaration != SnapshotDeclarationVerified || len(block) <= 4<<20 {
			t.Fatal("large selected block was truncated or rejected")
		}
	})
	for _, count := range []int{4096, 4097} {
		t.Run(fmt.Sprintf("bindings-%d", count), func(t *testing.T) {
			original := []byte(streamTestOriginal)
			digest := sha256.Sum256(original)
			catalogLines, blockLines := make([]string, count), make([]string, count)
			for i := range count {
				catalogLines[i] = streamTestCatalogLine(uint64(i), original)
				blockLines[i] = streamTestBlockLine("left-pad", uint64(i), original, 0)
			}
			catalog, block := streamTestRows(catalogLines...), streamTestRows(blockLines...)
			manifest := streamTestManifest(t, catalog, 0x2a, block)
			got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog), Originals: []SnapshotOriginalStream{{SHA256: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			if count == 4096 {
				if len(got.Records) != 1 || len(got.Records[0].Bindings) != count || containsSnapshotGap(got.Gaps, SnapshotGapResource) {
					t.Fatal("4096 bindings rejected")
				}
			} else if len(got.Records) != 0 || !containsSnapshotGap(got.Gaps, SnapshotGapResource) || got.BlockState != SnapshotStreamStructured {
				t.Fatal("4097 bindings did not stop after block verification")
			}
		})
	}
	t.Run("supplied-slots", func(t *testing.T) {
		original := []byte(streamTestOriginal)
		catalog := streamTestRows(streamTestCatalogLine(0, original))
		block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
		manifest := streamTestManifest(t, catalog, 0x2a, block)
		for _, count := range []int{1024, 1025} {
			items := make([]SnapshotOriginalStream, count)
			br, cr := &snapshotCountingReader{}, &snapshotCountingReader{}
			streams := SnapshotNPMStreams{Block: br, Catalog: cr, Originals: items}
			if count == 1024 {
				streams.Block, streams.Catalog = bytes.NewReader(block), bytes.NewReader(catalog)
			}
			got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", streams)
			if count == 1024 {
				if err != nil || len(got.Records) != 1 || got.Records[0].Problem != SnapshotOriginalProblemMissing {
					t.Fatal("1024 nil slots rejected")
				}
			} else {
				var pe *ParseError
				if !errors.As(err, &pe) || pe.Code != "limit-exceeded" || !reflect.DeepEqual(got, SnapshotNPMEvidence{}) || br.calls != 0 || cr.calls != 0 {
					t.Fatal("1025 slots did not fail before allocation/read")
				}
			}
		}
	})
	for _, count := range []int{1024, 1025} {
		t.Run(fmt.Sprintf("selected-unique-%d", count), func(t *testing.T) {
			catalogLines, blockLines := make([]string, count), make([]string, count)
			for i := range count {
				d := sha256.Sum256([]byte(fmt.Sprintf("original-%d", i)))
				catalogLines[i] = streamTestCatalogRefLine(uint64(i), d, 1)
				blockLines[i] = streamTestBlockRefLine("left-pad", uint64(i), d, 1, 0)
			}
			catalog, block := streamTestRows(catalogLines...), streamTestRows(blockLines...)
			manifest := streamTestManifest(t, catalog, 0x2a, block)
			got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(catalog)})
			if err != nil {
				t.Fatal(err)
			}
			if count == 1024 {
				if len(got.Records) != 1024 || containsSnapshotGap(got.Gaps, SnapshotGapResource) {
					t.Fatal("1024 selected unique originals rejected")
				}
			} else if len(got.Records) != 0 || !containsSnapshotGap(got.Gaps, SnapshotGapResource) {
				t.Fatal("1025 selected unique originals materialized")
			}
		})
	}
	t.Run("declared-32GiB", func(t *testing.T) {
		build := func(plus uint64) []byte {
			const count = 8192
			sizes := make([]uint64, count)
			for i := range sizes {
				sizes[i] = 4 << 20
			}
			for range 10 {
				lines := make([]string, count)
				var sum uint64
				for i, size := range sizes {
					d := sha256.Sum256([]byte(fmt.Sprintf("decl-%d", i)))
					lines[i] = streamTestCatalogRefLine(uint64(i), d, size)
					sum += size
				}
				catalog := streamTestRows(lines...)
				want := maxSnapshotManifestObjectBytes + plus
				actual := sum + uint64(len(catalog))
				if actual == want {
					return catalog
				}
				if actual > want {
					sizes[count-1] -= actual - want
				} else {
					sizes[count-1] += want - actual
				}
			}
			t.Fatal("declaration boundary fixture did not converge")
			return nil
		}
		for _, plus := range []uint64{0, 1} {
			catalog := build(plus)
			manifest := streamTestManifest(t, catalog, 0x2a, nil)
			got, err := ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{Block: bytes.NewReader(nil), Catalog: bytes.NewReader(catalog)})
			if plus == 0 {
				if err != nil || got.Declaration != SnapshotDeclarationVerified {
					t.Fatal("exact 32 GiB declaration rejected", err)
				}
			} else {
				var pe *ParseError
				if !errors.As(err, &pe) || pe.Code != "limit-exceeded" || !reflect.DeepEqual(got, SnapshotNPMEvidence{}) {
					t.Fatal("32 GiB + 1 declaration accepted")
				}
			}
		}
	})
	t.Run("retained-counters", func(t *testing.T) {
		b := snapshotRetainedBudget{raw: maxSnapshotRetainedOriginalBytes - 1, logical: maxSnapshotLogicalBytes - 2}
		if !b.reserveOriginal(1, 1) || b.raw != maxSnapshotRetainedOriginalBytes || b.logical != maxSnapshotLogicalBytes {
			t.Fatal("exact retained raw/logical boundary rejected")
		}
		before := b
		if b.reserveOriginal(1, 0) || b != before {
			t.Fatal("failed reservation changed counters")
		}
		b = snapshotRetainedBudget{metadata: maxSnapshotMetadataEntries - 1}
		if !b.metadataEntry() || b.metadata != maxSnapshotMetadataEntries || b.metadataEntry() {
			t.Fatal("metadata boundary changed")
		}
		b = snapshotRetainedBudget{logical: maxSnapshotLogicalBytes - 1}
		if !b.logicalBytes(1) || b.logicalBytes(1) {
			t.Fatal("logical boundary changed")
		}
	})
}

func TestReadSnapshotNPMIdentityGapsPrivacyOwnership(t *testing.T) {
	original := []byte(streamTestOriginal)
	got := streamTestCall(t, original)
	if !reflect.DeepEqual(got.Gaps, streamTestBaselineGaps()) {
		t.Fatal("positive baseline gaps changed")
	}
	emptyManifest := streamTestManifest(t, nil, 0x2a, nil)
	empty, err := ReadSnapshotNPMIdentity(context.Background(), emptyManifest, "left-pad", SnapshotNPMStreams{Block: bytes.NewReader(nil), Catalog: bytes.NewReader(nil)})
	if err != nil || !reflect.DeepEqual(empty.Gaps, streamTestBaselineGaps()) || len(empty.Records) != 0 || !containsSnapshotGap(empty.Gaps, SnapshotGapIndexCompleteness) || !containsSnapshotGap(empty.Gaps, SnapshotGapCorrection) || !containsSnapshotGap(empty.Gaps, SnapshotGapFindingAuthority) {
		t.Fatal("empty block became definitive absence")
	}

	catalog := streamTestRows(streamTestCatalogLine(0, original))
	block := streamTestRows(streamTestBlockLine("left-pad", 0, original, 0))
	manifest := streamTestManifest(t, catalog, 0x2a, block)
	badBlock := streamTestRows(`{"private-path:/secret/raw-marker":true}`)
	badManifest := streamTestManifest(t, catalog, 0x2a, badBlock)
	for _, run := range []func() (SnapshotNPMEvidence, error){
		func() (SnapshotNPMEvidence, error) {
			return ReadSnapshotNPMIdentity(context.Background(), manifest, "left-pad", SnapshotNPMStreams{Block: snapshotTestErrorReader{}, Catalog: bytes.NewReader(catalog)})
		},
		func() (SnapshotNPMEvidence, error) {
			return ReadSnapshotNPMIdentity(context.Background(), badManifest, "left-pad", SnapshotNPMStreams{Block: bytes.NewReader(badBlock), Catalog: bytes.NewReader(catalog)})
		},
	} {
		value, err := run()
		text := fmt.Sprint(value, err)
		for _, marker := range []string{"private-path:/secret/raw-marker", "packtrace-synthetic-stream"} {
			if strings.Contains(text, marker) {
				t.Fatal("private content leaked")
			}
		}
	}

	originalInput := append([]byte(nil), original...)
	first := streamTestCall(t, originalInput)
	copy(originalInput, bytes.Repeat([]byte{'X'}, len(originalInput)))
	if !bytes.Equal(first.Records[0].Raw, original) || first.Records[0].Header.ID.Value != "OSV-SYNTHETIC-1" {
		t.Fatal("caller mutation changed returned evidence")
	}
	first.Records[0].Raw[0] = 'X'
	first.Records[0].Affected.Entries[0].Name.Value = "mutated"
	first.Records[0].Identity.Entries[0].Name.Value = "mutated"
	first.Records[0].Bindings[0].State = SnapshotBindingGap
	fresh := streamTestCall(t, original)
	if fresh.Records[0].Raw[0] != '{' || fresh.Records[0].Affected.Entries[0].Name.Value != "left-pad" || fresh.Records[0].Identity.Entries[0].Name.Value != "left-pad" || fresh.Records[0].Bindings[0].State != SnapshotBindingEligible || !bytes.Equal(original, []byte(streamTestOriginal)) {
		t.Fatal("returned mutation changed caller or fresh call")
	}

	typ := reflect.TypeOf(SnapshotOriginalEvidence{})
	wantFields := []string{"SHA256", "Bytes", "State", "Problem", "Raw", "Header", "Affected", "Identity", "Times", "Bindings"}
	if typ.NumField() != len(wantFields) {
		t.Fatal("row-level projection fields entered result")
	}
	for i, name := range wantFields {
		if typ.Field(i).Name != name {
			t.Fatal("record shape changed")
		}
	}
}

func TestReadSnapshotNPMIdentitySourceScope(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "snapshot_npm_stream.go", nil, 0)
	if err != nil {
		t.Fatal("cannot inspect consumer source", err)
	}
	allowed := map[string]bool{"bytes": true, "context": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true, "io": true, "packtrace/internal/jsoninput": true}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !allowed[path] {
			t.Fatal("operational or dependency import entered consumer")
		}
	}
	for _, decl := range file.Decls {
		if d, ok := decl.(*ast.GenDecl); ok && d.Tok == token.VAR {
			t.Fatal("mutable package global entered consumer")
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok {
			switch id.Name {
			case "EvaluateOSVVersionConditions", "panic", "print", "println":
				t.Fatal("version/panic/output authority entered consumer")
			}
		}
		return true
	})
}
