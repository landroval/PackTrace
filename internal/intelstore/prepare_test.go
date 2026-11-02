package intelstore

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"packtrace/internal/intel"
	"testing"
)

type archiveRecord struct {
	name, body string
	mode       uint32
}

func ownedArchive(t *testing.T, records []archiveRecord) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, r := range records {
		h := &zip.FileHeader{Name: r.name, Method: zip.Deflate}
		if r.mode != 0 {
			h.ExternalAttrs = r.mode << 16
			h.CreatorVersion = 3 << 8
		}
		f, e := w.CreateHeader(h)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := io.WriteString(f, r.body); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

const ownedOSVRecord = `{"id":"OWNED-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["1.0.0"]}]}`

func TestArchivePreparesActualOriginalsAndExistingIndexGrammar(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	data := ownedArchive(t, []archiveRecord{{"OWNED-1.json", ownedOSVRecord, 0}})
	draft, e := prepareArchive(ctx, tx, bytes.NewReader(data), int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := s.readRef(ctx, draft.Manifest, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	manifest, e := intel.ParseSnapshotManifestV11(raw)
	if e != nil {
		t.Fatal(e)
	}
	if manifest.Originals.Records != 1 || manifest.Blocks[0x2a].Reference.Records != 1 {
		t.Fatal("original/affected membership lost")
	}
	cat, e := s.readRef(ctx, ObjectRef{manifest.Originals.SHA256, manifest.Originals.Bytes}, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	block, e := s.readRef(ctx, ObjectRef{manifest.Blocks[0x2a].Reference.SHA256, manifest.Blocks[0x2a].Reference.Bytes}, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	original, e := intel.ParseOSVRecord([]byte(ownedOSVRecord))
	if e != nil {
		t.Fatal(e)
	}
	got, e := intel.ReadSnapshotNPMIdentity(ctx, manifest, "left-pad", intel.SnapshotNPMStreams{Block: bytes.NewReader(block), Catalog: bytes.NewReader(cat), Originals: []intel.SnapshotOriginalStream{{SHA256: original.SHA256, Reader: bytes.NewReader([]byte(ownedOSVRecord))}}})
	if e != nil || len(got.Records) != 1 || !bytes.Equal(got.Records[0].Raw, []byte(ownedOSVRecord)) {
		t.Fatal("real consumer lost original", e)
	}
	id, e := tx.seal(ctx, draft)
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.activate(ctx, id); e != nil {
		t.Fatal(e)
	}
}
func TestArchiveRejectsAmbiguousOrUnsafeInputWithoutActivation(t *testing.T) {
	cases := []struct {
		name    string
		records []archiveRecord
	}{
		{"escape", []archiveRecord{{"../OWNED-1.json", ownedOSVRecord, 0}}},
		{"duplicate", []archiveRecord{{"OWNED-1.json", ownedOSVRecord, 0}, {"OWNED-1.json", ownedOSVRecord, 0}}},
		{"identity-mismatch", []archiveRecord{{"OTHER.json", ownedOSVRecord, 0}}},
		{"symlink", []archiveRecord{{"OWNED-1.json", ownedOSVRecord, 0120777}}},
		{"duplicate-json-key", []archiveRecord{{"OWNED-1.json", `{"id":"OWNED-1","id":"OWNED-2","modified":"x"}`, 0}}},
		{"unsupported-schema", []archiveRecord{{"OWNED-1.json", `{"id":"OWNED-1","modified":"2026-11-01T00:00:00Z","schema_version":"2.0.0"}`, 0}}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			s, _ := transactionFixture(t)
			tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Close()
			data := ownedArchive(t, tt.records)
			if _, e := prepareArchive(ctx, tx, bytes.NewReader(data), int64(len(data))); e == nil {
				t.Fatal("unsafe archive prepared")
			}
			if _, _, e := s.readSelection(ctx); !errors.Is(e, ErrUnavailable) {
				t.Fatal("failed input activated state", e)
			}
		})
	}
}
func TestArchivePreservesUnusableIdentityDisposition(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	record := `{"id":"OWNED-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":null}},{"package":{"ecosystem":"PyPI","name":"other"}}]}`
	data := ownedArchive(t, []archiveRecord{{"OWNED-1.json", record, 0}})
	draft, e := prepareArchive(ctx, tx, bytes.NewReader(data), int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := s.readRef(ctx, draft.Provenance, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	var p preparationRecord
	if json.Unmarshal(raw, &p) != nil || p.IdentityGaps != 1 || p.OutsideNPM != 1 {
		t.Fatal("unknown identity was silently negative")
	}
}
