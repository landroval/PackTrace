package intelstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"packtrace/internal/intel"
	"packtrace/internal/testfile"
)

func TestSingleRunConcatReusesActualCatalogWithoutStagingAndStillRequiresSeal(t *testing.T) {
	for _, mode := range []string{"intact", "missing", "corrupt", "cancelled", "closed"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, path := transactionFixture(t)
			tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Close()
			archive := ownedArchive(t, []archiveRecord{{"OWNED-1.json", ownedOSVRecord, 0}})
			draft, e := prepareArchive(ctx, tx, bytes.NewReader(archive), int64(len(archive)))
			if e != nil || len(tx.prep.catRuns) != 1 {
				t.Fatal("single complete catalog run", e)
			}
			if mode == "cancelled" || mode == "closed" {
				request, cancel := context.WithCancel(ctx)
				defer cancel()
				if mode == "cancelled" {
					cancel()
				} else if e := tx.Close(); e != nil {
					t.Fatal(e)
				}
				if _, e := concatObjects(request, tx, tx.prep.catRuns); e == nil {
					t.Fatal("reuse escaped cancelled/closed transaction")
				}
				if mode == "cancelled" && tx.failed == nil {
					t.Fatal("cancelled reuse did not retain failure")
				}
				return
			}
			before, written, held := tx.sequence, tx.written, tx.held
			ref, e := concatObjects(ctx, tx, tx.prep.catRuns)
			if e != nil || ref != tx.prep.catRuns[0] {
				t.Fatal("canonical run changed", e)
			}
			if tx.sequence != before || tx.written != written || tx.held != held {
				t.Fatal("copied a complete immutable run into charged staging", tx.sequence-before, tx.written-written)
			}
			raw, e := s.readRef(ctx, draft.Manifest, 1<<20)
			if e != nil {
				t.Fatal(e)
			}
			manifest, e := intel.ParseSnapshotManifestV11(raw)
			if e != nil || (ObjectRef{manifest.Originals.SHA256, manifest.Originals.Bytes}) != ref {
				t.Fatal("manifest no longer binds actual catalog", e)
			}
			if e := tx.fence(ctx); e != nil {
				t.Fatal(e)
			}
			original := filepath.Join(path, objectPath(ref))
			switch mode {
			case "missing":
				if e := os.Remove(original); e != nil {
					t.Fatal(e)
				}
			case "corrupt":
				if e := testfile.Overwrite(original, bytes.Repeat([]byte{'x'}, int(ref.Bytes))); e != nil {
					t.Fatal(e)
				}
			}
			id, e := tx.seal(ctx, draft)
			if mode != "intact" {
				if e == nil {
					t.Fatal("reused reference bypassed mandatory original sealing")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if e := tx.activate(ctx, id); e != nil {
				t.Fatal(e)
			}
		})
	}
}
