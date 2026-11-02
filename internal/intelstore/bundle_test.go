package intelstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"packtrace/internal/nativefs"
	"path/filepath"
	"testing"
	"time"
)

func originalBundleInput(t *testing.T, data []byte) (*nativefs.File, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "owned.bundle")
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	root, e := nativefs.OpenRoot(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	input, e := root.OpenDistributionInput(context.Background(), "owned.bundle")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { input.Close() })
	return input, path
}
func TestExportImportRoundtripPreservesActualOriginalAndInput(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fetch, closeSource := fullSourceFixture(t, "success")
	defer closeSource()
	prepared, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if e != nil {
		t.Fatal(e)
	}
	id := prepared.Generation
	snapshot, e := s.ReadPinned(ctx, &id)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	var archive bytes.Buffer
	if e := s.Export(ctx, snapshot, &archive); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(archive.Bytes(), []byte("acquisition.key")) || bytes.Contains(archive.Bytes(), []byte("local-acquisition.mac")) {
		t.Fatal("private local source authority exported")
	}
	input, path := originalBundleInput(t, archive.Bytes())
	other, _ := transactionFixture(t)
	result, e := other.Import(ctx, input, ImportOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if result.Generation != id {
		t.Fatal("canonical generation semantics changed")
	}
	got, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(got, archive.Bytes()) {
		t.Fatal("foreign input modified", e)
	}
	imported, e := other.ReadPinned(ctx, &result.Generation)
	if e != nil {
		t.Fatal(e)
	}
	defer imported.Close()
	evidence, e := imported.ReadIdentity(ctx, "left-pad")
	if e != nil || len(evidence.Records) != 1 || !bytes.Contains(evidence.Records[0].Raw, []byte(`"id":"GHSA-2345-6789-cfgh"`)) {
		t.Fatal("roundtrip lost original ordinal/affected identity", e)
	}
	observation, e := imported.Observe(ctx, time.Now(), nil)
	if e != nil || observation.SourceAuthority != SourceUnqualified {
		t.Fatal("import self-authorized OSV freshness", e)
	}
	designated, e := imported.Observe(ctx, time.Now(), &id)
	if e != nil || designated.SourceAuthority != SourceDesignated {
		t.Fatal("external descriptor designation lost", e)
	}
}
func TestBundleTrailingBytesOrWrongPinCannotActivate(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	id := fixtureGeneration(t, s, "OWNED-1", "2026-11-01T00:00:00Z")
	snapshot, e := s.ReadPinned(ctx, &id)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	var archive bytes.Buffer
	if e := s.Export(ctx, snapshot, &archive); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []bool{false, true} {
		data := append([]byte(nil), archive.Bytes()...)
		opts := ImportOptions{}
		if bad {
			data = append(data, 'x')
		} else {
			wrong := id
			wrong[0] ^= 1
			opts.TrustedSnapshotDigest = "sha256-" + base64.StdEncoding.EncodeToString(wrong[:])
		}
		input, _ := originalBundleInput(t, data)
		other, _ := transactionFixture(t)
		if _, e := other.Import(ctx, input, opts); e == nil {
			t.Fatal("malformed package selected")
		}
		if _, _, e := other.readSelection(ctx); e == nil {
			t.Fatal("failed import activated")
		}
	}
}
