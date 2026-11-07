package intelstore

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestSnapshotPinGrammarRejectsWeakMultipleAndNoncanonical(t *testing.T) {
	for _, raw := range []string{"sha256-a sha512-b", "sha1-Zm9v", "sha256-Zm9v", " sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} {
		if _, e := parseSnapshotPin(raw); e == nil {
			t.Fatal("unsupported pin admitted")
		}
	}
}
func TestBundleRejectsUnsafeUSTARMemberProfiles(t *testing.T) {
	for _, header := range []tar.Header{
		{Name: "../descriptor.json", Size: 2, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR},
		{Name: "descriptor.json", Linkname: "../target", Typeflag: tar.TypeSymlink, Format: tar.FormatUSTAR},
		{Name: "descriptor.json", Size: 2, Typeflag: tar.TypeReg, Format: tar.FormatGNU},
		{Name: "descriptor.json", Size: 2, Typeflag: tar.TypeReg, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "owned extension"}},
	} {
		t.Run(header.Name+string(header.Typeflag)+header.Format.String(), func(t *testing.T) {
			var raw bytes.Buffer
			w := tar.NewWriter(&raw)
			if e := w.WriteHeader(&header); e != nil {
				t.Fatal(e)
			}
			if header.Size != 0 {
				w.Write([]byte("{}"))
			}
			if e := w.Close(); e != nil {
				t.Fatal(e)
			}
			input, _ := originalBundleInput(t, raw.Bytes())
			s, _ := transactionFixture(t)
			if _, e := s.Import(context.Background(), input, ImportOptions{}); e == nil {
				t.Fatal("unsafe archive profile selected")
			}
		})
	}
}
func TestFailedOrCancelledExportCannotChangeActivation(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	id := fixtureGeneration(t, s, "OWNED-1", "2026-11-01T00:00:00Z")
	snapshot, e := s.ReadPinned(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	before, _, e := s.readSelection(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.Export(ctx, snapshot, failedHTTPOutput{}); e == nil {
		t.Fatal("failed output accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if e := s.Export(cancelled, snapshot, &bytes.Buffer{}); e == nil || !errors.Is(e, context.Canceled) {
		t.Fatal("cancel ignored", e)
	}
	after, _, e := s.readSelection(ctx)
	if e != nil || after != before || id == (ID{}) {
		t.Fatal("readonly export changed activation")
	}
}
