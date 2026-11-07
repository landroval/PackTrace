package intel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
)

func batchNames(n int) []string {
	names := []string{"left-pad"}
	for i := 0; len(names) < n; i++ {
		name := fmt.Sprintf("owned-batch-%d", i)
		if snapshotNPMIdentityHash(name)[0] == snapshotNPMIdentityHash(names[0])[0] {
			names = append(names, name)
		}
	}
	sorted, _, _ := SnapshotNPMIdentityNames(names)
	return sorted
}
func batchFixture(t *testing.T) (SnapshotManifest, *SnapshotVerifiedCatalog, []byte, []byte, []string) {
	t.Helper()
	names := batchNames(2)
	original := []byte(fmt.Sprintf(`{"id":"OWNED-BATCH","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":%q},"versions":["1.0.0"]},{"package":{"ecosystem":"npm","name":%q},"versions":["2.0.0"]}]}`, names[0], names[1]))
	catalogRaw := streamTestRows(streamTestCatalogLine(0, original))
	block := streamTestRows(streamTestBlockLine(names[0], 0, original, 0), streamTestBlockLine(names[1], 0, original, 1))
	m := streamTestManifest(t, catalogRaw, snapshotNPMIdentityHash(names[0])[0], block)
	catalog, err := ReadSnapshotCatalog(context.Background(), m, bytes.NewReader(catalogRaw))
	if err != nil {
		t.Fatal(err)
	}
	return m, catalog, block, original, names
}

type batchCountingReader struct {
	*bytes.Reader
	bytes, calls int
}

func (r *batchCountingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytes += n
	r.calls++
	return n, err
}

type batchOriginal struct {
	*bytes.Reader
	closed *int
}

func (r batchOriginal) Close() error { *r.closed++; return nil }

func TestGroupedReaderParityMandatoryOriginalAndOneIndexPass(t *testing.T) {
	m, catalog, block, original, names := batchFixture(t)
	ctx := context.Background()
	var expected []SnapshotNPMEvidence
	var baseline uint64
	for _, name := range names {
		got, err := ReadSnapshotNPMIdentityWithCatalog(ctx, m, name, catalog, bytes.NewReader(block), []SnapshotOriginalStream{{SHA256: sha256.Sum256(original), Reader: bytes.NewReader(original)}})
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, got)
		baseline += got.BytesRead
	}
	r := &batchCountingReader{Reader: bytes.NewReader(block)}
	opened, closed, emitted := 0, 0, 0
	var consumed uint64
	err := WalkSnapshotNPMIdentitiesWithCatalog(ctx, m, []string{names[1], names[0]}, catalog, r, func(ref SnapshotObjectReference) (io.ReadCloser, error) {
		if opened != closed {
			t.Fatal("previous identity original retained")
		}
		if ref.SHA256 != sha256.Sum256(original) || ref.Bytes != uint64(len(original)) {
			t.Fatal("unbound original")
		}
		opened++
		return batchOriginal{bytes.NewReader(original), &closed}, nil
	}, func(name string, got SnapshotNPMEvidence) error {
		if opened != closed {
			t.Fatal("original not closed before callback")
		}
		if name != names[emitted] {
			t.Fatal("noncanonical emission order")
		}
		want := expected[emitted]
		consumed += got.BytesRead
		got.BytesRead = want.BytesRead
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("legacy hydration differs for %s", name)
		}
		if got.Records[0].Bindings[0].AffectedIndex != uint64(emitted) || got.Records[0].Bindings[0].State != SnapshotBindingEligible {
			t.Fatal("same-original slot binding lost")
		}
		emitted++
		return nil
	})
	if err != nil || emitted != 2 || opened != 2 || closed != 2 || r.bytes != len(block) || r.calls != 2 {
		t.Fatal("one-pass walk", emitted, opened, closed, r.bytes, r.calls, err)
	}
	t.Logf("two nonempty identities: legacy=%d grouped=%d index=%d bytes; index reads=%d", baseline, consumed, len(block), r.calls)
	if consumed != uint64(len(block)+2*len(original)) || baseline-consumed != uint64(len(block)) {
		t.Fatal("actual byte reduction", baseline, consumed)
	}
}

func TestGroupedReaderRejectsWindowBeforeReads(t *testing.T) {
	m, catalog, block, _, names := batchFixture(t)
	mixed := "different-bucket"
	if snapshotNPMIdentityHash(mixed)[0] == snapshotNPMIdentityHash(names[0])[0] {
		t.Fatal("fixture bucket")
	}
	inputs := [][]string{nil, {}, {""}, {"@bad"}, {names[0], names[0]}, {names[0], mixed}, make([]string, 65)}
	for _, input := range inputs {
		r := &batchCountingReader{Reader: bytes.NewReader(block)}
		err := WalkSnapshotNPMIdentitiesWithCatalog(context.Background(), m, input, catalog, r, func(SnapshotObjectReference) (io.ReadCloser, error) { t.Fatal("opened original"); return nil, nil }, func(string, SnapshotNPMEvidence) error { t.Fatal("emitted"); return nil })
		if err == nil || r.calls != 0 {
			t.Fatal("invalid window read", input, err, r.calls)
		}
	}
	r := &batchCountingReader{Reader: bytes.NewReader(block)}
	err := WalkSnapshotNPMIdentitiesWithCatalog(context.Background(), m, names, catalog, r, func(SnapshotObjectReference) (io.ReadCloser, error) { return nil, nil }, nil)
	if err == nil || r.calls != 0 {
		t.Fatal("nil emitter read")
	}
}

func TestGroupedReaderCorruptionCancellationAndEmitterFailure(t *testing.T) {
	m, catalog, block, original, names := batchFixture(t)
	sentinel := errors.New("owned emitter stop")
	for _, mode := range []string{"index-digest", "index-growth", "catalog", "original-digest", "original-missing", "cancel", "emit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			input := append([]byte(nil), block...)
			cat := catalog
			if mode == "index-digest" {
				input[len(input)-3] ^= 1
			}
			if mode == "index-growth" {
				input = append(input, 'x')
			}
			if mode == "catalog" {
				copy := *catalog
				copy.manifest = [32]byte{}
				cat = &copy
			}
			if mode == "cancel" {
				cancel()
			}
			opened, closed, emitted := 0, 0, 0
			err := WalkSnapshotNPMIdentitiesWithCatalog(ctx, m, names, cat, bytes.NewReader(input), func(SnapshotObjectReference) (io.ReadCloser, error) {
				opened++
				raw := original
				if mode == "original-digest" {
					raw = bytes.Repeat([]byte{'x'}, len(original))
				}
				if mode == "original-missing" {
					return nil, sentinel
				}
				return batchOriginal{bytes.NewReader(raw), &closed}, nil
			}, func(_ string, got SnapshotNPMEvidence) error {
				emitted++
				if mode == "original-digest" && got.Records[0].State == SnapshotOriginalVerified {
					t.Fatal("corrupt original verified")
				}
				if mode == "emit" {
					return sentinel
				}
				return nil
			})
			if mode == "original-digest" {
				if err != nil || opened != 2 || closed != 2 || emitted != 2 {
					t.Fatal("original gap parity", err)
				}
				return
			}
			if err == nil {
				t.Fatal("failure accepted", mode)
			}
			if mode == "emit" {
				if !errors.Is(err, sentinel) || opened != 1 || closed != 1 || emitted != 1 {
					t.Fatal("emitter failure", err)
				}
			} else if mode != "original-missing" && (opened != 0 || emitted != 0) {
				t.Fatal("read/emitted before verification", opened, emitted)
			}
		})
	}
}

func TestGroupedReaderSelectedBindingCapNotMultiplied(t *testing.T) {
	original := []byte(streamTestOriginal)
	catalogRaw := streamTestRows(streamTestCatalogLine(0, original))
	// One extra selected slot must fail visibly, after verification, never return
	// a falsely complete prefix of bindings.
	lines := make([]string, maxSnapshotRetainedBindings+1)
	for i := range lines {
		lines[i] = streamTestBlockLine("left-pad", 0, original, uint64(i))
	}
	block := streamTestRows(lines...)
	m := streamTestManifest(t, catalogRaw, 0x2a, block)
	catalog, err := ReadSnapshotCatalog(context.Background(), m, bytes.NewReader(catalogRaw))
	if err != nil {
		t.Fatal(err)
	}
	r := &batchCountingReader{Reader: bytes.NewReader(block)}
	err = WalkSnapshotNPMIdentitiesWithCatalog(context.Background(), m, []string{"left-pad"}, catalog, r, func(SnapshotObjectReference) (io.ReadCloser, error) { t.Fatal("opened beyond cap"); return nil, nil }, func(string, SnapshotNPMEvidence) error { t.Fatal("emitted beyond cap"); return nil })
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != "limit-exceeded" || r.bytes != len(block) {
		t.Fatal("selection cap/complete verification", r.bytes, err)
	}
}
