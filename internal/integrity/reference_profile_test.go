package integrity

import (
	"archive/tar"
	"bytes"
	"context"
	"testing"
)

func inspectProfile(t *testing.T, b []byte, ok bool) ReferenceCatalog {
	t.Helper()
	c, e := InspectReferenceArchiveProfile(context.Background(), archiveBinding(t, b), bytes.NewReader(b), Limits{}, ArchiveVerifyNPM)
	if (e == nil) != ok || c.verified != ok || !ok && len(c.Entries()) != 0 {
		t.Fatalf("profile accepted=%v error=%v catalog=%+v", ok, e, c)
	}
	return c
}

func TestVerifyArchiveEnvelopeProfile(t *testing.T) {
	for _, root := range []string{"package", "historic-v1", "CaseSensitive"} {
		for _, explicit := range []bool{false, true} {
			headers := []*tar.Header{}
			if explicit {
				headers = append(headers, &tar.Header{Name: root, Typeflag: tar.TypeDir})
			}
			headers = append(headers, &tar.Header{Name: root + "/src", Typeflag: tar.TypeDir}, &tar.Header{Name: root + "/src/a", Typeflag: tar.TypeReg, Size: 3})
			b := archiveFixture(t, headers...)
			c := inspectProfile(t, b, true)
			if c.Entries()[len(headers)-1].Name != "src/a" {
				t.Fatal("wrong envelope strip", c)
			}
			if c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, b), bytes.NewReader(b), Limits{}); e == nil || c.verified {
				t.Fatal("legacy widened")
			}
		}
	}
	for _, headers := range [][]*tar.Header{
		{{Name: "one/a"}, {Name: "two/b"}},
		{{Name: "Root/a"}, {Name: "root/b"}},
		{{Name: "root", Typeflag: tar.TypeReg}},
		{{Name: "root//", Typeflag: tar.TypeDir}},
		{{Name: "root/./", Typeflag: tar.TypeDir}},
		{{Name: "root/../", Typeflag: tar.TypeDir}},
		{{Name: "root/a"}, {Name: "root/a"}},
		{{Name: "root/A"}, {Name: "root/a"}},
		{{Name: "root/a"}, {Name: "root/a/b"}},
		{{Name: "root/a/b"}, {Name: "root/a"}},
		{{Name: "root/a", Typeflag: tar.TypeDir}, {Name: "root/a/", Typeflag: tar.TypeDir}},
		{{Name: "root/a", Typeflag: tar.TypeSymlink, Linkname: "x"}},
		{{Name: "root/a", Typeflag: tar.TypeLink, Linkname: "x"}},
	} {
		inspectProfile(t, archiveFixture(t, headers...), false)
	}
}

func TestVerifyArchiveMalformedDirectory(t *testing.T) {
	for _, name := range []string{"root//", "root/./", "root/../", "root/a/"} {
		b := archiveFixture(t, &tar.Header{Name: "root/a", Typeflag: tar.TypeReg})
		raw := unzipFixture(t, b)
		clear(raw[:100])
		copy(raw[:100], name)
		fixTarChecksum(raw[:512])
		inspectProfile(t, zipFixture(t, raw), false)
	}
}

func TestVerifyArchiveHistoricalMetadata(t *testing.T) {
	base := archiveFixture(t, &tar.Header{Name: "historic/a", Typeflag: tar.TypeReg})
	raw := unzipFixture(t, base)
	copy(raw[476:488], "14332753065\x00")
	copy(raw[488:500], "14332753065\x00")
	fixTarChecksum(raw[:512])
	b := zipFixture(t, raw)
	inspectProfile(t, b, true)
	if c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, b), bytes.NewReader(b), Limits{}); e == nil || c.verified {
		t.Fatal("legacy metadata widened")
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[345] = 'x' },
		func(b []byte) { b[475] = 1 },
		func(b []byte) { b[476] = '8' },
		func(b []byte) { b[477] = 0 },
		func(b []byte) { b[487] = ' ' },
		func(b []byte) { b[488] = '2' },
		func(b []byte) { b[499] = ' ' },
		func(b []byte) { b[500] = 1 },
		func(b []byte) { b[108] = 128 },
		func(b []byte) { b[156] = tar.TypeXHeader },
		func(b []byte) { b[156] = tar.TypeGNULongName },
	} {
		v := bytes.Clone(raw)
		mutate(v)
		fixTarChecksum(v[:512])
		inspectProfile(t, zipFixture(t, v), false)
	}
	// SRI binds the unmodified compressed stream, even under the new profile.
	c, e := InspectReferenceArchiveProfile(context.Background(), archiveBinding(t, base), bytes.NewReader(b), Limits{}, ArchiveVerifyNPM)
	if e == nil || c.verified || len(c.Entries()) != 0 {
		t.Fatal("rebound modified bytes")
	}
}

func TestVerifyArchiveRetainsStreamGuards(t *testing.T) {
	b := archiveFixture(t, &tar.Header{Name: "root/a", Typeflag: tar.TypeReg, Size: 3})
	raw := unzipFixture(t, b)
	for _, v := range [][]byte{b[:len(b)-1], append(bytes.Clone(b), 1), append(bytes.Clone(b), b...), zipFixture(t, raw[:len(raw)-512]), zipFixture(t, append(bytes.Clone(raw), make([]byte, 512)...))} {
		inspectProfile(t, v, false)
	}
	for _, lim := range []Limits{{Entries: 1, FileBytes: 2}, {CompressedBytes: 1}, {ExpandedBytes: 1}, {TotalNameBytes: 1}, {NameBytes: 1}} {
		c, e := InspectReferenceArchiveProfile(context.Background(), archiveBinding(t, b), bytes.NewReader(b), lim, ArchiveVerifyNPM)
		if e == nil || c.verified {
			t.Fatal("limit escaped", lim)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c, e := InspectReferenceArchiveProfile(ctx, archiveBinding(t, b), bytes.NewReader(b), Limits{}, ArchiveVerifyNPM); e == nil || c.verified {
		t.Fatal("cancellation escaped")
	}
}
