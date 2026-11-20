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

func TestIndependentHistoricalTimestampFields(t *testing.T) {
	base := archiveFixture(t, &tar.Header{Name: "package/a", Typeflag: tar.TypeReg, Size: 3})
	raw := unzipFixture(t, base)
	copy(raw[476:488], "14742053445\x00")
	copy(raw[488:500], "14742053371\x00")
	fixTarChecksum(raw[:512])
	archive := zipFixture(t, raw)
	binding := archiveBinding(t, archive)
	for _, profile := range []ArchiveProfile{ArchiveLegacy, ArchiveVerifyNPM, ArchiveVerifyNPMv2} {
		c, err := InspectReferenceArchiveProfile(context.Background(), binding, bytes.NewReader(archive), Limits{}, profile)
		if profile == ArchiveVerifyNPMv2 {
			if err != nil || !c.verified || len(c.entries) != 1 || c.entries[0].Name != "a" || c.entries[0].Size != 3 {
				t.Fatal("invalid content projection", c, err)
			}
		} else if err == nil || len(c.entries) != 0 || c.verified {
			t.Fatal("older profile widened", profile)
		}
	}
	for i, value := range map[int]byte{475: 'x', 476: '8', 487: ' ', 488: 0, 498: '8', 499: '0', 500: '1'} {
		v := bytes.Clone(raw)
		v[i] = value
		fixTarChecksum(v[:512])
		b := zipFixture(t, v)
		if c, err := InspectReferenceArchiveProfile(context.Background(), archiveBinding(t, b), bytes.NewReader(b), Limits{}, ArchiveVerifyNPMv2); err == nil || c.verified || len(c.entries) != 0 {
			t.Fatalf("accepted malformed metadata at %d", i)
		}
	}
	if c, err := InspectReferenceArchiveProfile(context.Background(), archiveBinding(t, base), bytes.NewReader(archive), Limits{}, ArchiveVerifyNPMv2); err == nil || c.verified || len(c.entries) != 0 {
		t.Fatal("accepted changed archive under original pin")
	}
}

func TestArchiveProfilesDifferentialHeaders(t *testing.T) {
	base := archiveFixture(t, &tar.Header{Name: "package/a", Typeflag: tar.TypeReg})
	for _, tc := range []struct {
		name           string
		mutate         func([]byte)
		legacy, verify bool
	}{
		{"safe-prefix", func(b []byte) { clear(b[:100]); copy(b[:100], "a"); copy(b[345:500], "package/src") }, true, true},
		{"other-envelope", func(b []byte) { clear(b[:100]); copy(b[:100], "other/index.js") }, false, true},
		{"hidden-name", func(b []byte) { b[99] = 'x' }, false, false},
		{"hidden-prefix", func(b []byte) { b[499] = 'x' }, false, false},
		{"hidden-owner", func(b []byte) { b[296] = 'x' }, false, false},
		{"unused-link", func(b []byte) { b[157] = 'x' }, true, false},
		{"unused-padding", func(b []byte) { b[511] = 'x' }, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := unzipFixture(t, base)
			tc.mutate(raw[:512])
			fixTarChecksum(raw[:512])
			b := zipFixture(t, raw)
			c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, b), bytes.NewReader(b), Limits{})
			if (e == nil) != tc.legacy || c.verified != tc.legacy {
				t.Fatal("legacy acceptance changed", c, e)
			}
			inspectProfile(t, b, tc.verify)
		})
	}
	// Case-fold collisions and mixed envelopes are rejected by both APIs.
	for _, names := range [][2]string{{"package/A", "package/a"}, {"other/a", "package/b"}} {
		b := archiveFixture(t, &tar.Header{Name: names[0]}, &tar.Header{Name: names[1]})
		if c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, b), bytes.NewReader(b), Limits{}); e == nil || c.verified {
			t.Fatal("legacy collision/mixed root accepted")
		}
		inspectProfile(t, b, false)
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
