package integrity

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func archiveFixture(t *testing.T, headers ...*tar.Header) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, h := range headers {
		h.Format = tar.FormatUSTAR
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func archiveBinding(t *testing.T, b []byte) ReferenceBinding {
	t.Helper()
	sum := sha256.Sum256(b)
	sri := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	in := BindingInput{InstanceID: "physical-1", Lockfile: BindingClaim{PackageID: "p", Version: "1", Origin: "o", ExpectedSRI: sri, SourceLocator: "loc", SourceHash: sri, EvidenceID: "e"}, SelectedBaseline: BaselineLockfile, SelectionReason: "selected", RequiredAssurance: AssuranceLockfile, Qualification: QualificationEvidence{ControllerEvidenceID: "q", Basis: "caller assertion"}}
	binding, gaps := ResolveReferenceBinding(in)
	if len(gaps) != 0 {
		t.Fatalf("binding: %+v", gaps)
	}
	return binding
}
func TestInspectReferenceArchiveValid(t *testing.T) {
	b := archiveFixture(t, &tar.Header{Name: "package/", Typeflag: tar.TypeDir}, &tar.Header{Name: "package/lib/", Typeflag: tar.TypeDir}, &tar.Header{Name: "package/lib/a.js", Size: 3, Typeflag: tar.TypeReg})
	c, err := InspectReferenceArchive(context.Background(), archiveBinding(t, b), bytes.NewReader(b), Limits{})
	if err != nil || !c.verified || len(c.entries) != 3 {
		t.Fatalf("catalog %+v error %v", c, err)
	}
	want := sha256.Sum256([]byte("xxx"))
	if c.entries[2].SHA256 != want || c.entries[2].Name != "lib/a.js" || c.entries[2].Size != 3 || c.entries[2].Type != EntryFile || c.CompressedRead != int64(len(b)) || c.ExpandedRead != 3072 {
		t.Fatalf("bad catalog %+v", c)
	}
}
func TestInspectReferenceArchiveRejectNamesAndHierarchy(t *testing.T) {
	names := []string{"evil/a", "package/../a", "package/./a", "package//a", "/package/a", "package/C:/x", "package/a:b", "package/a\\b", "package/CON", "package/a\x01b", "package/a<b", "package/a>b", "package/a\"b", "package/a|b", "package/a?b", "package/a*b"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			b := archiveFixture(t, &tar.Header{Name: name, Typeflag: tar.TypeReg})
			c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, b), bytes.NewReader(b), Limits{})
			if e == nil || c.verified {
				t.Fatalf("accepted %q: %+v", name, c)
			}
		})
	}
	for _, headers := range [][]*tar.Header{
		{{Name: "package/a", Typeflag: tar.TypeReg}, {Name: "package/a", Typeflag: tar.TypeReg}},
		{{Name: "package/A", Typeflag: tar.TypeReg}, {Name: "package/a", Typeflag: tar.TypeReg}},
		{{Name: "package/a", Typeflag: tar.TypeReg}, {Name: "package/a/b", Typeflag: tar.TypeReg}},
		{{Name: "package/a/b", Typeflag: tar.TypeReg}, {Name: "package/a", Typeflag: tar.TypeReg}},
	} {
		b := archiveFixture(t, headers...)
		c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, b), bytes.NewReader(b), Limits{})
		if e == nil || c.verified {
			t.Fatalf("accepted conflict: %+v", c)
		}
	}
}
func TestClosureUSTARNumericGrammar(t *testing.T) {
	base := archiveFixture(t, &tar.Header{Name: "package/a", Typeflag: tar.TypeReg})
	for _, field := range []struct {
		name       string
		start, end int
	}{{"mode", 100, 108}, {"uid", 108, 116}, {"gid", 116, 124}, {"size", 124, 136}, {"mtime", 136, 148}, {"devmajor", 329, 337}, {"devminor", 337, 345}} {
		t.Run(field.name, func(t *testing.T) {
			for _, invalid := range []string{strings.Repeat("z", field.end-field.start), "+000001", "0\x001", "\x00001"} {
				raw := unzipFixture(t, base)
				clear(raw[field.start:field.end])
				copy(raw[field.start:field.end], invalid)
				fixTarChecksum(raw[:512])
				v := zipFixture(t, raw)
				c, err := InspectReferenceArchive(context.Background(), archiveBinding(t, v), bytes.NewReader(v), Limits{})
				if err == nil || c.verified {
					t.Errorf("invalid numeric grammar accepted: %q", invalid)
				}
			}
		})
	}
	// Empty optional device fields are valid for regular files.
	raw := unzipFixture(t, base)
	clear(raw[329:345])
	fixTarChecksum(raw[:512])
	v := zipFixture(t, raw)
	if c, err := InspectReferenceArchive(context.Background(), archiveBinding(t, v), bytes.NewReader(v), Limits{}); err != nil || !c.verified {
		t.Fatalf("optional device fields: %+v %v", c, err)
	}
}

func TestInspectReferenceArchiveEntryAndDepthLimits(t *testing.T) {
	b := archiveFixture(t, &tar.Header{Name: "package/a", Typeflag: tar.TypeReg}, &tar.Header{Name: "package/b", Typeflag: tar.TypeReg})
	if c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, b), bytes.NewReader(b), Limits{Entries: 1}); e == nil || c.verified {
		t.Fatalf("entry limit accepted: %+v", c)
	}
	nested := archiveFixture(t, &tar.Header{Name: "package/a/b", Typeflag: tar.TypeReg})
	if c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, nested), bytes.NewReader(nested), Limits{PathDepth: 1}); e == nil || c.verified {
		t.Fatalf("depth limit accepted: %+v", c)
	}
}
func TestInspectReferenceArchiveLimits(t *testing.T) {
	b := archiveFixture(t, &tar.Header{Name: "package/a", Typeflag: tar.TypeReg, Size: 3})
	binding := archiveBinding(t, b)
	cases := []Limits{{CompressedBytes: int64(len(b) - 1)}, {ReferenceReadBytes: int64(len(b) - 1)}, {ExpandedBytes: 2047}, {AggregateExpandedBytes: 2047}, {FileBytes: 2}, {TotalNameBytes: 3}, {NameBytes: 3}}
	for i, lim := range cases {
		c, e := InspectReferenceArchive(context.Background(), binding, bytes.NewReader(b), lim)
		if e == nil || c.verified {
			t.Fatalf("limit %d accepted: %+v", i, c)
		}
	}
}
func TestInspectReferenceArchiveRejectUnqualifiedUnicodeName(t *testing.T) {
	base := archiveFixture(t, &tar.Header{Name: "package/a", Typeflag: tar.TypeReg})
	raw := unzipFixture(t, base)
	clear(raw[:100])
	copy(raw[:100], []byte("package/é"))
	fixTarChecksum(raw[:512])
	v := zipFixture(t, raw)
	if c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, v), bytes.NewReader(v), Limits{}); e == nil || c.verified {
		t.Fatalf("unqualified spelling accepted: %+v", c)
	}
}
func TestInspectReferenceArchiveUnsupportedHeaders(t *testing.T) {
	base := archiveFixture(t, &tar.Header{Name: "package/a", Typeflag: tar.TypeReg})
	for _, typ := range []byte{tar.TypeSymlink, tar.TypeLink, tar.TypeGNUSparse, tar.TypeXHeader, tar.TypeGNULongName} {
		t.Run(string(typ), func(t *testing.T) {
			raw := unzipFixture(t, base)
			raw[156] = typ
			fixTarChecksum(raw[:512])
			v := zipFixture(t, raw)
			c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, v), bytes.NewReader(v), Limits{})
			if e == nil || c.verified {
				t.Fatalf("unsupported header accepted: %+v", c)
			}
		})
	}
	long := archiveFixturePAX(t)
	if c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, long), bytes.NewReader(long), Limits{}); e == nil || c.verified {
		t.Fatalf("PAX accepted: %+v", c)
	}
}
func unzipFixture(t *testing.T, b []byte) []byte {
	t.Helper()
	r, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	v, e := io.ReadAll(r)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func zipFixture(t *testing.T, v []byte) []byte {
	t.Helper()
	var o bytes.Buffer
	g := gzip.NewWriter(&o)
	if _, e := g.Write(v); e != nil {
		t.Fatal(e)
	}
	if e := g.Close(); e != nil {
		t.Fatal(e)
	}
	return o.Bytes()
}
func fixTarChecksum(h []byte) {
	for i := 148; i < 156; i++ {
		h[i] = ' '
	}
	sum := 0
	for _, v := range h {
		sum += int(v)
	}
	copy(h[148:156], []byte(fmt.Sprintf("%06o\x00 ", sum)))
}
func archiveFixturePAX(t *testing.T) []byte {
	t.Helper()
	var o bytes.Buffer
	g := gzip.NewWriter(&o)
	w := tar.NewWriter(g)
	if e := w.WriteHeader(&tar.Header{Name: "package/a", Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "unsupported"}}); e != nil {
		t.Fatal(e)
	}
	w.Close()
	g.Close()
	return o.Bytes()
}
func TestInspectReferenceArchiveRejectIncompleteAndTrailing(t *testing.T) {
	b := archiveFixture(t, &tar.Header{Name: "package/a", Typeflag: tar.TypeReg, Size: 3})
	raw := func() []byte {
		r, e := gzip.NewReader(bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		v, e := io.ReadAll(r)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}()
	rezip := func(v []byte) []byte {
		var o bytes.Buffer
		g := gzip.NewWriter(&o)
		g.Write(v)
		g.Close()
		return o.Bytes()
	}
	cases := [][]byte{b[:len(b)-1], append(bytes.Clone(b), 1), append(bytes.Clone(b), b...), rezip(raw[:len(raw)-512]), rezip(append(bytes.Clone(raw), make([]byte, 512)...)), rezip(append(bytes.Clone(raw), 1))}
	badCRC := bytes.Clone(b)
	badCRC[len(badCRC)-8] ^= 1
	cases = append(cases, badCRC)
	for i, v := range cases {
		c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, v), bytes.NewReader(v), Limits{})
		if e == nil || c.verified {
			t.Fatalf("malformed %d accepted: %+v", i, c)
		}
	}
}
func TestInspectReferenceArchiveInvalidClaimsAndReads(t *testing.T) {
	b := archiveFixture(t, &tar.Header{Name: "package/a", Typeflag: tar.TypeReg})
	if c, e := InspectReferenceArchive(context.Background(), ReferenceBinding{}, bytes.NewReader(b), Limits{}); e == nil || c.verified || c.CompressedRead != 0 {
		t.Fatalf("invalid binding: %+v %v", c, e)
	}
	wrong := archiveBinding(t, []byte("different"))
	if c, e := InspectReferenceArchive(context.Background(), wrong, bytes.NewReader(b), Limits{}); e == nil || c.verified || c.CompressedRead != int64(len(b)) {
		t.Fatalf("wrong hash: %+v %v", c, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c, e := InspectReferenceArchive(ctx, archiveBinding(t, b), bytes.NewReader(b), Limits{}); e == nil || c.verified {
		t.Fatalf("cancelled: %+v %v", c, e)
	}
	reader := &errorAfterReader{data: b, remaining: 20}
	c, e := InspectReferenceArchive(context.Background(), archiveBinding(t, b), reader, Limits{})
	if e == nil || c.verified || c.CompressedRead != 20 {
		t.Fatalf("read error: %+v %v", c, e)
	}
}

type errorAfterReader struct {
	data      []byte
	remaining int
}

func (r *errorAfterReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, errors.New("private source failure")
	}
	n := copy(p, r.data[:min(len(r.data), len(p), r.remaining)])
	r.data = r.data[n:]
	r.remaining -= n
	return n, nil
}
