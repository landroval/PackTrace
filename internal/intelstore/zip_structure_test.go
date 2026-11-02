package intelstore

import (
	"archive/zip"
	"bytes"
	"fmt"
	"testing"
)

func TestArchiveStructureAdmitsZIP64EntryCountAndRejectsTrailingBytes(t *testing.T) {
	var raw bytes.Buffer
	w := zip.NewWriter(&raw)
	for i := 0; i < 65536; i++ {
		f, e := w.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("OWNED-%06d.json", i), Method: zip.Store})
		if e != nil {
			t.Fatal(e)
		}
		if _, e := f.Write([]byte("{}")); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	data := raw.Bytes()
	z, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	if e := validateZIPStructure(bytes.NewReader(data), int64(len(data)), z.File); e != nil {
		t.Fatal("standard ZIP64 count refused", e)
	}
	data = append(append([]byte(nil), data...), []byte("trailing")...)
	if e := validateZIPStructure(bytes.NewReader(data), int64(len(data)), z.File); e == nil {
		t.Fatal("trailing data became archive evidence")
	}
}
