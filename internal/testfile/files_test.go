package testfile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExistingFixtureIOPreservesIdentityAndRefusesCreationOrOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned")
	if e := os.WriteFile(path, []byte("original-long"), 0600); e != nil {
		t.Fatal(e)
	}
	before, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	if e := Overwrite(path, []byte("short")); e != nil {
		t.Fatal(e)
	}
	after, e := os.Stat(path)
	data, read := Read(path)
	if e != nil || !os.SameFile(before, after) || read != nil || string(data) != "short" {
		t.Fatal("fixture was replaced or changed incorrectly", e, read)
	}
	missing := path + ".absent"
	if e := Overwrite(missing, []byte("not-created")); e == nil {
		t.Fatal("missing fixture created")
	}
	if _, e := os.Lstat(missing); !os.IsNotExist(e) {
		t.Fatal("failed overwrite changed missing slot", e)
	}
	if _, e := Read(filepath.Dir(path)); e == nil {
		t.Fatal("directory read as fixture bytes")
	}
	large := bytes.Repeat([]byte{'x'}, (1<<20)+1)
	if e := Overwrite(path, large); e == nil {
		t.Fatal("oversized fixture overwrite admitted")
	}
	if e := os.WriteFile(path, large, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(path); e == nil {
		t.Fatal("oversized fixture read admitted")
	}
}
