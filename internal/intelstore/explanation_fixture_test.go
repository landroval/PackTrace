package intelstore

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Both records are authored inert evidence. No real record or payload is copied.
func explanationSourceRecords() []archiveRecord {
	partial := strings.Replace(matchingSourceRecords()[0].body, "MAL-2026-1", "MAL-2026-42", -1)
	partial = strings.Replace(partial, `"versions":["1.0.0"]`, `"versions":["1.0.0","PRIVATE-inert-unsupported-version"]`, 1)
	descriptive := strings.Replace(matchingSourceRecords()[0].body, "MAL-2026-1", "MAL-2026-43", -1)
	descriptive = strings.Replace(descriptive, `"name":"left-pad"`, `"name":"@packtrace/cwe-fixture"`, 1)
	descriptive = strings.Replace(descriptive, `"versions":["1.0.0"]}`, `"versions":["1.0.0"],"database_specific":{"source":"https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/@packtrace/cwe-fixture/MAL-2026-43.json","cwes":[{"cweId":"CWE-506","name":"Embedded Malicious Code","description":"Authored informational fixture; not classification authority."}]}}`, 1)
	return []archiveRecord{{"MAL-2026-42.json", partial, 0}, {"MAL-2026-43.json", descriptive, 0}}
}

func TestExplanationFixtureReproducible(t *testing.T) {
	data, id := matchingFixtureBundleFor(t, "matching-explanation", 2)
	t.Logf("generation=%x bytes=%d sha256=%x", id, len(data), sha256.Sum256(data))
	if output := os.Getenv("PACKTRACE_EXPLANATION_FIXTURE_NEW_OUTPUT"); output != "" {
		f, e := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		n, we := f.Write(data)
		ce := f.Close()
		if we != nil || ce != nil || n != len(data) {
			t.Fatal(n, we, ce)
		}
		return
	}
	existing, e := os.ReadFile(filepath.Join("..", "execution", "testdata", "intel", "explanation.bundle"))
	if e != nil || !bytes.Equal(existing, data) {
		t.Fatal("nonreproducible authored fixture", e)
	}
	if bytes.Contains(data, []byte("acquisition.key")) || bytes.Contains(data, []byte("local-acquisition.mac")) {
		t.Fatal("exported local authority")
	}
}
